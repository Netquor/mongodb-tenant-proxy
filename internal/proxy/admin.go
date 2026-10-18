package proxy

import (
	"context"
	"github.com/netquor/mongodb-tenant-proxy/internal/safeconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// connUp lets rewrite's multi-step commands run on this connection's upstream
// link and use proxy state.
type connUp struct{ c *conn }

func (u connUp) Run(db string, cmd bsoncore.Document) (bsoncore.Document, error) {
	return u.c.run(db, cmd)
}

func (u connUp) Txn() bool { return u.c.s.txnSupported() }

func (u connUp) TenantViews(db string) ([]string, error) {
	if u.c.s.cfg.DisableViews {
		return nil, nil
	}
	views, err := u.c.viewsIn(db)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(views))
	for n := range views {
		out = append(out, n)
	}
	return out, nil
}

func (u connUp) DropTenantViews(db string) error {
	if u.c.s.cfg.DisableViews {
		return nil
	}
	c := u.c
	// Bypass the cache: dropDatabase must see every view.
	c.invalidateViews(db)
	views, err := c.viewsIn(db)
	if err != nil {
		return err
	}
	for _, def := range views {
		if resp, err := c.run(db, bsoncore.BuildDocument(nil, bsoncore.AppendStringElement(nil, "drop", def.Phys))); err != nil {
			return err
		} else if failed(resp) {
			if code, _ := resp.Lookup("code").AsInt64OK(); code != 26 {
				return respErr(resp)
			}
		}
	}
	del := bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "delete", viewsColl),
		bsoncore.AppendArrayElement(nil, "deletes", arrayOfDocs(bsoncore.BuildDocument(nil,
			bsoncore.AppendDocumentElement(nil, "q", bsoncore.BuildDocument(nil, valueElem(c.s.cfg.Tenant.Field, c.tenant.Value))),
			bsoncore.AppendInt32Element(nil, "limit", 0)))))
	resp, err := c.run(db, del)
	c.invalidateViews(db)
	if err != nil {
		return err
	}
	if failed(resp) {
		if code, _ := resp.Lookup("code").AsInt64OK(); code != 26 {
			return respErr(resp)
		}
	}
	return nil
}

func respErr(resp bsoncore.Document) error {
	code, _ := resp.Lookup("code").AsInt64OK()
	name, _ := resp.Lookup("codeName").StringValueOK()
	msg, _ := resp.Lookup("errmsg").StringValueOK()
	return &rewrite.Error{Code: safeconv.Sat32(code), CodeName: name, Msg: msg}
}

func (u connUp) OwnClients() []string { return u.c.s.ownClients(u.c.tenant.ID) }

// runResult executes a command whose reply the rewriter produces itself.
func (c *conn) runResult(h wire.Header, m *wire.Msg, res *rewrite.Result) error {
	if m.Flags&wire.FlagMoreToCome != 0 {
		return nil // these commands have no unacknowledged form
	}
	resp, err := res.Run(connUp{c})
	if err != nil {
		c.s.M.Command(res.Command, "error")
		return c.reply(h, c.runErrorDoc(err))
	}
	c.s.M.Command(res.Command, "ok")
	return c.reply(h, resp)
}

func (c *conn) runErrorDoc(err error) bsoncore.Document {
	if _, ok := err.(*rewrite.Error); ok {
		return toErrorDoc(err)
	}
	c.log.Error("upstream command failed", "err", err)
	return errorDoc(6, "HostUnreachable", "tenant proxy: "+err.Error())
}

// checkBulkViews refuses bulkWrite namespaces that are the tenant's views.
func (c *conn) checkBulkViews(res *rewrite.Result) error {
	if c.s.cfg.DisableViews {
		return nil
	}
	for _, ns := range res.Namespaces {
		db, coll, _ := strings.Cut(ns, ".")
		views, err := c.viewsIn(db)
		if err != nil {
			return err
		}
		if views[coll] != nil {
			return &rewrite.Error{Code: 166, CodeName: "CommandNotSupportedOnView", Msg: "tenant proxy: bulkWrite is not supported on views"}
		}
	}
	return nil
}

// ---- server-level state -----------------------------------------------------

// registerUp / unregisterUp keep the upstream-side address of each tenant
// connection, which is how $currentOp attributes operations to tenants.
func (s *Server) registerUp(tenant, addr string) {
	s.opsMu.Lock()
	defer s.opsMu.Unlock()
	if s.upAddrs == nil {
		s.upAddrs = map[string]map[string]struct{}{}
	}
	if s.upAddrs[tenant] == nil {
		s.upAddrs[tenant] = map[string]struct{}{}
	}
	s.upAddrs[tenant][addr] = struct{}{}
}

func (s *Server) unregisterUp(tenant, addr string) {
	s.opsMu.Lock()
	defer s.opsMu.Unlock()
	delete(s.upAddrs[tenant], addr)
	if len(s.upAddrs[tenant]) == 0 {
		delete(s.upAddrs, tenant)
	}
}

// ownClients returns the "client" strings mongod reports for the tenant's
// proxy connections (both the bracketed and the plain IPv6 spelling).
func (s *Server) ownClients(tenant string) []string {
	s.opsMu.Lock()
	defer s.opsMu.Unlock()
	var out []string
	for a := range s.upAddrs[tenant] {
		out = append(out, a)
		if strings.HasPrefix(a, "[") {
			if i := strings.LastIndex(a, "]:"); i > 0 {
				out = append(out, a[1:i]+":"+a[i+2:])
			}
		}
	}
	return out
}

// txnSupported reports whether the upstream is a replica set or a sharded
// cluster (multi-document transactions). The answer is cached once known.
func (s *Server) txnSupported() bool {
	s.opsMu.Lock()
	known, v := s.txnKnown, s.txn
	s.opsMu.Unlock()
	if known {
		return v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, err := s.dial.Hello(ctx)
	if err != nil {
		return false
	}
	msg, _ := h.Lookup("msg").StringValueOK()
	v = h.Lookup("setName").Type != 0 || msg == "isdbgrid"
	s.opsMu.Lock()
	s.txnKnown, s.txn = true, v
	s.opsMu.Unlock()
	return v
}

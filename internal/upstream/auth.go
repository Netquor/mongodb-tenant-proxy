package upstream

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// init resolves the compressor list and credentials from the configuration.
func (d *Dialer) init() error {
	for _, n := range d.cfg.Compressors {
		id, ok := wire.CompressorByName(n)
		if !ok {
			return fmt.Errorf("upstream.compressors: unknown compressor %q", n)
		}
		d.comps = append(d.comps, id)
	}
	return nil
}

func sha1Password(user, password string) string {
	h := md5.Sum([]byte(user + ":mongo:" + password))
	return hex.EncodeToString(h[:])
}

// authenticate runs the configured authentication mechanism on a new
// connection.
func (d *Dialer) authenticate(c *Conn) error {
	switch mech := d.cfg.Mechanism(); mech {
	case "SCRAM-SHA-256", "SCRAM-SHA-1":
		return d.authSCRAM(c, mech)
	case "MONGODB-X509":
		return d.authX509(c)
	case "MONGODB-AWS":
		return d.authAWS(c)
	default:
		return fmt.Errorf("unsupported mechanism %q", mech)
	}
}

// authX509 authenticates with the TLS client certificate presented on dial.
func (d *Dialer) authX509(c *Conn) error {
	cmd := bsoncore.AppendInt32Element(nil, "authenticate", 1)
	cmd = bsoncore.AppendStringElement(cmd, "mechanism", "MONGODB-X509")
	if d.cfg.Username != "" {
		cmd = bsoncore.AppendStringElement(cmd, "user", d.cfg.Username)
	}
	resp, err := d.RunCommand(c, "$external", docOf(cmd))
	if err != nil {
		return err
	}
	return replyErr(resp)
}

func docOf(elems []byte) bsoncore.Document { return bsoncore.BuildDocument(nil, elems) }

func replyErr(resp bsoncore.Document) error {
	if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
		msg, _ := resp.Lookup("errmsg").StringValueOK()
		if msg == "" {
			msg = "authentication failed"
		}
		return errors.New(msg)
	}
	return nil
}

// negotiateCompression sends a hello advertising the configured compressors
// and adopts the first one the server also supports.
func (d *Dialer) negotiateCompression(c *Conn) error {
	if len(d.comps) == 0 {
		return nil
	}
	vals := make([]bsoncore.Value, len(d.comps))
	for i, id := range d.comps {
		vals[i] = bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, id.String())}
	}
	resp, err := d.RunCommand(c, "admin", bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "hello", 1),
		bsoncore.AppendArrayElement(nil, "compression", bsoncore.BuildArray(nil, vals...)),
	))
	if err != nil {
		return err
	}
	if err := replyErr(resp); err != nil {
		return err
	}
	arr, ok := resp.Lookup("compression").ArrayOK()
	if !ok {
		return nil // server offers none: stay uncompressed
	}
	offered, _ := arr.Values()
	for _, id := range d.comps {
		for _, v := range offered {
			if n, _ := v.StringValueOK(); n == id.String() {
				c.Comp = id
				return nil
			}
		}
	}
	return nil
}

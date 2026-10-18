// Package upstream dials and authenticates connections to the real MongoDB
// server.
package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xdg-go/scram"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// Conn is an authenticated connection to the upstream server.
type Conn struct {
	net.Conn
	R *bufio.Reader
}

// Dialer opens upstream connections.
type Dialer struct {
	cfg    config.Upstream
	dial   net.Dialer
	tls    *tls.Config
	max    int
	ids    atomic.Int32
	images sync.Map // "db.coll" -> struct{}
}

// NewDialer prepares a Dialer from the upstream configuration.
func NewDialer(cfg *config.Config) (*Dialer, error) {
	d := &Dialer{cfg: cfg.Upstream, max: cfg.MaxMessageBytes}
	if d.cfg.AuthSource == "" {
		d.cfg.AuthSource = "admin"
	}
	d.dial.Timeout = cfg.DialDuration()
	d.dial.KeepAlive = 30e9
	if cfg.Upstream.TLS {
		tc := &tls.Config{InsecureSkipVerify: cfg.Upstream.InsecureSkipVerify, MinVersion: tls.VersionTLS12}
		if cfg.Upstream.CAFile != "" {
			pem, err := os.ReadFile(cfg.Upstream.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("upstream.caFile contains no certificates")
			}
			tc.RootCAs = pool
		}
		d.tls = tc
	}
	return d, nil
}

// Dial opens and authenticates a connection.
func (d *Dialer) Dial(ctx context.Context) (*Conn, error) {
	nc, err := d.dial.DialContext(ctx, "tcp", d.cfg.Addr)
	if err != nil {
		return nil, err
	}
	if d.tls != nil {
		tc := d.tls.Clone()
		if tc.ServerName == "" {
			host, _, _ := net.SplitHostPort(d.cfg.Addr)
			tc.ServerName = host
		}
		tconn := tls.Client(nc, tc)
		if err := tconn.HandshakeContext(ctx); err != nil {
			nc.Close()
			return nil, err
		}
		nc = tconn
	}
	c := &Conn{Conn: nc, R: bufio.NewReaderSize(nc, 64*1024)}
	if d.cfg.Username != "" {
		if err := d.authenticate(c); err != nil {
			nc.Close()
			return nil, fmt.Errorf("upstream authentication: %w", err)
		}
	}
	return c, nil
}

// RunCommand sends a command and returns the reply document.
func (d *Dialer) RunCommand(c *Conn, db string, cmd bsoncore.Document) (bsoncore.Document, error) {
	body := bsoncore.Document(cmd)
	var err error
	body = appendDB(body, db)
	m := wire.Msg{Body: body}
	id := d.ids.Add(1)
	if err = wire.WriteFrame(c.Conn, id, 0, wire.OpMsg, m.Encode()); err != nil {
		return nil, err
	}
	_, b, err := wire.ReadFrame(c.R, d.max)
	if err != nil {
		return nil, err
	}
	rm, err := wire.ParseMsg(b)
	if err != nil {
		return nil, err
	}
	return rm.Body, nil
}

func appendDB(cmd bsoncore.Document, db string) bsoncore.Document {
	out := make([]byte, 0, len(cmd)+len(db)+8)
	out = append(out, cmd[:len(cmd)-1]...)
	out = bsoncore.AppendStringElement(out, "$db", db)
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// Hello returns the upstream's hello reply, used to learn wire versions.
func (d *Dialer) Hello(ctx context.Context) (bsoncore.Document, error) {
	c, err := d.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	cmd := bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "hello", 1))
	return d.RunCommand(c, "admin", cmd)
}

func (d *Dialer) authenticate(c *Conn) error {
	client, err := scram.SHA256.NewClient(d.cfg.Username, d.cfg.Password, "")
	if err != nil {
		return err
	}
	conv := client.NewConversation()
	payload, err := conv.Step("")
	if err != nil {
		return err
	}
	opts := bsoncore.BuildDocument(nil, bsoncore.AppendBooleanElement(nil, "skipEmptyExchange", true))
	cmd := bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "saslStart", 1),
		bsoncore.AppendStringElement(nil, "mechanism", "SCRAM-SHA-256"),
		bsoncore.AppendBinaryElement(nil, "payload", 0, []byte(payload)),
		bsoncore.AppendDocumentElement(nil, "options", opts),
	)
	resp, err := d.RunCommand(c, d.cfg.AuthSource, cmd)
	for {
		if err != nil {
			return err
		}
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
			msg, _ := resp.Lookup("errmsg").StringValueOK()
			return errors.New(msg)
		}
		_, data, _ := resp.Lookup("payload").BinaryOK()
		done, _ := resp.Lookup("done").BooleanOK()
		if !conv.Done() {
			payload, err = conv.Step(string(data))
			if err != nil {
				return err
			}
		} else {
			payload = ""
		}
		if done && conv.Done() {
			if !conv.Valid() {
				return errors.New("server signature mismatch")
			}
			return nil
		}
		cid := resp.Lookup("conversationId")
		cmd = bsoncore.BuildDocument(nil,
			bsoncore.AppendInt32Element(nil, "saslContinue", 1),
			valueElem("conversationId", cid),
			bsoncore.AppendBinaryElement(nil, "payload", 0, []byte(payload)),
		)
		resp, err = d.RunCommand(c, d.cfg.AuthSource, cmd)
	}
}

func valueElem(key string, v bsoncore.Value) []byte { return bsoncore.AppendValueElement(nil, key, v) }

// DialTimeout is the configured connect timeout.
func (d *Dialer) DialTimeout() time.Duration { return d.dial.Timeout }

// EnsureImages enables changeStreamPreAndPostImages on a collection (creating
// it if it does not exist). It is idempotent.
func (d *Dialer) EnsureImages(c *Conn, db, coll string) error {
	if _, ok := d.images.Load(db + "." + coll); ok {
		return nil
	}
	on := bsoncore.BuildDocument(nil, bsoncore.AppendBooleanElement(nil, "enabled", true))
	run := func(cmd bsoncore.Document) (bsoncore.Document, error) { return d.RunCommand(c, db, cmd) }
	resp, err := run(bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "collMod", coll),
		bsoncore.AppendDocumentElement(nil, "changeStreamPreAndPostImages", on)))
	if err != nil {
		return err
	}
	if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
		if code, _ := resp.Lookup("code").AsInt64OK(); code != 26 { // NamespaceNotFound
			msg, _ := resp.Lookup("errmsg").StringValueOK()
			return errors.New(msg)
		}
		resp, err = run(bsoncore.BuildDocument(nil,
			bsoncore.AppendStringElement(nil, "create", coll),
			bsoncore.AppendDocumentElement(nil, "changeStreamPreAndPostImages", on)))
		if err != nil {
			return err
		}
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
			if code, _ := resp.Lookup("code").AsInt64OK(); code != 48 { // already exists (race)
				msg, _ := resp.Lookup("errmsg").StringValueOK()
				return errors.New(msg)
			}
		}
	}
	d.images.Store(db+"."+coll, struct{}{})
	return nil
}

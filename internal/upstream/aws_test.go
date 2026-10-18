package upstream

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// fakeAWSServer is just enough of a mongod to run the MONGODB-AWS exchange
// and record what the client sent.
type fakeAWSServer struct {
	ln   net.Listener
	host string

	mu    sync.Mutex
	nonce []byte // server-first "s"
	final bsoncore.Document
}

func newFakeAWS(t *testing.T, stsHost string) *fakeAWSServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAWSServer{ln: ln, host: stsHost}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(nc)
		}
	}()
	return f
}

func (f *fakeAWSServer) serve(nc net.Conn) {
	defer nc.Close()
	for {
		h, body, err := wire.ReadFrame(nc, 1<<20)
		if err != nil {
			return
		}
		var cmd bsoncore.Document
		legacy := h.OpCode == wire.OpQuery
		if legacy {
			q, err := wire.ParseQuery(body)
			if err != nil {
				return
			}
			cmd = q.Doc
		} else {
			m, err := wire.ParseMsg(body)
			if err != nil {
				return
			}
			cmd = m.Body
		}
		first := ""
		if e, err := cmd.IndexErr(0); err == nil {
			first = e.Key()
		}
		var resp bsoncore.Document
		switch first {
		case "hello", "isMaster", "ismaster":
			resp = bsoncore.BuildDocument(nil,
				bsoncore.AppendBooleanElement(nil, "helloOk", true),
				bsoncore.AppendBooleanElement(nil, "isWritablePrimary", true),
				bsoncore.AppendBooleanElement(nil, "ismaster", true),
				bsoncore.AppendInt32Element(nil, "maxBsonObjectSize", 16<<20),
				bsoncore.AppendInt32Element(nil, "maxMessageSizeBytes", 48000000),
				bsoncore.AppendInt32Element(nil, "maxWriteBatchSize", 100000),
				bsoncore.AppendInt32Element(nil, "minWireVersion", 0),
				bsoncore.AppendInt32Element(nil, "maxWireVersion", 21),
				bsoncore.AppendStringElement(nil, "msg", "isdbgrid"),
				bsoncore.AppendInt32Element(nil, "ok", 1))
		case "saslStart":
			_, p, _ := cmd.Lookup("payload").BinaryOK()
			_, r, _ := bsoncore.Document(p).Lookup("r").BinaryOK()
			f.mu.Lock()
			f.nonce = append(append([]byte{}, r...), bytes.Repeat([]byte{7}, 32)...)
			n := f.nonce
			f.mu.Unlock()
			resp = bsoncore.BuildDocument(nil,
				bsoncore.AppendInt32Element(nil, "conversationId", 1),
				bsoncore.AppendBooleanElement(nil, "done", false),
				bsoncore.AppendBinaryElement(nil, "payload", 0, bsoncore.BuildDocument(nil,
					bsoncore.AppendBinaryElement(nil, "s", 0, n),
					bsoncore.AppendStringElement(nil, "h", f.host))),
				bsoncore.AppendInt32Element(nil, "ok", 1))
		case "saslContinue":
			_, p, _ := cmd.Lookup("payload").BinaryOK()
			f.mu.Lock()
			f.final = append(bsoncore.Document{}, p...)
			f.mu.Unlock()
			resp = bsoncore.BuildDocument(nil,
				bsoncore.AppendInt32Element(nil, "conversationId", 1),
				bsoncore.AppendBooleanElement(nil, "done", true),
				bsoncore.AppendBinaryElement(nil, "payload", 0, nil),
				bsoncore.AppendInt32Element(nil, "ok", 1))
		default:
			resp = bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "ok", 1))
		}
		if legacy {
			wire.WriteFrame(nc, 1, h.RequestID, wire.OpReply, wire.EncodeReply(resp))
		} else {
			wire.WriteFrame(nc, 1, h.RequestID, wire.OpMsg, (&wire.Msg{Body: resp}).Encode())
		}
	}
}

func (f *fakeAWSServer) captured() (nonce []byte, final bsoncore.Document) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nonce, f.final
}

func parts(t *testing.T, final bsoncore.Document) (a, d, tok string) {
	t.Helper()
	a, _ = final.Lookup("a").StringValueOK()
	d, _ = final.Lookup("d").StringValueOK()
	tok, _ = final.Lookup("t").StringValueOK()
	if a == "" || d == "" {
		t.Fatalf("client final message incomplete: %v", final)
	}
	return
}

// TestAWSSignatureMatchesDriver cross-checks our SigV4 implementation against
// the official driver's: for the nonce, host, date and credentials the driver
// actually used, we must produce the identical Authorization header.
func TestAWSSignatureMatchesDriver(t *testing.T) {
	for _, tc := range []struct{ host, token string }{
		{"sts.amazonaws.com", ""},
		{"sts.eu-west-1.amazonaws.com", "SESSION/TOKEN+value=="},
	} {
		srv := newFakeAWS(t, tc.host)
		o := options.Client().
			ApplyURI(fmt.Sprintf("mongodb://127.0.0.1:%d/?directConnection=true", srv.ln.Addr().(*net.TCPAddr).Port)).
			SetServerSelectionTimeout(5 * time.Second)
		props := map[string]string{}
		if tc.token != "" {
			props["AWS_SESSION_TOKEN"] = tc.token
		}
		o.SetAuth(options.Credential{AuthMechanism: "MONGODB-AWS", Username: "AKIDEXAMPLE",
			Password: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", AuthMechanismProperties: props})
		c, err := mongo.Connect(o)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Ping(context.Background(), nil); err != nil {
			t.Fatalf("%s: driver ping: %v", tc.host, err)
		}
		c.Disconnect(context.Background())

		nonce, final := srv.captured()
		a, d, tok := parts(t, final)
		when, err := time.Parse("20060102T150405Z", d)
		if err != nil {
			t.Fatal(err)
		}
		creds := awsCreds{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", tok}
		got, gd := signAWS(creds, tc.host, nonce, when)
		if gd != d || got != a {
			t.Errorf("%s: signature differs from the driver's\n ours:   %s\n driver: %s", tc.host, got, a)
		}
		if tok != tc.token {
			t.Errorf("driver sent token %q, want %q", tok, tc.token)
		}
	}
}

// TestAuthAWSExchange runs our client against the fake server.
func TestAuthAWSExchange(t *testing.T) {
	srv := newFakeAWS(t, "sts.us-west-2.amazonaws.com")
	cfg := &config.Config{MaxMessageBytes: 1 << 20, Upstream: config.Upstream{
		Addr: srv.ln.Addr().String(), AuthMechanism: "MONGODB-AWS",
		AWSAccessKeyID: "AKIDEXAMPLE", AWSSecretAccessKey: "secret", AWSSessionToken: "tok",
	}}
	d, err := NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	nonce, final := srv.captured()
	a, date, tok := parts(t, final)
	when, _ := time.Parse("20060102T150405Z", date)
	if want, _ := signAWS(awsCreds{"AKIDEXAMPLE", "secret", "tok"}, "sts.us-west-2.amazonaws.com", nonce, when); a != want || tok != "tok" {
		t.Fatalf("authorization = %q", a)
	}

	// A server that does not echo our nonce must be refused.
	bad := newFakeAWS(t, "sts.amazonaws.com")
	cfg.Upstream.Addr = bad.ln.Addr().String()
	bad.host = "a..b" // invalid STS host
	d, _ = NewDialer(cfg)
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("invalid STS host accepted")
	}
}

func TestAWSRegion(t *testing.T) {
	for host, want := range map[string]string{
		"sts.amazonaws.com": "us-east-1", "sts.us-west-2.amazonaws.com": "us-west-2",
		"sts.eu-central-1.amazonaws.com": "eu-central-1", "localhost": "us-east-1",
	} {
		if got := awsRegion(host); got != want {
			t.Errorf("%s -> %s, want %s", host, got, want)
		}
	}
}

func TestAWSCredentialResolution(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENVSECRET")
	t.Setenv("AWS_SESSION_TOKEN", "ENVTOK")
	d := &Dialer{cfg: config.Upstream{}}
	if c, err := d.awsCredentials(); err != nil || c.AccessKeyID != "ENVKEY" || c.SessionToken != "ENVTOK" {
		t.Fatalf("env: %+v %v", c, err)
	}
	d.cfg = config.Upstream{Username: "U", Password: "P"}
	if c, _ := d.awsCredentials(); c.AccessKeyID != "U" || c.SecretAccessKey != "P" {
		t.Fatalf("username/password: %+v", c)
	}
	d.cfg = config.Upstream{AWSAccessKeyID: "A", AWSSecretAccessKey: "S"}
	if c, _ := d.awsCredentials(); c.AccessKeyID != "A" {
		t.Fatalf("explicit: %+v", c)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	d.cfg = config.Upstream{}
	if _, err := d.awsCredentials(); err == nil {
		t.Fatal("expected an error without credentials")
	}
}

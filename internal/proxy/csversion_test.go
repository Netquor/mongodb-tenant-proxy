package proxy

import (
	"testing"

	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
)

func TestChangeStreamUnsupportedOnOldUpstream(t *testing.T) {
	cs := &rewrite.Result{ChangeStream: true}
	if d := changeStreamUnsupported(cs, 13); d == nil { // MongoDB 5.0
		t.Fatal("5.0 upstream must reject change streams")
	} else if c, _ := d.Lookup("code").Int32OK(); c != 115 {
		t.Fatalf("code = %d, want 115 (CommandNotSupported)", c)
	}
	if changeStreamUnsupported(cs, 17) != nil {
		t.Fatal("6.0 upstream must allow change streams")
	}
	if changeStreamUnsupported(&rewrite.Result{}, 13) != nil {
		t.Fatal("non-change-stream commands must be unaffected")
	}
}

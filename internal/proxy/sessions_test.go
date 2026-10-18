package proxy

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

func uuid(b byte) bsoncore.Value {
	id := make([]byte, 16)
	for i := range id {
		id[i] = b
	}
	return bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: bsoncore.BuildDocument(nil,
		bsoncore.AppendBinaryElement(nil, "id", 4, id))}
}

func cmdWithLsid(cmd string, lsid bsoncore.Value) bsoncore.Document {
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, cmd, "c"),
		bsoncore.AppendValueElement(nil, "lsid", lsid))
}

func TestSessionBinding(t *testing.T) {
	now := time.Unix(1000, 0)
	st := newSessionTable(30, func() time.Time { return now })

	if m := st.check("a", "find", cmdWithLsid("find", uuid(1))); m != "" {
		t.Fatal(m)
	}
	if m := st.check("a", "find", cmdWithLsid("find", uuid(1))); m != "" {
		t.Fatal("owner must be allowed again:", m)
	}
	for _, cmd := range []string{"find", "getMore", "commitTransaction", "abortTransaction", "insert"} {
		if m := st.check("b", cmd, cmdWithLsid(cmd, uuid(1))); m == "" {
			t.Fatalf("%s with a foreign lsid must be rejected", cmd)
		}
	}

	arr := func(cmd string, ids ...bsoncore.Value) bsoncore.Document {
		return bsoncore.BuildDocument(nil, bsoncore.AppendArrayElement(nil, cmd, bsoncore.BuildArray(nil, ids...)))
	}
	for _, cmd := range []string{"endSessions", "refreshSessions", "killSessions"} {
		if m := st.check("b", cmd, arr(cmd, uuid(2), uuid(1))); m == "" {
			t.Fatalf("%s listing a foreign session must be rejected", cmd)
		}
	}
	// ...and must not have bound the unbound session 2 to b.
	if m := st.check("a", "find", cmdWithLsid("find", uuid(2))); m != "" {
		t.Fatalf("rejected request leaked a binding: %s", m)
	}
	if m := st.check("a", "endSessions", arr("endSessions", uuid(1), uuid(2))); m != "" {
		t.Fatal(m)
	}

	if m := st.check("a", "find", cmdWithLsid("find", bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "x")})); m == "" {
		t.Fatal("malformed lsid accepted")
	}
	if m := st.check("a", "find", bsoncore.BuildDocument(nil, bsoncore.AppendStringElement(nil, "find", "c"))); m != "" {
		t.Fatal("commands without lsid are fine:", m)
	}

	// TTL: after timeout + grace the binding lapses and the id can be reused.
	now = now.Add(30*time.Minute + sessionGrace - time.Second)
	if m := st.check("b", "find", cmdWithLsid("find", uuid(1))); m == "" {
		t.Fatal("binding expired too early")
	}
	// A's use above refreshed nothing (b was rejected); a's own use refreshes.
	if m := st.check("a", "find", cmdWithLsid("find", uuid(1))); m != "" {
		t.Fatal(m)
	}
	now = now.Add(30*time.Minute + sessionGrace - time.Second)
	if m := st.check("b", "find", cmdWithLsid("find", uuid(1))); m == "" {
		t.Fatal("use must refresh the TTL")
	}
	now = now.Add(2 * time.Second)
	if m := st.check("b", "find", cmdWithLsid("find", uuid(1))); m != "" {
		t.Fatal("expired binding should be claimable:", m)
	}
	if st.size() == 0 {
		t.Fatal("table empty")
	}
}

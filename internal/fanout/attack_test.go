package fanout

import (
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

func event(t *testing.T, pad int) bsoncore.Document {
	b, err := bson.Marshal(bson.M{"operationType": "insert", "pad": make([]byte, pad)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A subscriber that never reads is cut off by size as well as by count: 20000
// events of a few MiB each must not be retained.
func TestSubscriberQueueIsBoundedByBytes(t *testing.T) {
	s := &Sub{notify: make(chan struct{}, 1)}
	ev := event(t, 4<<20)
	pushed := 0
	for ; pushed < 100; pushed++ {
		s.push(ev)
		s.mu.Lock()
		err := s.err
		s.mu.Unlock()
		if err != nil {
			break
		}
	}
	if pushed >= 20 {
		t.Fatalf("%d events of 4 MiB queued (%d MiB) before the subscriber was cut off", pushed, pushed*4)
	}
	if _, _, _, err := s.Next(10, time.Millisecond); !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflowed subscriber got %v, want ErrOverflow (so the driver resumes it privately)", err)
	}
	s.mu.Lock()
	n, qb := len(s.queue), s.qbytes
	s.mu.Unlock()
	if n != 0 || qb != 0 {
		t.Fatalf("overflow kept %d events / %d bytes pinned", n, qb)
	}
}

// Draining the queue gives the space back: a reader that keeps up is never cut off.
func TestSubscriberThatKeepsUpIsNotCutOff(t *testing.T) {
	s := &Sub{notify: make(chan struct{}, 1)}
	ev := event(t, 1<<20)
	for i := 0; i < 500; i++ {
		s.push(ev)
		if i%8 == 7 {
			if _, _, _, err := s.Next(100, time.Millisecond); err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.qbytes < 0 || s.qbytes > 8*len(ev) {
		t.Fatalf("byte accounting drifted: %d", s.qbytes)
	}
}

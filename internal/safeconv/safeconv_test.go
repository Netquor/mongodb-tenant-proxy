package safeconv

import (
	"math"
	"testing"
)

func TestConversions(t *testing.T) {
	if I32(0xFFFFFFFF) != -1 || U32(-1) != 0xFFFFFFFF || I64(math.MaxUint64) != -1 {
		t.Fatal("two's complement reinterpretation broken")
	}
	if Sat32(int64(math.MaxInt64)) != math.MaxInt32 || Sat32(int64(math.MinInt64)) != math.MinInt32 || Sat32(7) != 7 {
		t.Fatal("Sat32")
	}
	if Len32(-1) != 0 || Len32(math.MaxInt64) != math.MaxInt32 || Len32(16) != 16 {
		t.Fatal("Len32")
	}
	b := make([]byte, 4)
	PutLen(b, 0x01020304)
	if b[0] != 4 || b[3] != 1 {
		t.Fatalf("PutLen = %v", b)
	}
}

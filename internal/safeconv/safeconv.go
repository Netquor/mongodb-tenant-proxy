// Package safeconv centralises the integer conversions the wire-protocol code
// needs, so each narrowing or sign change is reviewed (and gosec G115 is
// justified) once instead of at every call site.
package safeconv

import (
	"encoding/binary"
	"math"
)

// I32 reinterprets a little-endian wire uint32 as the signed int32 the
// MongoDB wire format and BSON define for the same bytes (two's complement).
// Wraparound is the protocol's meaning, not an overflow; callers still range
// check the result (e.g. message length against the size limit).
func I32(u uint32) int32 {
	return int32(u) // #nosec G115 -- intentional two's-complement reinterpretation of wire bytes
}

// U32 is the inverse of I32, for writing signed wire fields.
func U32(i int32) uint32 {
	return uint32(i) // #nosec G115 -- intentional two's-complement reinterpretation for wire bytes
}

// I64 reinterprets a little-endian wire uint64 as int64 (BSON int64 / cursor ids).
func I64(u uint64) int64 {
	return int64(u) // #nosec G115 -- intentional two's-complement reinterpretation of wire bytes
}

// Sat32 converts to int32, saturating instead of wrapping. Used for values
// reported back to clients (error codes, counts) where wrapping could alias a
// different meaning.
func Sat32[T ~int | ~int64](v T) int32 {
	switch {
	case int64(v) > math.MaxInt32:
		return math.MaxInt32
	case int64(v) < math.MinInt32:
		return math.MinInt32
	}
	return int32(v)
}

// Len32 converts a length to the uint32 a wire/BSON length prefix holds,
// saturating at MaxInt32. Real messages are bounded by maxMessageBytes (48 MiB
// by default) and BSON documents by 16 MiB, so saturation only ever produces
// an invalid-length value for an already-impossible input, never a short one.
func Len32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return uint32(n)
}

// PutLen writes n as a little-endian uint32 into b[0:4].
func PutLen(b []byte, n int) { binary.LittleEndian.PutUint32(b, Len32(n)) }

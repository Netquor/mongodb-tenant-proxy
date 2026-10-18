package upstream

import (
	"errors"
	"net"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Server error codes that mean "this member is not (or no longer) the
// primary" or "this member is going away".
const (
	CodeHostUnreachable       = 6
	CodeNotWritablePrimary    = 10107
	CodeNotPrimaryNoSecOK     = 13435
	CodeNotPrimaryOrSecondary = 13436
	CodePrimarySteppedDown    = 189
	CodeInterruptedAtShutdown = 11600
	CodeInterruptedReplState  = 11602
	CodeShutdownInProgress    = 91
)

// Labels drivers act on.
const (
	LabelRetryableWrite = "RetryableWriteError"
	LabelTransient      = "TransientTransactionError"
)

// IsNotPrimary reports codes returned when a command that needs the primary
// reached a member that is not one. The command never executed, so it is safe
// to run again elsewhere.
func IsNotPrimary(code int32) bool {
	switch code {
	case CodeNotWritablePrimary, CodeNotPrimaryNoSecOK, CodeNotPrimaryOrSecondary:
		return true
	}
	return false
}

// IsStateChange reports any "replica set state changed" code.
func IsStateChange(code int32) bool {
	switch code {
	case CodePrimarySteppedDown, CodeInterruptedAtShutdown, CodeInterruptedReplState, CodeShutdownInProgress:
		return true
	}
	return IsNotPrimary(code)
}

// IsShutdown reports codes that mean the member is shutting down, so its
// pooled connections are all about to die.
func IsShutdown(code int32) bool {
	return code == CodeInterruptedAtShutdown || code == CodeShutdownInProgress
}

// IsNetwork reports a transport-level failure.
func IsNetwork(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) || errors.Is(err, errPoolClosed) || isEOF(err)
}

// ReplyStatus summarises the failure information of a command reply.
type ReplyStatus struct {
	OK     bool
	Code   int32 // top-level code, else write concern error, else first write error
	Labels []string
}

// Status extracts error information from a reply document.
func Status(resp bsoncore.Document) ReplyStatus {
	st := ReplyStatus{}
	ok := resp.Lookup("ok")
	if v, isNum := ok.AsFloat64OK(); isNum {
		st.OK = v == 1
	} else if v, isNum := ok.AsInt64OK(); isNum {
		st.OK = v == 1
	}
	if c, has := resp.Lookup("code").AsInt64OK(); has {
		st.Code = int32(c)
	}
	if st.Code == 0 {
		if c, has := resp.Lookup("writeConcernError", "code").AsInt64OK(); has {
			st.Code = int32(c)
		}
	}
	if st.Code == 0 {
		if arr, has := resp.Lookup("writeErrors").ArrayOK(); has {
			vals, _ := arr.Values()
			for _, v := range vals {
				d, _ := v.DocumentOK()
				if c, has := d.Lookup("code").AsInt64OK(); has && IsStateChange(int32(c)) {
					st.Code = int32(c)
					break
				}
			}
		}
	}
	if arr, has := resp.Lookup("errorLabels").ArrayOK(); has {
		vals, _ := arr.Values()
		for _, v := range vals {
			if s, has := v.StringValueOK(); has {
				st.Labels = append(st.Labels, s)
			}
		}
	}
	return st
}

// HasLabel reports whether the status carries a label.
func (s ReplyStatus) HasLabel(l string) bool {
	for _, x := range s.Labels {
		if x == l {
			return true
		}
	}
	return false
}

// AddLabels returns doc with the given error labels merged into errorLabels.
func AddLabels(doc bsoncore.Document, labels ...string) bsoncore.Document {
	have := map[string]bool{}
	var vals []bsoncore.Value
	if arr, ok := doc.Lookup("errorLabels").ArrayOK(); ok {
		vs, _ := arr.Values()
		for _, v := range vs {
			if s, ok := v.StringValueOK(); ok {
				have[s] = true
			}
			vals = append(vals, v)
		}
	}
	add := false
	for _, l := range labels {
		if !have[l] {
			have[l] = true
			add = true
			vals = append(vals, bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, l)})
		}
	}
	if !add {
		return doc
	}
	els, err := doc.Elements()
	if err != nil {
		return doc
	}
	out := make([]byte, 4, len(doc)+64)
	for _, e := range els {
		if e.Key() != "errorLabels" {
			out = append(out, e...)
		}
	}
	out = bsoncore.AppendArrayElement(out, "errorLabels", bsoncore.BuildArray(nil, vals...))
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

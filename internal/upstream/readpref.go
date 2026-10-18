package upstream

import (
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Mode is a read preference mode.
type Mode int

// Read preference modes.
const (
	Primary Mode = iota
	PrimaryPreferred
	Secondary
	SecondaryPreferred
	Nearest
)

func (m Mode) String() string {
	return [...]string{"primary", "primaryPreferred", "secondary", "secondaryPreferred", "nearest"}[m]
}

// minStaleness is the smallest maxStalenessSeconds servers accept.
const minStaleness = 90 * time.Second

// Selector says which member a command may run on.
type Selector struct {
	Mode Mode
	// Tags is an ordered list of tag sets; the first that matches a member wins.
	Tags []map[string]string
	// MaxStaleness excludes secondaries lagging further than this (0 = off).
	MaxStaleness time.Duration
	// Addr, when set, pins the command to exactly this member (cursor
	// affinity); the other fields are ignored.
	Addr string
}

// ParseReadPref decodes a $readPreference document.
func ParseReadPref(doc bsoncore.Document) (Selector, error) {
	var s Selector
	mode, ok := doc.Lookup("mode").StringValueOK()
	if !ok {
		return s, fmt.Errorf("$readPreference requires a mode")
	}
	switch mode {
	case "primary":
		s.Mode = Primary
	case "primaryPreferred":
		s.Mode = PrimaryPreferred
	case "secondary":
		s.Mode = Secondary
	case "secondaryPreferred":
		s.Mode = SecondaryPreferred
	case "nearest":
		s.Mode = Nearest
	default:
		return s, fmt.Errorf("unknown read preference mode %q", mode)
	}
	if tags, ok := doc.Lookup("tags").ArrayOK(); ok {
		if s.Mode == Primary {
			return s, fmt.Errorf("mode 'primary' conflicts with tags")
		}
		vals, _ := tags.Values()
		for _, v := range vals {
			td, ok := v.DocumentOK()
			if !ok {
				return s, fmt.Errorf("$readPreference tags must be documents")
			}
			set := map[string]string{}
			els, _ := td.Elements()
			for _, e := range els {
				set[e.Key()], _ = e.Value().StringValueOK()
			}
			s.Tags = append(s.Tags, set)
		}
	}
	if v := doc.Lookup("maxStalenessSeconds"); v.Type != 0 {
		n, ok := v.AsInt64OK()
		if !ok {
			return s, fmt.Errorf("maxStalenessSeconds must be a number")
		}
		if n > 0 || v.Type != bsoncore.TypeInt32 {
			if s.Mode == Primary {
				return s, fmt.Errorf("mode 'primary' conflicts with maxStalenessSeconds")
			}
			if n >= 0 {
				s.MaxStaleness = time.Duration(n) * time.Second
			}
		}
		if s.MaxStaleness > 0 && s.MaxStaleness < minStaleness {
			return s, fmt.Errorf("maxStalenessSeconds must be at least %d", int(minStaleness/time.Second))
		}
	}
	return s, nil
}

func (s Selector) String() string {
	if s.Addr != "" {
		return "member " + s.Addr
	}
	out := s.Mode.String()
	if len(s.Tags) > 0 {
		out += fmt.Sprintf(" tags=%v", s.Tags)
	}
	if s.MaxStaleness > 0 {
		out += fmt.Sprintf(" maxStaleness=%s", s.MaxStaleness)
	}
	return out
}

func tagsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

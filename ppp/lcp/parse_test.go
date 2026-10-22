package lcp

import (
	"testing"

	"github.com/gandalfast/souppp/ppp"
)

// TestParseRejectsMalformedPackets checks that packets cut short or lying
// about their lengths are rejected with an error rather than a panic: they
// arrive from the peer over the session.
func TestParseRejectsMalformedPackets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto ppp.ProtocolNumber
		buf   []byte
	}{
		{"length below the header", ppp.ProtoLCP, []byte{1, 1, 0, 3}},
		{"length beyond the packet", ppp.ProtoLCP, []byte{1, 1, 0x30, 0x30, 1, 4, 5, 220}},
		{"MRU option cut", ppp.ProtoLCP, []byte{1, 1, 0, 6, 1, 4}},
		{"magic number option cut", ppp.ProtoLCP, []byte{1, 1, 0, 7, 5, 6, 1}},
		{"auth option longer than the payload", ppp.ProtoLCP, []byte{1, 1, 0, 8, 3, 10, 0xc2, 0x23}},
		{"auth option shorter than its header", ppp.ProtoLCP, []byte{1, 1, 0, 8, 3, 2, 0xc2, 0x23}},
		{"generic option longer than the payload", ppp.ProtoLCP, []byte{1, 1, 0, 8, 9, 10, 1, 2}},
		{"option header cut", ppp.ProtoLCP, []byte{1, 1, 0, 5, 9}},
		{"IP address option cut", ppp.ProtoIPCP, []byte{1, 1, 0, 8, 3, 6, 10, 0}},
		{"interface id option cut", ppp.ProtoIPv6CP, []byte{1, 1, 0, 8, 1, 10, 1, 2}},
		{"echo without magic number", ppp.ProtoLCP, []byte{9, 1, 0, 4}},
		{"protocol reject without protocol", ppp.ProtoLCP, []byte{8, 1, 0, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPacket(tc.proto)
			if err := p.Parse(tc.buf); err == nil {
				t.Fatalf("Parse(% x) = nil, want an error", tc.buf)
			}
		})
	}
}

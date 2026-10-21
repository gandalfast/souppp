package pppoe

import "testing"

// TestParseRejectsMalformedPackets checks that packets cut short or lying
// about their lengths are rejected with an error rather than a panic: they
// arrive from the access network, before any session exists.
func TestParseRejectsMalformedPackets(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"length beyond the frame", []byte{0x11, 0x07, 0, 0, 0, 40, 0x01, 0x02, 0, 0}},
		{"tag header cut", []byte{0x11, 0x07, 0, 0, 0, 2, 0x01, 0x02}},
		{"tag value cut", []byte{0x11, 0x07, 0, 0, 0, 6, 0x01, 0x02, 0, 10, 'a', 'b'}},
		{"end-of-list cut", []byte{0x11, 0x07, 0, 0, 0, 2, 0, 0}},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p Packet
			if err := p.Parse(tc.buf); err == nil {
				t.Fatalf("Parse(% x) = nil, want an error", tc.buf)
			}
		})
	}
}

// TestParseTaglessPADT checks that a discovery packet with a zero length,
// such as a PADT, which RFC 2516 sends without tags, parses with no tags,
// and that parsing into a packet used before does not keep its old tags.
func TestParseTaglessPADT(t *testing.T) {
	var p Packet
	if err := p.Parse([]byte{0x11, 0x07, 0, 0, 0, 4, 0x01, 0x02, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if len(p.Tags) != 1 {
		t.Fatalf("parsed %d tags from a PADO with one, want 1", len(p.Tags))
	}
	if err := p.Parse([]byte{0x11, 0xa7, 0x12, 0x34, 0, 0}); err != nil {
		t.Fatalf("Parse of a tagless PADT: %v", err)
	}
	if p.Code != CodePADT || p.SessionID != 0x1234 || len(p.Tags) != 0 {
		t.Fatalf("parsed %+v, want a PADT for session 0x1234 with no tags", p)
	}
}

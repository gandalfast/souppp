package chap

import "testing"

// TestParseRejectsMalformedPackets checks that packets cut short or lying
// about their lengths are rejected with an error rather than a panic.
func TestParseRejectsMalformedPackets(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"length beyond the packet", []byte{1, 1, 0, 9, 4}},
		{"challenge cut inside the value", []byte{1, 1, 0, 7, 4, 1, 2}},
		{"value length beyond the length field", []byte{1, 1, 0, 6, 4, 1, 2, 3}},
		{"value filling the packet with no room for itself", []byte{1, 1, 0, 8, 4, 1, 2, 3}},
		{"success with length beyond the packet", []byte{3, 1, 0, 9, 'o', 'k'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p Packet
			if err := p.Parse(tc.buf); err == nil {
				t.Fatalf("Parse(% x) = nil, want an error", tc.buf)
			}
		})
	}
}

// TestParseChallenge checks a well-formed challenge is parsed into its
// value and name.
func TestParseChallenge(t *testing.T) {
	var p Packet
	if err := p.Parse([]byte{1, 7, 0, 11, 4, 1, 2, 3, 4, 'a', 'c'}); err != nil {
		t.Fatal(err)
	}
	if p.Code != CodeChallenge || p.ID != 7 || string(p.Value) != "\x01\x02\x03\x04" || string(p.Name) != "ac" {
		t.Fatalf("parsed %+v, want challenge 7 with value 01020304 and name ac", p)
	}
}

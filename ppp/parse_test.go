package ppp

import "testing"

// TestParsePacketIPRejectsShortPackets checks that IP packets cut short at
// any layer are rejected rather than panicking the adapter.
func TestParsePacketIPRejectsShortPackets(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"IPv6 header cut", append([]byte{0x60}, make([]byte, 30)...)},
		{"IPv4 UDP header cut", []byte{0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 0x02, 0x22}},
		{"IPv6 ICMPv6 header cut", append([]byte{0x60, 0, 0, 0, 0, 2, 58, 255}, append(make([]byte, 32), 128, 0)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePacketIP(tc.buf); err == nil {
				t.Fatalf("parsePacketIP(% x) = nil error, want an error", tc.buf)
			}
		})
	}
}

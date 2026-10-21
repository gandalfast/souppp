package ethernetconn

import "testing"

// TestParseReceivedDataRejectsShortFrames checks that frames cut short at
// any layer are rejected rather than panicking the relay: they come off the
// wire.
func TestParseReceivedDataRejectsShortFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"no header", []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08}},
		{"VLAN tag cut", []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x81, 0x00, 0}},
		{"IPv4 header cut", []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00, 0x45, 0, 0, 20}},
		{"IPv6 header cut", append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x86, 0xdd}, make([]byte, 30)...)},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseReceivedData(tc.buf); err == nil {
				t.Fatalf("parseReceivedData(% x) = nil error, want an error", tc.buf)
			}
			if typ := ParseEthernetType(tc.buf); typ != 0 && len(tc.buf) < 14 {
				t.Fatalf("ParseEthernetType(% x) = %#x, want 0 for a frame without a type", tc.buf, typ)
			}
		})
	}
}

// TestParseReceivedDataUDPWithoutHeader checks that an IPv4 packet that
// claims UDP but ends before the UDP header is parsed as having no
// transport payload rather than panicking.
func TestParseReceivedDataUDPWithoutHeader(t *testing.T) {
	frame := append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00},
		0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 0x02, 0x22, 0x02, 0x23)
	rcv, err := parseReceivedData(frame)
	if err != nil {
		t.Fatal(err)
	}
	if rcv.Protocol != 17 || rcv.TransportPayloadBytes != nil || rcv.LocalPort != 0 {
		t.Fatalf("parsed %+v, want UDP with no transport payload", rcv)
	}
}

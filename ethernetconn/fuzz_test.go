package ethernetconn

import "testing"

func FuzzParseReceivedData(f *testing.F) {
	// IPv4 UDP frame: dst, src, type, 20-byte IP header, 8-byte UDP header, payload.
	f.Add(append(append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00},
		0x45, 0, 0, 29, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
		0x02, 0x22, 0x02, 0x23, 0, 9, 0, 0), 'x'))
	// VLAN-tagged IPv6 UDP frame.
	f.Add(append(append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x81, 0x00, 0, 1, 0x86, 0xdd},
		0x60, 0, 0, 0, 0, 9, 17, 64,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x02, 0x22, 0x02, 0x23, 0, 9, 0, 0), 'x'))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseReceivedData(b)
		_ = ParseEthernetType(b)
	})
}

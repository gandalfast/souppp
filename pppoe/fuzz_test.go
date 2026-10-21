package pppoe

import "testing"

func FuzzPacketParse(f *testing.F) {
	f.Add([]byte{0x11, 0x07, 0, 0, 0, 0})
	f.Add([]byte{0x11, 0x07, 0, 0, 0, 8, 0x01, 0x01, 0, 0, 0x01, 0x02, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Packet
		_ = p.Parse(b)
	})
}

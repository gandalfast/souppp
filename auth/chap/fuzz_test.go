package chap

import "testing"

func FuzzPacketParse(f *testing.F) {
	f.Add([]byte{1, 1, 0, 9, 4, 1, 2, 3, 4})
	f.Add([]byte{3, 1, 0, 6, 'o', 'k'})
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Packet
		_ = p.Parse(b)
	})
}

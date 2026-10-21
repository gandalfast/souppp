package pap

import "testing"

func FuzzPacketParse(f *testing.F) {
	f.Add([]byte{1, 1, 0, 14, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'})
	f.Add([]byte{2, 1, 0, 7, 2, 'o', 'k'})
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Packet
		_ = p.Parse(b)
	})
}

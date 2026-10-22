package ppp

import "testing"

func FuzzParsePacketIP(f *testing.F) {
	f.Add(append([]byte{0x45, 0, 0, 29, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
		0x02, 0x22, 0x02, 0x23, 0, 9, 0, 0}, 'x'))
	f.Add(append([]byte{0x60, 0, 0, 0, 0, 9, 17, 64,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x02, 0x22, 0x02, 0x23, 0, 9, 0, 0}, 'x'))
	f.Add([]byte{0x60, 0, 0, 0, 0, 8, 58, 255,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		128, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parsePacketIP(b)
	})
}

package lcp

import (
	"testing"

	"github.com/gandalfast/souppp/ppp"
)

func FuzzPacketParse(f *testing.F) {
	f.Add(uint16(ppp.ProtoLCP), []byte{1, 1, 0, 8, 1, 4, 5, 220})
	f.Add(uint16(ppp.ProtoIPCP), []byte{1, 1, 0, 10, 3, 6, 10, 0, 0, 1})
	f.Add(uint16(ppp.ProtoIPv6CP), []byte{1, 1, 0, 14, 1, 10, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, proto uint16, b []byte) {
		p := NewPacket(ppp.ProtocolNumber(proto))
		_ = p.Parse(b)
	})
}

package lcp

import (
	"encoding/hex"
	"github.com/gandalfast/souppp/ppp"
	"testing"
)

func TestLCP(t *testing.T) {
	lcppkt, err := hex.DecodeString("01100012010405d40304c023050642ae33170000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var l Packet
	if err := l.Parse(lcppkt); err != nil {
		t.Fatal(err)
	}

	if l.Code != CodeConfigureRequest {
		t.Fatal("wrong lcp code")
	}
	if *(l.GetOption(OpTypeMaximumReceiveUnit)[0].(*OpMRU)) != OpMRU(1492) {
		t.Fatal("wrong MRU")
	}
	if l.GetOption(OpTypeAuthenticationProtocol)[0].(*OpAuthProto).Proto != ppp.ProtoPAP {
		t.Fatal("wrong auth proto")
	}
	if *(l.GetOption(OpTypeMagicNumber)[0].(*OpMagicNum)) != 0x42ae3317 {
		t.Fatal("wrong magic number")
	}

	lencoded, err := l.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	if err := l.Parse(lencoded); err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%v", l)
}

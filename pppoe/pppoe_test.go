package pppoe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gandalfast/souppp/ethernetconn"
	"github.com/rs/zerolog"
)

// fakeRelay is a PacketRelay whose frames the test injects and inspects.
type fakeRelay struct {
	recv, send chan []byte
	stop       chan struct{}
}

func (r *fakeRelay) Register([]ethernetconn.L2EndpointKey, bool) (chan []byte, chan []byte, chan struct{}, int) {
	return r.recv, r.send, r.stop, 1
}
func (r *fakeRelay) Unregister(int) {}
func (r *fakeRelay) Close() error   { return nil }

var (
	clientMAC = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	acMAC     = net.HardwareAddr{2, 0, 0, 0, 0, 2}
	otherMAC  = net.HardwareAddr{2, 0, 0, 0, 0, 3}
)

// frame builds an Ethernet frame.
func frame(dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], etherType)
	return append(f, payload...)
}

func mustSerialize(t *testing.T, pkt Packet) []byte {
	t.Helper()
	b, err := pkt.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newOpenSession returns a PPPoE in the open state with session 0x1234 to
// the access concentrator acMAC, over a fake relay.
func newOpenSession(t *testing.T) (*PPPoE, *fakeRelay) {
	t.Helper()
	relay := &fakeRelay{recv: make(chan []byte, 8), send: make(chan []byte, 8), stop: make(chan struct{})}
	conn := ethernetconn.NewEtherConn(clientMAC, relay, []uint16{EtherTypePPPoEDiscovery, EtherTypePPPoESession})
	logger := zerolog.Nop()
	p := NewPPPoE(conn, &logger)
	p.state = pppoeStateOpen
	p.sessionID = 0x1234
	p.acMAC = acMAC
	return p, relay
}

// TestReadFromTerminatesOnPADT checks that a PADT from the access
// concentrator for the open session ends it: ReadFrom reports the
// termination, the session is closed, Close sends no PADT back, and PADTs
// for another session or from another MAC are ignored.
func TestReadFromTerminatesOnPADT(t *testing.T) {
	p, relay := newOpenSession(t)
	pppPayload := []byte{0xc0, 0x21, 1, 2, 3, 4}
	relay.recv <- frame(clientMAC, acMAC, EtherTypePPPoEDiscovery, mustSerialize(t, Packet{Code: CodePADT, SessionID: 0x9999}))
	relay.recv <- frame(clientMAC, otherMAC, EtherTypePPPoEDiscovery, mustSerialize(t, Packet{Code: CodePADT, SessionID: 0x1234}))
	relay.recv <- frame(clientMAC, acMAC, EtherTypePPPoESession, mustSerialize(t, Packet{Code: CodeSession, SessionID: 0x1234, Payload: pppPayload}))

	buf := make([]byte, 1500)
	if err := p.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := p.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after two foreign PADTs: %v, want the session packet", err)
	}
	if !bytes.Equal(buf[:n], pppPayload) {
		t.Fatalf("ReadFrom returned % x, want the session payload % x", buf[:n], pppPayload)
	}

	relay.recv <- frame(clientMAC, acMAC, EtherTypePPPoEDiscovery, mustSerialize(t, Packet{Code: CodePADT, SessionID: 0x1234}))
	if _, _, err := p.ReadFrom(buf); !errors.Is(err, ErrSessionTerminated) {
		t.Fatalf("ReadFrom after the peer's PADT: %v, want %v", err, ErrSessionTerminated)
	}
	if _, _, err := p.ReadFrom(buf); !errors.Is(err, ErrSessionTerminated) {
		t.Fatalf("ReadFrom on the terminated session: %v, want %v", err, ErrSessionTerminated)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-relay.send:
		t.Fatalf("Close sent a frame after the peer's PADT: % x", f)
	default:
	}
}

// TestCloseSendsPADTWhileOpen checks that closing an open session, which a
// peer did not terminate, sends it a PADT.
func TestCloseSendsPADTWhileOpen(t *testing.T) {
	p, relay := newOpenSession(t)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-relay.send:
		var pkt Packet
		if err := pkt.Parse(f[14:]); err != nil || binary.BigEndian.Uint16(f[12:14]) != EtherTypePPPoEDiscovery || pkt.Code != CodePADT || pkt.SessionID != 0x1234 {
			t.Fatalf("Close sent % x, want a PADT for session 0x1234", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close sent nothing, want a PADT")
	}
}

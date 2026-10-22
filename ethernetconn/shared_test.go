package ethernetconn

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// captureConn is a SharedEthernetConn that keeps the IP packets written
// through it.
type captureConn struct {
	packets [][]byte
}

func (c *captureConn) Register(L4HashKey) chan *EthernetResponse {
	return make(chan *EthernetResponse, 1)
}
func (c *captureConn) Unregister(L4HashKey) {}
func (c *captureConn) WriteIPPktTo(p []byte, _ net.HardwareAddr) (int, error) {
	c.packets = append(c.packets, append([]byte(nil), p...))
	return len(p), nil
}
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// udpChecksumIsValid reports whether the UDP checksum of an IPv6 packet
// verifies against the addresses in its own header, as a receiver checks
// it: the ones' complement sum over the pseudo-header and the UDP segment,
// checksum field included, must come out as zero.
func udpChecksumIsValid(pkt []byte) bool {
	src := &net.UDPAddr{IP: pkt[8:24]}
	dst := &net.UDPAddr{IP: pkt[24:40]}
	udp := pkt[40:]
	csum := pseudoHeaderChecksumV6(src, dst) + 17 + uint32(len(udp))
	return tcpipChecksum(udp, csum) == 0
}

// TestSharedRUDPConnWriteToSendsFromTheLocalAddress checks that a packet
// written through a shared connection carries the connection's own address
// and port as its source, in the IPv6 header, in the UDP header and in the
// pseudo-header the checksum covers, so that the checksum verifies at the
// receiver. DHCPv6 solicits go through this path.
func TestSharedRUDPConnWriteToSendsFromTheLocalAddress(t *testing.T) {
	local := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 546}
	remote := &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547}
	capture := &captureConn{}
	conn, err := NewSharingRUDPConn(local, capture)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("solicit")
	n, err := conn.WriteTo(payload, remote)
	if err != nil || n != len(payload) {
		t.Fatalf("WriteTo = %d, %v; want %d, nil", n, err, len(payload))
	}
	if len(capture.packets) != 1 {
		t.Fatalf("%d packets written, want 1", len(capture.packets))
	}
	pkt := capture.packets[0]
	if len(pkt) != 40+8+len(payload) {
		t.Fatalf("packet is %d bytes, want an IPv6 header, a UDP header and the payload", len(pkt))
	}
	if src := net.IP(pkt[8:24]); !src.Equal(local.IP) {
		t.Errorf("IPv6 source %v, want %v", src, local.IP)
	}
	if dst := net.IP(pkt[24:40]); !dst.Equal(remote.IP) {
		t.Errorf("IPv6 destination %v, want %v", dst, remote.IP)
	}
	udp := pkt[40:]
	if sp := binary.BigEndian.Uint16(udp[0:2]); int(sp) != local.Port {
		t.Errorf("UDP source port %d, want %d", sp, local.Port)
	}
	if dp := binary.BigEndian.Uint16(udp[2:4]); int(dp) != remote.Port {
		t.Errorf("UDP destination port %d, want %d", dp, remote.Port)
	}
	if !udpChecksumIsValid(pkt) {
		t.Errorf("UDP checksum %#04x does not verify against the packet's own addresses", binary.BigEndian.Uint16(udp[6:8]))
	}
}

// TestIPv6UDPChecksumNeverZero checks that a payload whose checksum
// computes to zero is sent with 0xffff, as RFC 8200 section 8.1 requires:
// over IPv6 a zero UDP checksum means "no checksum" and is discarded.
func TestIPv6UDPChecksumNeverZero(t *testing.T) {
	local := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 546}
	remote := &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547}
	ruc, err := NewRUDPConn(local, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Find a payload whose checksum would be zero: vary the last two bytes.
	payload := make([]byte, 10)
	found := false
	for v := 0; v < 1<<16 && !found; v++ {
		binary.BigEndian.PutUint16(payload[8:], uint16(v))
		pkt, _ := ruc.buildPacket(payload, local, remote)
		found = binary.BigEndian.Uint16(pkt[40+6:]) == 0xffff || binary.BigEndian.Uint16(pkt[40+6:]) == 0
		if found {
			if got := binary.BigEndian.Uint16(pkt[40+6:]); got != 0xffff {
				t.Fatalf("checksum sent as %#04x, want 0xffff", got)
			}
			if !udpChecksumIsValid(pkt) {
				t.Fatal("the 0xffff checksum does not verify")
			}
		}
	}
	if !found {
		t.Fatal("no payload with a zero checksum found among 65536 candidates")
	}
}

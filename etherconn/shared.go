package etherconn

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// SharedEthernetConn is a shared connection where multiple parallel
// connections can be opened simultaneously over it.
type SharedEthernetConn interface {
	Register(key L4HashKey) chan *RelayReceival
	WriteIPPktTo(p []byte, dstMac net.HardwareAddr) (int, error)
	SetWriteDeadline(t time.Time) error
}

// L4HashKey represents a Layer4 (transport) endpoint
// hashed key.
// [0:15] bytes is the IP address,
// [16] is the IP protocol,
// [17:18] is the port number, in big endian
type L4HashKey [19]byte

// NewL4HashKeyWithUDPAddr returns a L4HashKey from a net.UDPAddr
func NewL4HashKeyWithUDPAddr(addr *net.UDPAddr) (r L4HashKey) {
	copy(r[:16], addr.IP.To16())
	r[16] = 17
	binary.BigEndian.PutUint16(r[17:], uint16(addr.Port))
	return r
}

// SharedRUDPConn is the UDP connection could share same SharedEtherConn;
type SharedRUDPConn struct {
	udpConn          *RUDPConn
	conn             SharedEthernetConn
	recvChan         chan *RelayReceival
	readDeadline     time.Time
	readDeadlineLock sync.RWMutex
}

// NewSharingRUDPConn creates a new SharedRUDPConn, to run a
// UDP Conn over a custom SharedEtherConn network.
// SharedRUDPConn doesn't support accepting packets for other MAC addresses,
// and only WithResolveNextHopMacFunc option is supported.
func NewSharingRUDPConn(src *net.UDPAddr, c SharedEthernetConn, roptions ...RUDPConnOption) (*SharedRUDPConn, error) {
	r := new(SharedRUDPConn)
	var err error
	if r.udpConn, err = NewRUDPConn(src, nil, roptions...); err != nil {
		return nil, err
	}
	r.conn = c
	r.recvChan = c.Register(NewL4HashKeyWithUDPAddr(r.udpConn.localAddress))
	return r, nil
}

func (shared *SharedRUDPConn) LocalAddr() net.Addr {
	return shared.udpConn.LocalAddr()
}

func (shared *SharedRUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	shared.readDeadlineLock.RLock()
	deadline := shared.readDeadline
	shared.readDeadlineLock.RUnlock()

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	var received *RelayReceival
	timeout := false

	select {
	case <-ctx.Done():
		timeout = true
	case received = <-shared.recvChan:
		// Save received data into variable
	}

	if received == nil && timeout {
		return 0, nil, ErrTimeOut
	} else if received == nil {
		return 0, nil, errors.New("failed to read from SharedEtherConn")
	}

	copy(p, received.TransportPayloadBytes)
	return len(received.TransportPayloadBytes), &net.UDPAddr{IP: received.RemoteIP, Port: int(received.RemotePort), Zone: "udp"}, nil
}

// WriteTo sends UDP payload to the specified target.
// This function adds UDP and IP headers, and uses RUDPConn's resolve function
// to obtain next hop's MAC address, and use underlying EtherConn to send IP packet,
// with EtherConn's Ethernet encapsulation.
func (shared *SharedRUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	srcAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid source address")
	}
	destAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid destination address")
	}

	buf, destIP := shared.udpConn.buildPacket(p, srcAddr, destAddr)
	nextHopMAC := shared.udpConn.resolveNextHopFunc(destIP)
	if _, err := shared.conn.WriteIPPktTo(buf, nextHopMAC); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (shared *SharedRUDPConn) SetReadDeadline(t time.Time) error {
	shared.readDeadlineLock.Lock()
	defer shared.readDeadlineLock.Unlock()

	shared.readDeadline = t
	return nil
}

func (shared *SharedRUDPConn) SetWriteDeadline(t time.Time) error {
	return shared.conn.SetWriteDeadline(t)
}

func (shared *SharedRUDPConn) SetDeadline(t time.Time) error {
	var errList []error
	errList = append(errList, shared.SetReadDeadline(t))
	errList = append(errList, shared.SetWriteDeadline(t))
	return errors.Join(errList...)
}

func (shared *SharedRUDPConn) Close() error {
	return nil
}

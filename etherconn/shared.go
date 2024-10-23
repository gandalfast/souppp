package etherconn

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// L4RecvKey resprsents a Layer4 recv endpoint:
// [0:15] bytes is the IP address,
// [16] is the IP protocol,
// [17:18] is the port number, in big endian
type L4RecvKey [19]byte

// NewL4RecvKeyViaUDPAddr returns a L4RecvKey from a net.UDPAddr
func NewL4RecvKeyViaUDPAddr(uaddr *net.UDPAddr) (r L4RecvKey) {
	copy(r[:16], uaddr.IP.To16())
	r[16] = 17
	binary.BigEndian.PutUint16(r[17:], uint16(uaddr.Port))
	return r
}

type SharedEconn interface {
	Register(k L4RecvKey) (torecvch chan *RelayReceival)
	WriteIPPktTo(p []byte, dstmac net.HardwareAddr) (int, error)
	SetWriteDeadline(t time.Time) error
}

// SharingRUDPConn is the UDP connection could share same SharedEtherConn;
type SharingRUDPConn struct {
	udpconn          *RUDPConn
	conn             SharedEconn
	readDeadline     time.Time
	readDeadlineLock *sync.RWMutex
	recvChan         chan *RelayReceival
}

// SharingRUDPConnOptions is is the option to customize new SharingRUDPConn
type SharingRUDPConnOptions func(srudpc *SharingRUDPConn)

// NewSharingRUDPConn creates a new SharingRUDPConn,
// src is the string represents its UDP Address as format supported by net.ResolveUDPAddr().
// c is the underlying SharedEtherConn,
// roptions is a list of RUDPConnOptions that use for customization,
// supported are: WithResolveNextHopMacFunc;
// note unlike RUDPConn, SharingRUDPConn doesn't support acceptting pkt is not destinated to own address
func NewSharingRUDPConn(src string, c SharedEconn, roptions []RUDPConnOption, options ...SharingRUDPConnOptions) (*SharingRUDPConn, error) {
	r := new(SharingRUDPConn)
	var err error
	if r.udpconn, err = NewRUDPConn(src, nil, roptions...); err != nil {
		return nil, err
	}
	r.conn = c
	r.readDeadlineLock = new(sync.RWMutex)
	r.recvChan = c.Register(NewL4RecvKeyViaUDPAddr(r.udpconn.localAddress))
	for _, opt := range options {
		opt(r)
	}
	return r, nil
}

// ReadFrom implment net.PacketConn interface, it returns UDP payload;
func (sruc *SharingRUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	sruc.readDeadlineLock.RLock()
	deadline := sruc.readDeadline
	sruc.readDeadlineLock.RUnlock()
	d := time.Until(deadline)
	timeout := false
	var receival *RelayReceival
	if d > 0 {
		select {
		case <-time.After(d):
			timeout = true
		case receival = <-sruc.recvChan:
		}
	} else {
		receival = <-sruc.recvChan
	}
	if receival == nil {
		if timeout {
			return 0, nil, ErrTimeOut
		}
		return 0, nil, fmt.Errorf("failed to read from SharedEtherConn")
	}
	copy(p, receival.TransportPayloadBytes)
	return len(receival.TransportPayloadBytes), &net.UDPAddr{IP: receival.RemoteIP, Port: int(receival.RemotePort), Zone: "udp"}, nil
}

// WriteTo implements net.PacketConn interface, it sends UDP payload;
// This function adds UDP and IP header, and uses sruc's resolve function
// to get nexthop's MAC address, and use underlying SharedEtherConn to send IP packet,
// with SharedEtherConn's Ethernet encapsulation, to nexthop MAC address;
// by default ResolveNexhopMACWithBrodcast is used for nexthop mac resolvement
func (sruc *SharingRUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	pktbuf, dstip := sruc.udpconn.buildPkt(p, sruc.udpconn.LocalAddr(), addr)
	nexthopMAC := sruc.udpconn.resolveNexthopFunc(dstip)
	_, err := sruc.conn.WriteIPPktTo(pktbuf, nexthopMAC)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.PacketConn interface, it closes underlying EtherConn
func (sruc *SharingRUDPConn) Close() error {
	return nil
}

// LocalAddr implements net.PacketConn interface, it returns its UDPAddr
func (sruc *SharingRUDPConn) LocalAddr() net.Addr {
	return sruc.udpconn.LocalAddr()
}

// SetReadDeadline implements net.PacketConn interface
func (sruc *SharingRUDPConn) SetReadDeadline(t time.Time) error {
	sruc.readDeadlineLock.Lock()
	defer sruc.readDeadlineLock.Unlock()
	sruc.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.PacketConn interface
func (sruc *SharingRUDPConn) SetWriteDeadline(t time.Time) error {
	return sruc.conn.SetWriteDeadline(t)
}

// SetDeadline implements net.PacketConn interface
func (sruc *SharingRUDPConn) SetDeadline(t time.Time) error {
	sruc.SetReadDeadline(t)
	sruc.SetWriteDeadline(t)
	return nil
}

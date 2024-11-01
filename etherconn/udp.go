package etherconn

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

var BroadCastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// NextHopResolver resolves the target MAC address for the destination
// given its IP.
type NextHopResolver func(net.IP) net.HardwareAddr

// resolveNextHopMACWithBroadcast is the default resolve function that always return broadcast mac
func resolveNextHopMACWithBroadcast(ip net.IP) net.HardwareAddr {
	return BroadCastMAC
}

const (
	_udpProtocol = 17
	_defaultTTL  = 255
)

// RUDPConn implement net.PacketConn interface;
// it's used to send/receive UDP payload, using an underlying EtherConn
// for packet forwarding.
type RUDPConn struct {
	localAddress           *net.UDPAddr
	conn                   *EtherConn
	ipHeader, pseudoHeader []byte
	acceptAnyUDP           bool
	resolveNextHopFunc     NextHopResolver
}

// RUDPConnOption is a function use to provide customized option when creating RUDPConn
type RUDPConnOption func(rudpc *RUDPConn)

// WithAcceptAny allows RUDPConn to accept any UDP packet, even if this isn't the destination address
func WithAcceptAny(accept bool) RUDPConnOption {
	return func(rudpc *RUDPConn) {
		rudpc.acceptAnyUDP = accept
	}
}

// WithResolveNextHopMacFunc specifies a function to resolve a destination
// IP address to next-hop MAC address.
// By default, resolveNextHopMACWithBroadcast is used.
func WithResolveNextHopMacFunc(f NextHopResolver) RUDPConnOption {
	return func(rudpc *RUDPConn) {
		rudpc.resolveNextHopFunc = f
	}
}

// NewRUDPConn creates a new RUDPConn, with specified EtherConn, and, optionally RUDPConnOption(s).
// src is the source UDP Address, it could be any IP address, even address not provisioned in OS, like 0.0.0.0.
func NewRUDPConn(src *net.UDPAddr, c *EtherConn, options ...RUDPConnOption) (*RUDPConn, error) {
	r := &RUDPConn{
		localAddress:       src,
		conn:               c,
		resolveNextHopFunc: resolveNextHopMACWithBroadcast,
	}

	for _, opt := range options {
		opt(r)
	}

	if r.localAddress.IP.To4() == nil {
		// IPv6
		r.ipHeader = make([]byte, 40)
		r.ipHeader[0] = 0x60                                  // Version
		r.ipHeader[6] = _udpProtocol                          // Next header
		r.ipHeader[7] = _defaultTTL                           // TTL
		copy(r.ipHeader[8:24], r.localAddress.IP.To16()[:16]) // src addr
	} else {
		// IPv4
		r.ipHeader = make([]byte, 20)
		r.ipHeader[0] = 0x45                                 // Version + IHL (20 bytes)
		r.ipHeader[8] = _defaultTTL                          // TTL
		r.ipHeader[9] = _udpProtocol                         // Protocol
		copy(r.ipHeader[12:16], r.localAddress.IP.To4()[:4]) // src addr
	}

	return r, nil
}

// LocalAddr implements net.PacketConn interface, it returns its UDPAddr
func (ruc *RUDPConn) LocalAddr() net.Addr {
	return ruc.localAddress
}

// ReadFrom implements net.PacketConn interface, and copies UDP payload to p.
// Note: the underlying EtherConn will send all received packets as
// *EthernetResponse to RUDPConn, RUDPConn will ignore packets that aren't
// destined to its UDPAddr, unless WithAcceptAny(true) is specified
// when creating the RUDPConn.
// In that case, RUDPConn will accept any UDP packet.
func (ruc *RUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		receival, err := ruc.conn.getReceivedData()
		if err != nil {
			return 0, nil, err
		}
		if receival.Protocol == _udpProtocol {
			if ruc.acceptAnyUDP || (!ruc.acceptAnyUDP && (ruc.localAddress.IP.Equal(receival.LocalIP) && ruc.localAddress.Port == int(receival.LocalPort))) {
				copy(p, receival.TransportPayloadBytes)
				return len(receival.TransportPayloadBytes), &net.UDPAddr{IP: receival.RemoteIP, Port: int(receival.RemotePort), Zone: "udp"}, nil
			}
		}
	}
}

// WriteTo sends UDP payload to the specified target.
// This function adds UDP and IP headers, and uses RUDPConn's resolve function
// to obtain next hop's MAC address, and use underlying EtherConn to send IP packet,
// with EtherConn's Ethernet encapsulation.
func (ruc *RUDPConn) WriteTo(p []byte, dstAddr net.Addr) (int, error) {
	dst, ok := dstAddr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid destination address")
	}

	buf, destinationIP := ruc.buildPacket(p, ruc.localAddress, dst)
	nextHopMAC := ruc.resolveNextHopFunc(destinationIP)
	if _, err := ruc.conn.WriteIPData(buf, nextHopMAC); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (ruc *RUDPConn) SetReadDeadline(t time.Time) error {
	return ruc.conn.SetReadDeadline(t)
}

func (ruc *RUDPConn) SetWriteDeadline(t time.Time) error {
	return ruc.conn.SetWriteDeadline(t)
}

func (ruc *RUDPConn) SetDeadline(t time.Time) error {
	return ruc.conn.SetDeadline(t)
}

// Close closes underlying EtherConn
func (ruc *RUDPConn) Close() error {
	return ruc.conn.Close()
}

func (ruc *RUDPConn) buildPacket(p []byte, src, dst *net.UDPAddr) ([]byte, net.IP) {
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[:2], uint16(src.Port))               // src port
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dst.Port))              // dst port
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(udpHeader)+len(p))) // udp len

	if src.IP.To4() == nil {
		// IPv6
		ipv6header := make([]byte, 40)
		copy(ipv6header, ruc.ipHeader)
		binary.BigEndian.PutUint16(ipv6header[4:6], uint16(len(udpHeader)+len(p))) // payload length
		copy(ipv6header[24:40], dst.IP.To16()[:16])                                // dst addr

		udpAndPayload := append(udpHeader, p...)
		binary.BigEndian.PutUint16(udpAndPayload[6:], v6udpChecksum(udpAndPayload, src, dst)) // udp checksum

		return append(ipv6header, udpAndPayload...), dst.IP
	}

	// IPv4
	ipv4header := make([]byte, 20)
	copy(ipv4header, ruc.ipHeader)
	binary.BigEndian.PutUint16(ipv4header[2:4], uint16(len(ipv4header)+len(udpHeader)+len(p))) // length
	copy(ipv4header[16:], dst.IP.To4()[:4])                                                    // dst addr
	binary.BigEndian.PutUint16(ipv4header[10:12], ipv4Checksum(ipv4header))                    // ipv4 header checksum
	// UDP checksum is optional in IPv4, and we don't calculate it

	return append(ipv4header, append(udpHeader, p...)...), dst.IP
}

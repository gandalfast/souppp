package ethernetconn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// L2Endpoint represents a layer 2 MAC address that send/receives
// Ethernet frames
type L2Endpoint struct {
	HwAddr       net.HardwareAddr
	EthernetType uint16 // inner most EtherType (e.g payload type)
}

// L2EndpointKey is key identify a L2 EndPoint
// 1. First 6 bytes are MAC address
// 2. Last 2 bytes are innermost EtherType
type L2EndpointKey [8]byte

func (l2epkey L2EndpointKey) String() string {
	r := fmt.Sprintf("%v", net.HardwareAddr(l2epkey[:6]))
	r += fmt.Sprintf("#0x%x", l2epkey[6:])
	return r
}

func (l2e *L2Endpoint) GetKey() (key L2EndpointKey) {
	copy(key[:6], l2e.HwAddr[:6])
	binary.BigEndian.PutUint16(key[6:], l2e.EthernetType)
	return
}

func (l2e *L2Endpoint) Network() string {
	return "l2ep"
}

// String implements net.Addr interface, return a string with format:
// l2ep&<l2EndpointKey_str>, see L2EndpointKey.String for format of <l2EndpointKey_str>
func (l2e *L2Endpoint) String() (s string) {
	return fmt.Sprintf("%v&%v", l2e.Network(), l2e.GetKey().String())
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

// NewL4HashKeyWithEthernet returns a L4HashKey from a Ethernet response
func NewL4HashKeyWithEthernet(eth *EthernetResponse) (r L4HashKey) {
	copy(r[:16], eth.LocalIP.To16())
	r[16] = eth.Protocol
	binary.BigEndian.PutUint16(r[17:], eth.LocalPort)
	return r
}

// EthernetResponse is what PacketRelay received and parsed
type EthernetResponse struct {
	//LocalEndpoint/RemoteEndpoint is the local/remote L2Endpoint
	LocalEndpoint, RemoteEndpoint *L2Endpoint
	// EtherBytes is the Ethernet frame bytes
	EtherBytes []byte
	// EtherPayloadBytes is the Ethernet payload bytes within the EtherBytes,
	// where payload belongs to the specified EtherTypes,
	// default are 0x0800 (IPv4) and 0x86dd (IPv6),
	// nil if there is no payload with specified EtherTypes;
	EtherPayloadBytes []byte
	// TransportPayloadBytes is the transport layer(UDP/TCP/SCTP) payload bytes within the IPBytes,nil for unsupport transport layer
	TransportPayloadBytes []byte
	// RemoteIP is the remote IP address
	RemoteIP net.IP
	// RemotePort is the remote transport layer port, 0 for unsupport transport layer
	RemotePort uint16
	// Protocol is the IP protocol number
	Protocol uint8
	// LocalIP is the local IP address
	LocalIP net.IP
	// LocalPort is the local transport layer port, 0 for unsupport transport layer
	LocalPort uint16
}

// PacketRelay represents the Ethernet packet forwarder implementation.
type PacketRelay interface {
	// Register registers a list of L2EndpointKey of a EtherConn, PacketRely send/receive packet on its behalf,
	// it returns following channels:
	// receive is the channel used to receive;
	// send is the channel used to send;
	// stop is a channel that will be closed when PacketRelay stops sending;
	// if multicastSupport is true, then multicast ethernet traffic will be received as well;
	// if one of key is already registered, then existing key will be overridden;
	Register(ks []L2EndpointKey, multicast bool) (receiveChan, sendChan chan []byte, stop chan struct{}, registrationID int)
	// Unregister removes L2EndpointKey from registration
	Unregister(registrationID int)
	// Close stops the forwarding of Ethernet packets
	Close() error
}

// parseReceivedData parses a received Ethernet frame. It fails on a frame
// cut short at any layer; a UDP packet cut inside its UDP header has no
// transport payload.
func parseReceivedData(p []byte) (*EthernetResponse, error) {
	if len(p) < 14 {
		return nil, fmt.Errorf("ethernet frame of %d bytes is shorter than its header", len(p))
	}
	rcv := &EthernetResponse{
		EtherBytes: p,
		LocalEndpoint: &L2Endpoint{
			HwAddr: make([]byte, 6),
		},
		RemoteEndpoint: &L2Endpoint{
			HwAddr: make([]byte, 6),
		},
	}

	copy(rcv.LocalEndpoint.HwAddr, p[:6])    // dst mac
	copy(rcv.RemoteEndpoint.HwAddr, p[6:12]) // src mac

	index, ethernetType := ethernetTypeOffset(p)
	if index < 0 {
		return nil, errors.New("ethernet frame cut inside its VLAN tags")
	}
	rcv.LocalEndpoint.EthernetType = ethernetType
	rcv.RemoteEndpoint.EthernetType = ethernetType
	// Save only payload (without header)
	rcv.EtherPayloadBytes = p[index+2:]

	var l4index int
	switch ethernetType {
	case _ethernetTypeIPv4: //ipv4
		if len(rcv.EtherPayloadBytes) < 20 {
			return nil, fmt.Errorf("IPv4 packet of %d bytes is shorter than its header", len(rcv.EtherPayloadBytes))
		}
		rcv.RemoteIP = rcv.EtherPayloadBytes[12:16]
		rcv.LocalIP = rcv.EtherPayloadBytes[16:20]
		rcv.Protocol = rcv.EtherPayloadBytes[9]
		l4index = 20 // NOTE: this means no supporting of any ipv4 options
	case _ethernetTypeIPv6: //ipv6
		if len(rcv.EtherPayloadBytes) < 40 {
			return nil, fmt.Errorf("IPv6 packet of %d bytes is shorter than its header", len(rcv.EtherPayloadBytes))
		}
		rcv.Protocol = rcv.EtherPayloadBytes[6]
		rcv.RemoteIP = rcv.EtherPayloadBytes[8:24]
		rcv.LocalIP = rcv.EtherPayloadBytes[24:40]
		l4index = 40 // NOTE: this means no supporting of any ipv6 options
	}

	switch rcv.Protocol {
	case 17: // UDP
		if len(rcv.EtherPayloadBytes) >= l4index+8 {
			rcv.RemotePort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index : l4index+2])
			rcv.LocalPort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index+2 : l4index+4])
			rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+8:]
		}
	}

	return rcv, nil
}

// ethernetTypeOffset returns the offset of a frame's innermost EtherType,
// past any VLAN tags, and the type; the offset is -1 when the frame ends
// inside its tags.
func ethernetTypeOffset(framesData []byte) (int, uint16) {
	for index := 12; index+2 <= len(framesData); index += 4 {
		ethernetType := binary.BigEndian.Uint16(framesData[index : index+2])
		// 0x88A8: Service VLAN tag
		// 8x8100: 802.11q (VLAN)
		if ethernetType != 0x8100 && ethernetType != 0x88a8 {
			return index, ethernetType
		}
	}
	return -1, 0
}

// ParseEthernetType returns a frame's innermost EtherType, past any VLAN
// tags, or 0 when the frame ends before it.
func ParseEthernetType(framesData []byte) uint16 {
	_, ethernetType := ethernetTypeOffset(framesData)
	return ethernetType
}

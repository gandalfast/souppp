package ethernetconn

import (
	"encoding/binary"
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

// parseReceivedData parse received ethernet pkt, p is a ethernet packet in byte slice,
func parseReceivedData(p []byte) *EthernetResponse {
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

	index := 12
	for {
		ethernetType := binary.BigEndian.Uint16(p[index : index+2])
		// 0x88A8: Service VLAN tag
		// 8x8100: 802.11q (VLAN)
		if ethernetType != 0x8100 && ethernetType != 0x88a8 {
			rcv.LocalEndpoint.EthernetType = ethernetType
			break
		}
		index += 4
	}
	rcv.RemoteEndpoint.EthernetType = rcv.LocalEndpoint.EthernetType
	// Save only payload (without header)
	rcv.EtherPayloadBytes = p[index+2:]

	var l4index int
	switch rcv.LocalEndpoint.EthernetType {
	case _ethernetTypeIPv4: //ipv4
		rcv.RemoteIP = rcv.EtherPayloadBytes[12:16]
		rcv.LocalIP = rcv.EtherPayloadBytes[16:20]
		rcv.Protocol = rcv.EtherPayloadBytes[9]
		l4index = 20 // NOTE: this means no supporting of any ipv4 options
	case _ethernetTypeIPv6: //ipv6
		rcv.Protocol = rcv.EtherPayloadBytes[6]
		rcv.RemoteIP = rcv.EtherPayloadBytes[8:24]
		rcv.LocalIP = rcv.EtherPayloadBytes[24:40]
		l4index = 40 // NOTE: this means no supporting of any ipv6 options
	}

	switch rcv.Protocol {
	case 17: // UDP
		rcv.RemotePort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index : l4index+2])
		rcv.LocalPort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index+2 : l4index+4])
		rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+8:]
	}

	return rcv
}

func ParseEthernetType(framesData []byte) uint16 {
	index := 12
	for {
		ethernetType := binary.BigEndian.Uint16(framesData[index : index+2])
		// 0x88A8: Service VLAN tag
		// 8x8100: 802.11q (VLAN)
		if ethernetType != 0x8100 && ethernetType != 0x88a8 {
			return ethernetType
		}
		index += 4
	}
}

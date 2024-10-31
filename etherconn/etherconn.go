package etherconn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	// ErrTimeOut is the error returned when opeartion timeout
	ErrTimeOut = errors.New("timeout")
	// ErrRelayStopped is the error returned when relay already stopped
	ErrRelayStopped = errors.New("relay stopped")
)

// EtherConn sends/receives Ethernet payload like IP packet with
// Ethernet encapsulation, without provisioning them in OS.
// it needs to be registered with a PacketRelay instance to work.
type EtherConn struct {
	sourceAddress       net.HardwareAddr
	multicastSupport    bool
	rxL2Endpoints       []*L2Endpoint
	relay               PacketRelay
	relayRegistrationID int
	sendChan            chan []byte
	recvChan            chan *EthernetResponse
	closedChan          chan struct{}

	// Deadlines
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineMtx   sync.RWMutex
}

// EthernetOption is a function use to provide customized option when creating EtherConn
type EthernetOption func(ec *EtherConn)

// WithReceiveMulticast allow/disallow EtherConn to receive multicast/broadcast Ethernet traffic
func WithReceiveMulticast(multicast bool) EthernetOption {
	return func(ec *EtherConn) {
		ec.multicastSupport = multicast
	}
}

const (
	_ethernetTypeARP  uint16 = 0x0806
	_ethernetTypeIPv4 uint16 = 0x0800
	_ethernetTypeIPv6 uint16 = 0x86DD
)

// NewEtherConn creates a new EtherConn instance, mac is used as part of EtherConn's L2Endpoint;
// Relay is the PacketRelay forwarder where the Ethernet packets are sent and received .
// Ethernet types are the supported types for RX, if empty, default list contains ARP, IPv4 and IPv6.
func NewEtherConn(mac net.HardwareAddr, relay PacketRelay, ethernetTypes []uint16, options ...EthernetOption) *EtherConn {
	if len(ethernetTypes) == 0 {
		ethernetTypes = []uint16{_ethernetTypeARP, _ethernetTypeIPv4, _ethernetTypeIPv6}
	}

	r := &EtherConn{
		sourceAddress: mac,
		relay:         relay,
	}

	for _, option := range options {
		option(r)
	}

	for _, et := range ethernetTypes {
		r.rxL2Endpoints = append(r.rxL2Endpoints, &L2Endpoint{
			HwAddr:       r.sourceAddress,
			EthernetType: et,
		})
	}

	l2keys := make([]L2EndpointKey, len(r.rxL2Endpoints))
	for i, endpoint := range r.rxL2Endpoints {
		l2keys[i] = endpoint.GetKey()
	}
	r.recvChan, r.sendChan, r.closedChan, r.relayRegistrationID = relay.Register(l2keys, r.multicastSupport)
	return r
}

func (ec *EtherConn) LocalAddr() net.Addr {
	return ec.rxL2Endpoints[0]
}

func (ec *EtherConn) SetReadDeadline(t time.Time) error {
	ec.deadlineMtx.Lock()
	ec.readDeadline = t
	ec.deadlineMtx.Unlock()
	return nil
}

func (ec *EtherConn) SetWriteDeadline(t time.Time) error {
	ec.deadlineMtx.Lock()
	ec.writeDeadline = t
	ec.deadlineMtx.Unlock()
	return nil
}

func (ec *EtherConn) SetDeadline(t time.Time) error {
	var errList []error
	errList = append(errList, ec.SetReadDeadline(t))
	errList = append(errList, ec.SetWriteDeadline(t))
	return errors.Join(errList...)
}

// WriteIPData sends an IPv4/IPv6 packet to destMac.
func (ec *EtherConn) WriteIPData(p []byte, destMac net.HardwareAddr) (int, error) {
	var payloadType uint16
	switch p[0] >> 4 {
	case 4:
		payloadType = _ethernetTypeIPv4
	case 6:
		payloadType = _ethernetTypeIPv6
	default:
		return 0, fmt.Errorf("failed to write to EtherConn, invalid IP version, %d", p[0]>>4)
	}
	return ec.WritePacketTo(p, payloadType, destMac)
}

// WritePacketTo sends an Ethernet payload, along with specified
// EtherType, to destMac.
func (ec *EtherConn) WritePacketTo(p []byte, ethernetType uint16, destMac net.HardwareAddr) (int, error) {
	header := buildEthernetHeader(ec.sourceAddress, destMac, ethernetType)
	ethernetData := append(header, p...)

	ec.deadlineMtx.RLock()
	deadline := ec.writeDeadline
	ec.deadlineMtx.RUnlock()

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	select {
	case <-ec.closedChan:
		return 0, ErrRelayStopped
	case <-ctx.Done():
		return 0, ErrTimeOut
	case ec.sendChan <- ethernetData:
		// Data correctly sent
	}
	return len(p), nil
}

// ReadPacketFrom copies the received Ethernet payload to p,
// this is a wrapper of ReadPacket.
func (ec *EtherConn) ReadPacketFrom(p []byte) (int, *L2Endpoint, error) {
	buf, rep, err := ec.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, buf)
	return n, rep, nil
}

// ReadPacket returns received Ethernet payload bytes,
// along with the remote L2Endpoint.
// ReadPacket only returns payload that matches one of underlying
// PacketRelay's configured EtherTypes.
func (ec *EtherConn) ReadPacket() ([]byte, *L2Endpoint, error) {
	received, err := ec.getReceivedData()
	if err != nil {
		return nil, nil, err
	}
	return received.EtherPayloadBytes, received.RemoteEndpoint, nil
}

func (ec *EtherConn) Close() error {
	ec.relay.Unregister(ec.relayRegistrationID)
	return nil
}

func (ec *EtherConn) getReceivedData() (*EthernetResponse, error) {
	ec.deadlineMtx.RLock()
	deadline := ec.readDeadline
	ec.deadlineMtx.RUnlock()

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	var received *EthernetResponse
	select {
	case <-ctx.Done():
		return nil, ErrTimeOut
	case received = <-ec.recvChan:
		if received == nil {
			return nil, errors.New("failed to read from relay")
		}
	}
	return received, nil
}

func buildEthernetHeader(srcMac, destMac net.HardwareAddr, ethernetType uint16) []byte {
	header := make([]byte, 14)
	copy(header[:6], destMac)
	copy(header[6:12], srcMac)
	binary.BigEndian.PutUint16(header[12:14], ethernetType)
	return header
}

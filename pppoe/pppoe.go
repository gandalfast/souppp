// Package pppoe implements pppoe as defined in RFC2516
package pppoe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/gandalfast/souppp/etherconn"
	"github.com/rs/zerolog"
	"net"
	"sync/atomic"
	"time"
)

// PPPoE represents the PPPoE protocol
type PPPoE struct {
	logger *zerolog.Logger
	conn   *etherconn.EtherConn
	state  uint32

	// Configurable parameters
	serviceName string
	tags        []Tag

	// Session data
	sessionID uint16
	acMAC     net.HardwareAddr
}

const (
	_defaultTimeoutPPPoE = 3 * time.Second
	_defaultRetryPPPoE   = 3
)

// Modifier is a function to provide custom configuration when creating new PPPoE instances
type Modifier func(pppoe *PPPoE)

// WithTags adds all tags in t in PPPoE request pkt
func WithTags(t []Tag) Modifier {
	return func(pppoe *PPPoE) {
		if len(t) == 0 {
			return
		}
		pppoe.tags = append(pppoe.tags, t...)
	}
}

func WithServiceName(serviceName string) Modifier {
	return func(pppoe *PPPoE) {
		pppoe.serviceName = serviceName
	}
}

// NewPPPoE return a new PPPoE struct; use conn as underlying transport, logger for logging;
// optionally Modifer could provide custom configurations;
func NewPPPoE(conn *etherconn.EtherConn, logger *zerolog.Logger, options ...Modifier) *PPPoE {
	r := new(PPPoE)
	for _, option := range options {
		option(r)
	}
	r.tags = append(r.tags, &TagString{
		TagByteSlice: &TagByteSlice{
			TagType: TagTypeServiceName,
			Value:   []byte(r.serviceName),
		},
	})
	r.state = pppoeStateInitial
	r.conn = conn
	r.logger = logger
	return r
}

// SetReadDeadline implements net.PacketConn interface
func (pppoe *PPPoE) SetReadDeadline(t time.Time) error {
	return pppoe.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn interface
func (pppoe *PPPoE) SetWriteDeadline(t time.Time) error {
	return pppoe.conn.SetWriteDeadline(t)
}

// SetDeadline implements net.PacketConn interface
func (pppoe *PPPoE) SetDeadline(t time.Time) error {
	var errList []error
	errList = append(errList, pppoe.SetReadDeadline(t))
	errList = append(errList, pppoe.SetWriteDeadline(t))
	return errors.Join(errList...)
}

// LocalAddr return local Endpoint, see doc of Endpoint
func (pppoe *PPPoE) LocalAddr() net.Addr {
	return &Endpoint{
		L2EP:      pppoe.conn.LocalAddr().(*etherconn.L2Endpoint).HwAddr,
		SessionID: pppoe.sessionID,
	}
}

// Dial complets a full PPPoE discovery exchange (PADI/PADO/PADR/PADS)
func (pppoe *PPPoE) Dial(ctx context.Context) (err error) {
	if atomic.LoadUint32(&pppoe.state) != pppoeStateInitial {
		return errors.New("pppoe is not in initial state")
	}

	atomic.StoreUint32(&pppoe.state, pppoeStateDialing)
	defer func() {
		// Set state to closed when there is a dialing error
		if atomic.LoadUint32(&pppoe.state) != pppoeStateOpen || err != nil {
			atomic.StoreUint32(&pppoe.state, pppoeStateClosed)
		}
	}()

	// Send PADI and receive PADO packet
	var pado Packet
	pado, pppoe.acMAC, err = pppoe.exchangePacket(
		ctx,
		pppoe.buildPADI(),
		CodePADO,
		etherconn.BroadCastMAC,
	)
	if err != nil {
		return err
	}
	pppoe.logger.Info().Any("pkt", pado).Msg("Got PADO")

	// Send PADR and receive PADS packet
	var pads Packet
	pads, _, err = pppoe.exchangePacket(
		ctx,
		pppoe.buildPADRWithPADO(pado),
		CodePADS,
		pppoe.acMAC,
	)
	if err != nil {
		return err
	}
	pppoe.logger.Info().Any("pkt", pads).Msg("Got PADS")

	if pads.SessionID == 0 {
		return fmt.Errorf("AC rejected,\n %v", pads)
	}
	pppoe.sessionID = pads.SessionID
	atomic.StoreUint32(&pppoe.state, pppoeStateOpen)

	logger := pppoe.logger.With().Uint16("SessionID", pppoe.sessionID).Logger()
	pppoe.logger = &logger
	return nil
}

// WriteTo implements net.PacketConn interface.
// addr is ignored, pkt is always sent to AC's MAC.
func (pppoe *PPPoE) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	pkt := &Packet{
		Code:      CodeSession,
		SessionID: pppoe.sessionID,
		Payload:   p,
	}
	pktbytes, err := pkt.Serialize()
	if err != nil {
		return 0, fmt.Errorf("failed to serialize pppoe packet: %w", err)
	}
	_, err = pppoe.conn.WritePacketTo(pktbytes, EtherTypePPPoESession, pppoe.acMAC)
	if err != nil {
		return 0, fmt.Errorf("failed to send pppoe packet: %w", err)
	}
	return len(p), nil
}

// ReadFrom only works after PPPoE session is open.
func (pppoe *PPPoE) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		n, l2ep, err := pppoe.conn.ReadPacketFrom(buf)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to recv, %w", err)
		}

		// 1. Check that the packet reaches the minimum PPPoE header length
		// 2. MAC Address must match the one for the current session
		// 3. The PPPoE packet must have the session type code
		// 4. Session ID must match the current one
		if n < 6 || l2ep.HwAddr.String() != pppoe.acMAC.String() ||
			Code(buf[1]) != CodeSession ||
			binary.BigEndian.Uint16(buf[2:4]) != pppoe.sessionID {
			continue
		}

		// Remove PPPoE header
		copy(buf, buf[6:])
		n -= 6

		// Save information about the source
		remoteEndpoint := &Endpoint{
			L2EP:      l2ep.HwAddr,
			SessionID: pppoe.sessionID,
		}

		return n, remoteEndpoint, nil
	}
}

// Close implements net.PacketConn interface
func (pppoe *PPPoE) Close() error {
	if atomic.LoadUint32(&pppoe.state) == pppoeStateOpen {
		pkt := pppoe.buildPADT()
		pktbytes, err := pkt.Serialize()
		if err != nil {
			return err
		}
		_, err = pppoe.conn.WritePacketTo(pktbytes, EtherTypePPPoEDiscovery, pppoe.acMAC)
		pppoe.logger.Info().Err(err).Any("pkt", pkt).Msg("Closing PPPoE connection")
		atomic.StoreUint32(&pppoe.state, pppoeStateClosed)
	}
	return nil
}

func (pppoe *PPPoE) buildPADI() Packet {
	return Packet{
		Code: CodePADI,
		Tags: pppoe.tags,
	}
}

func (pppoe *PPPoE) buildPADRWithPADO(pado Packet) Packet {
	padr := Packet{
		Code: CodePADR,
		Tags: pppoe.tags,
	}
	padr.Tags = append(padr.Tags, pado.GetTag(TagTypeACCookie)...)
	padr.Tags = append(padr.Tags, pado.GetTag(TagTypeRelaySessionID)...)
	return padr
}

func (pppoe *PPPoE) buildPADT() *Packet {
	return &Packet{
		Code:      CodePADT,
		SessionID: pppoe.sessionID,
	}
}

// exchangePacket returns the first received PPPoE response with the specified code, along with the remote MAC address
func (pppoe *PPPoE) exchangePacket(ctx context.Context, req Packet, code Code, dst net.HardwareAddr) (resp Packet, hwAddr net.HardwareAddr, err error) {
	pktbytes, err := req.Serialize()
	if err != nil {
		return resp, nil, err
	}

	for i := 0; i < _defaultRetryPPPoE; i++ {
		if _, err = pppoe.conn.WritePacketTo(pktbytes, EtherTypePPPoEDiscovery, dst); err != nil {
			return resp, nil, err
		}

		pppoe.logger.Info().Msgf("sending %v", req.Code)
		pppoe.logger.Debug().Msgf("%v:\n%v", req.Code, req)

		timeout := time.Now().Add(_defaultTimeoutPPPoE)
		deadline, ok := ctx.Deadline()
		if ok && deadline.Before(timeout) {
			timeout = deadline
		}
		_ = pppoe.conn.SetReadDeadline(timeout)

		receivedPacketBuf, l2ep, err := pppoe.conn.ReadPacket()
		if err != nil && errors.Is(err, etherconn.ErrTimeOut) {
			continue
		} else if err != nil {
			return resp, nil, fmt.Errorf("failed to receive response, %w", err)
		}

		if err := resp.Parse(receivedPacketBuf); err != nil {
			continue
		}

		if resp.Code == code {
			return resp, l2ep.HwAddr, nil
		}
	}

	return resp, nil, fmt.Errorf("failed to receive expect response %v", code)
}

// Endpoint represents a PPPoE endpont
type Endpoint struct {
	// L2 Endpoint
	L2EP net.HardwareAddr
	// SessionId is the PPPoE session ID
	SessionID uint16
}

// Network implenets net.Addr interface, always return "pppoe"
func (pep Endpoint) Network() string {
	return "pppoe"
}

// String implenets net.Addr interface, return "pppoe:<L2EP>:<SessionID>"
func (pep Endpoint) String() string {
	return fmt.Sprintf("pppoe:%v:%x", pep.L2EP.String(), pep.SessionID)
}

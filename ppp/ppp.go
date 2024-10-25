package ppp

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/gandalfast/zouppp/etherconn"
	"github.com/rs/zerolog"
	"net"
	"sync"
	"time"
)

const _readTimeout = 3 * time.Second

const (
	_relayChanDepth = 16
	_sendChanDepth  = 32
)

const (
	// IPv4 header size: 20 bytes (min)
	// IPv6 header size: 40 bytes
	MinimumFrameSize = 20

	// MaxPPPMsgSize specifies max length of a received PPP packet
	MaxPPPMsgSize = 1500
)

// PPP represents the PPP protocol (built over PPPoE for usage over ethernet)
type PPP struct {
	Logger *zerolog.Logger

	// Data forwarding
	relayChanList     map[ProtocolNumber]chan []byte
	relayChanListLock sync.RWMutex
	sendChan          chan []byte

	// PPPoE connection
	conn net.PacketConn

	// Support for protocol reject
	generateReject func(b []byte) *Packet
}

// NewPPP creates a new PPP protocol instance, using conn as underlying transport, l as Logger;
func NewPPP(conn net.PacketConn, l *zerolog.Logger, generateReject func(b []byte) *Packet) *PPP {
	r := new(PPP)
	r.Logger = l
	r.relayChanList = make(map[ProtocolNumber]chan []byte)
	r.sendChan = make(chan []byte, _sendChanDepth)
	r.conn = conn
	r.generateReject = generateReject
	return r
}

func (ppp *PPP) Start(ctx context.Context) {
	go ppp.receive(ctx)
	go ppp.send(ctx)
}

// Register a new protocol over PPP.
// 1. send is used to send packets
// 2. receive is used to receive packets
func (ppp *PPP) Register(p ProtocolNumber) (chan []byte, chan []byte) {
	ch := make(chan []byte, _relayChanDepth)

	ppp.relayChanListLock.Lock()
	if old, ok := ppp.relayChanList[p]; ok {
		close(old)
	}
	ppp.relayChanList[p] = ch
	ppp.relayChanListLock.Unlock()

	return ppp.sendChan, ch
}

// Unregister removes a previously registered protocol if present.
func (ppp *PPP) Unregister(p ProtocolNumber) {
	ppp.relayChanListLock.Lock()
	ch, ok := ppp.relayChanList[p]
	if ok {
		close(ch)
		delete(ppp.relayChanList, p)
	}
	ppp.relayChanListLock.Unlock()
}

func (ppp *PPP) Close() error {
	err := ppp.conn.Close()
	ppp.relayChanListLock.Lock()
	for _, ch := range ppp.relayChanList {
		close(ch)
	}
	ppp.relayChanListLock.Unlock()
	return err
}

func (ppp *PPP) send(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			ppp.Logger.Info().Msg("PPP send routine stopped")
			return
		case b := <-ppp.sendChan:
			_, err := ppp.conn.WriteTo(b, nil)
			if err != nil && !errors.Is(err, etherconn.ErrTimeOut) {
				ppp.Logger.Warn().Err(err).Msg("failed to send packet")
				return
			} else if err != nil {
				continue
			}
		}
	}
}

func (ppp *PPP) receive(ctx context.Context) {
	for {
		buf := make([]byte, MaxPPPMsgSize)
		_ = ppp.conn.SetReadDeadline(time.Now().Add(_readTimeout))
		n, _, err := ppp.conn.ReadFrom(buf)

		if err != nil && !errors.Is(err, etherconn.ErrTimeOut) {
			// Close the routine if there is an unrecoverable error
			ppp.Logger.Error().Err(err).Msg("failed to receive packet")
			return
		} else if err != nil {
			// Skip this packet and go to the next if there is a timeout
			select {
			case <-ctx.Done():
				ppp.Logger.Info().Msg("PPP receive routine stopped")
				return
			default:
			}
			continue
		}

		// Forward received packet asynchronously
		go ppp.relay(buf[:n])
	}
}

func (ppp *PPP) relay(buf []byte) {
	if len(buf) <= 2 {
		return
	}

	// Reject unknown protocol types
	protocolNumber := ProtocolNumber(binary.BigEndian.Uint16(buf[:2]))
	if protocolNumber != ProtoCHAP && protocolNumber != ProtoIPCP &&
		protocolNumber != ProtoLCP && protocolNumber != ProtoPAP &&
		protocolNumber != ProtoIPv6CP && protocolNumber != ProtoIPv4 &&
		protocolNumber != ProtoIPv6 {
		pkt := ppp.generateReject(append(buf[:2], buf...))
		pktbytes, err := pkt.Serialize()
		if err == nil {
			ppp.sendChan <- pktbytes
		}
		ppp.Logger.Debug().Any("pkt", pkt).Msg("send protocol reject")
		return
	}

	ppp.relayChanListLock.RLock()
	if ch, ok := ppp.relayChanList[protocolNumber]; ok {
		ch <- buf[2:]
	}
	ppp.relayChanListLock.RUnlock()
}

// Package lcp implements LCP, IPCP and IPv6CP protocols
package lcp

import (
	"context"
	"errors"
	"github.com/gandalfast/zouppp/ppp"
	"github.com/rs/zerolog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// LayerNotifyHandler is the handler function to handle Layer event (tlu/tld/tls/tlf as defined in RFC1661)
type LayerNotifyHandler func(evt LayerNotifyEvent)

// OwnOptionRule is rule that used to handle own LCP options, user could provide implementation of this interface to get custom behavior
type OwnOptionRule interface {
	// HandlerConfRej is the handler function to handle received Conf-Reject
	HandlerConfRej(received []Option)
	// HandlerConfNAK is the handler function to handle received Conf-Nak
	HandlerConfNAK(received []Option)
	// GetOptions returns current own options
	GetOptions() []Option
	// GetOption returns current option with type o
	GetOption(o byte) Option
}

// DefaultOwnOptionRule is the default OwnOptionRule implementation
type DefaultOwnOptionRule struct {
	ownOptions []Option
	mux        sync.RWMutex
}

// NewDefaultOwnOptionRule returns a new DefaultOwnOptionRule
func NewDefaultOwnOptionRule() *DefaultOwnOptionRule {
	defaultMRUOp := OpMRU(ppp.MaxPPPMsgSize)
	magicNum := OpMagicNum(rand.Uint32())

	return &DefaultOwnOptionRule{
		ownOptions: []Option{
			&defaultMRUOp,
			&magicNum,
		},
	}
}

func (own *DefaultOwnOptionRule) GetOptions() []Option {
	own.mux.RLock()
	defer own.mux.RUnlock()
	return own.ownOptions
}

func (own *DefaultOwnOptionRule) GetOption(o uint8) Option {
	own.mux.RLock()
	defer own.mux.RUnlock()
	for _, op := range own.ownOptions {
		if op.Type() == o {
			return op
		}
	}
	return nil
}

// HandlerConfRej removes all options listed in conf-rej
func (own *DefaultOwnOptionRule) HandlerConfRej(received []Option) {
	toReject := make(map[uint8]struct{}, len(received))
	for _, opt := range received {
		toReject[opt.Type()] = struct{}{}
	}

	own.mux.Lock()
	defer own.mux.Unlock()

	options := make([]Option, 0, len(own.ownOptions))
	for _, opt := range own.ownOptions {
		if _, isReject := toReject[opt.Type()]; !isReject {
			options = append(options, opt)
		}
	}
	own.ownOptions = options
}

// HandlerConfNAK accepts all options listed in conf-nak
func (own *DefaultOwnOptionRule) HandlerConfNAK(received []Option) {
	toReplace := make(map[uint8]Option, len(received))
	for _, opt := range received {
		toReplace[opt.Type()] = opt
	}

	own.mux.Lock()
	defer own.mux.Unlock()

	for i, opt := range own.ownOptions {
		if newOpt, isReplace := toReplace[opt.Type()]; isReplace {
			own.ownOptions[i] = newOpt
		}
	}
}

// PeerOptionRule is rule that use for handle received config-req from peer
type PeerOptionRule interface {
	// HandlerConfReq is the handler function to handle received Conf-Request.
	// if a received option needs to be naked or rejected, include it in returned nak/reject LCPOptions
	HandlerConfReq(received []Option) (nak, reject []Option)
	// GetOptions return current peer's options
	GetOptions() []Option
}

// DefaultPeerOptionRule is the default PeerOptionRule implementation.
type DefaultPeerOptionRule struct {
	// AuthOp is the required Auth Protocol Option (PAP or CHAP)
	AuthOp         *OpAuthProto
	currentOptions []Option
}

// NewDefaultPeerOptionRule create a new DefaultPeerOptionRule instance with specified auth protocol
func NewDefaultPeerOptionRule(authProto ppp.ProtocolNumber) (*DefaultPeerOptionRule, error) {
	switch authProto {
	case ppp.ProtoCHAP:
		return &DefaultPeerOptionRule{
			AuthOp: NewCHAPAuthOp(),
		}, nil
	case ppp.ProtoPAP:
		return &DefaultPeerOptionRule{
			AuthOp: NewPAPAuthOp(),
		}, nil
	default:
		return nil, errors.New("unsupported auth protocol: " + authProto.String())
	}
}

func (rule *DefaultPeerOptionRule) GetOptions() []Option {
	return rule.currentOptions
}

// HandlerConfReq implements PeerOptionRule, if config-request include an auth-proto option that is different from required one, it will be NAKed;
// Option in conf-req other than auth-proto, magic number and MRU will be rejected.
func (rule *DefaultPeerOptionRule) HandlerConfReq(received []Option) (nak, reject []Option) {
	rule.currentOptions = received
	for _, o := range received {
		switch OptionType(o.Type()) {
		case OpTypeAuthenticationProtocol:
			if !o.Equal(rule.AuthOp) {
				nak = append(nak, rule.AuthOp)
			}
		case OpTypeMagicNumber, OpTypeMaximumReceiveUnit:
		default:
			reject = append(reject, o)
		}
	}
	return nak, reject
}

// LCP is the implementation for LCP/IPCP/IPv6CP
type LCP struct {
	logger      *zerolog.Logger
	protoType   ppp.ProtocolNumber
	proto       *ppp.PPP
	OwnRule     OwnOptionRule  // Handle own options
	PeerRule    PeerOptionRule // Handle peer's options
	layerNotify LayerNotifyHandler

	requestID      atomic.Uint32
	state          atomic.Uint32
	restartCount   atomic.Uint32
	restartTimer   *time.Timer
	keepAliveTimer *time.Timer
	sendChan       chan []byte
	receiveChan    chan []byte
	closed         chan struct{}
}

const (
	// _defaultRestartCounter is the default LCP restart counter value
	_defaultRestartCounter = 3
	// _defaultRestartTimerDuration is the default restart timer duration
	_defaultRestartTimerDuration = 10 * time.Second
	// _defaultKeepAliveInterval is the default LCP keepalive interval
	_defaultKeepAliveInterval = 20 * time.Second
)

// NewLCP creates a new LCP/IPCP/IPv6CP according to the specific proto, runs over specified pppProto, calls h whenever there is layer event.
// optionly, LCPModifier(s) could be specified to change default config
func NewLCP(proto ppp.ProtocolNumber, pppProto *ppp.PPP, h LayerNotifyHandler, peerRule PeerOptionRule, optionRule OwnOptionRule) *LCP {
	lcp := new(LCP)
	lcp.protoType = proto
	logger := pppProto.Logger.With().Str("LCPProto", lcp.protoType.String()).Logger()
	lcp.logger = &logger
	lcp.proto = pppProto
	lcp.OwnRule = optionRule
	lcp.PeerRule = peerRule
	lcp.layerNotify = h
	lcp.state.Store(uint32(StateInitial))
	lcp.restartCount.Store(_defaultRestartCounter)
	lcp.restartTimer = time.NewTimer(_defaultRestartTimerDuration)
	lcp.keepAliveTimer = time.NewTimer(_defaultKeepAliveInterval)
	lcp.sendChan, lcp.receiveChan = lcp.proto.Register(lcp.protoType)
	lcp.closed = make(chan struct{})
	return lcp
}

func (lcp *LCP) Start(ctx context.Context) {
	go lcp.receive()

	// Keep alive handler
	if lcp.protoType == ppp.ProtoLCP {
		go func() {
			ticker := time.NewTicker(_defaultKeepAliveInterval)
			defer ticker.Stop()

			select {
			case <-ticker.C:
				switch lcp.getState() {
				case StateOpened:
					if err := lcp.sendEchoRequest(); err != nil {
						lcp.logger.Error().Err(err).Msg("keepAliveTimeout")
					} else {
						lcp.setState(StateEchoReqSent, "keepAliveTimeout")
					}
				default:
				}
			case _, ok := <-lcp.closed:
				if !ok {
					return
				}
			}
		}()
	}

	// Timer handler
	go func() {
		select {
		case <-lcp.restartTimer.C:
			counter := lcp.restartCount.Add(^uint32(0))
			if counter == 0 {
				if lcp.getState() == StateEchoReqSent {
					lcp.logger.Error().Msg("keepalive timeout")
				}
				lcp.toMinus()
			} else {
				lcp.toPlus()
			}
		case _, ok := <-lcp.closed:
			if !ok {
				return
			}
		}
	}()
}

func (lcp *LCP) Close() error {
	lcp.proto.Unregister(lcp.protoType)
	close(lcp.closed)
	return nil
}

func (lcp *LCP) setState(s State, caller string) {
	old := lcp.state.Swap(uint32(s))
	lcp.logger.Debug().Msgf("%v state transit %v -> %v", caller, State(old), s)
}

func (lcp *LCP) getState() State {
	return State(lcp.state.Load())
}

func (lcp *LCP) resetTimer() {
	lcp.logger.Debug().Msg("reset timer")
	if !lcp.restartTimer.Stop() {
		<-lcp.restartTimer.C
	}
	lcp.restartTimer.Reset(_defaultRestartTimerDuration)
}

func (lcp *LCP) send(p []byte) error {
	packetBytes, err := ppp.NewPacket(ppp.NewStaticSerializer(p), lcp.protoType).Serialize()
	if err != nil {
		return err
	}
	lcp.sendChan <- packetBytes
	return nil
}

func (lcp *LCP) receive() {
	for {
		select {
		case pktbytes, ok := <-lcp.receiveChan:
			if !ok {
				lcp.logger.Info().Msg("receive channel closed")
				return
			}
			lcp.processReceivedBytes(pktbytes)
		case _, ok := <-lcp.closed:
			if !ok {
				lcp.logger.Info().Msg("receive channel closed")
				return
			}
		}
	}
}

func (lcp *LCP) processReceivedBytes(pktbytes []byte) {
	if len(pktbytes) < 4 {
		lcp.logger.Warn().Msg("received LCP packet is too small")
		return
	}

	pkt := NewPacket(lcp.protoType)
	if err := pkt.Parse(pktbytes); err != nil {
		lcp.logger.Warn().Err(err).Msg("invalid LCP packet")
		return
	}
	lcp.logger.Info().Str("pkt", pkt.String()).Msg("got a lcp pkt")

	switch pkt.Code {
	case CodeConfigureAck:
		if err := lcp.rca(*pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RCA event")
		}
	case CodeConfigureRequest:
		nak, reject := lcp.PeerRule.HandlerConfReq(pkt.Options)
		if len(nak) == 0 && len(reject) == 0 {
			if err := lcp.rcrPlus(*pkt); err != nil {
				lcp.logger.Error().Err(err).Msg("failed to process RCR+ event")
			}
		} else {
			if err := lcp.rcrMinus(*pkt, nak, reject); err != nil {
				lcp.logger.Error().Err(err).Msg("failed to process RCR- event")
			}
		}
	case CodeEchoReply, CodeEchoRequest, CodeDiscardRequest:
		if err := lcp.rxr(*pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RXR event")
		}
	case CodeTerminateRequest:
		if err := lcp.rtr(*pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RTR event")
		}
	case CodeTerminateAck:
		if err := lcp.rta(); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RTA event")
		}
	case CodeConfigureNak, CodeConfigureReject:
		if err := lcp.rcn(*pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RCN event")
		}
	case CodeCodeReject, CodeProtocolReject:
		if err := lcp.rxjMinus(*pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RXJ event")
		}
	default:
		if err := lcp.ruc(*pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to handle RUC event")
		}
	}
}

// Events (https://datatracker.ietf.org/doc/html/rfc1661)

// UpEvent is lower layer up event, as defined in RFC1661
func (lcp *LCP) UpEvent() error {
	state := lcp.getState()
	switch state {
	case StateInitial:
		lcp.setState(StateClosed, "UpEvent "+state.String())
	case StateStarting:
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.restartCount.Store(_defaultRestartCounter)
		lcp.resetTimer()
		lcp.setState(StateReqSent, "UpEvent "+state.String())
	default:
	}
	return nil
}

// DownEvent is lower layer down event, as defined in RFC1661
func (lcp *LCP) DownEvent() error {
	state := lcp.getState()
	switch state {
	case StateStopped:
		lcp.layerNotify(LayerNotifyStarted)
		lcp.setState(StateStarting, "DownEvent "+state.String())
	case StateReqSent, StateAckRcvd, StateAckSent:
		lcp.setState(StateStarting, "DownEvent "+state.String())
	case StateOpened, StateEchoReqSent:
		lcp.layerNotify(LayerNotifyDown)
		lcp.setState(StateStarting, "DownEvent "+state.String())
	default:
	}
	return nil
}

// OpenEvent is admin Open event, as defined in RFC1661
func (lcp *LCP) OpenEvent() error {
	state := lcp.getState()
	switch state {
	case StateInitial:
		lcp.layerNotify(LayerNotifyStarted)
		lcp.setState(StateStarting, "OpenEvent "+state.String())
	case StateClosed:
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.restartCount.Store(_defaultRestartCounter)
		lcp.setState(StateReqSent, "OpenEvent "+state.String())
	case StateClosing:
		lcp.setState(StateStopping, "OpenEvent "+state.String())
	default:
	}
	return nil
}

// CloseEvent is admin Close event, as defined in RFC1661
func (lcp *LCP) CloseEvent() error {
	state := lcp.getState()
	switch state {
	case StateStarting:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateInitial, "CloseEvent "+state.String())
	case StateStopped:
		lcp.setState(StateClosed, "CloseEvent "+state.String())
	case StateStopping:
		lcp.setState(StateClosing, "CloseEvent "+state.String())
	case StateReqSent, StateAckRcvd, StateAckSent, StateOpened, StateEchoReqSent:
		// send term req
		if err := lcp.sendTermReq(); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process TO+ event")
			return err
		}
		if state == StateOpened || state == StateEchoReqSent {
			lcp.layerNotify(LayerNotifyDown)
		}
		lcp.restartCount.Store(_defaultRestartCounter)
		lcp.setState(StateClosing, "CloseEvent "+state.String())
	default:
	}
	return nil
}

// toPlus is TO+ event (Timeout with counter > 0)
func (lcp *LCP) toPlus() {
	lcp.logger.Debug().Msg("timer expired, TO+ event")
	state := lcp.getState()
	switch state {
	case StateClosing, StateStopping:
		// send term req
		if err := lcp.sendTermReq(); err != nil {
			lcp.logger.Error().Str("State", state.String()).Err(err).Msg("failed to process TO+ event")
		}
	case StateReqSent, StateAckSent:
		// send conf req
		if err := lcp.sendConfReq(); err != nil {
			lcp.logger.Error().Str("State", state.String()).Err(err).Msg("failed to process TO+ event")
		}
	case StateAckRcvd:
		// send conf req, this is actually send current version of config options
		err := lcp.sendConfReq()
		if err != nil {
			lcp.logger.Error().Str("State", state.String()).Err(err).Msg("failed to process TO+ event")
		} else {
			lcp.setState(StateReqSent, "toPlus")
		}
	case StateEchoReqSent:
		// send echo request
		if err := lcp.sendEchoRequest(); err != nil {
			lcp.logger.Error().Str("State", state.String()).Err(err).Msg("failed to process TO+ event")
		}
	default:
	}
}

// toMinus is TO- event (Timeout with counter expired)
func (lcp *LCP) toMinus() {
	lcp.logger.Debug().Msg("timer expired, TO- event")
	state := lcp.getState()
	switch state {
	case StateClosing:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateClosed, "toMinus "+state.String())
	case StateStopping:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateStopped, "toMinus "+state.String())
	case StateReqSent, StateAckSent, StateAckRcvd, StateEchoReqSent:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateStopped, "toMinus "+state.String())
	default:
	}
}

// rcrPlus is RCR+ event (Receive-Configure-Request (Good))
func (lcp *LCP) rcrPlus(req Packet) error {
	state := lcp.getState()
	switch state {
	case StateClosed:
		// send term-ack
		if err := lcp.sendTermACK(req); err != nil {
			return err
		}
	case StateStopped:
		// send conf-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		// send conf-ack
		if err := lcp.sendConfACK(req); err != nil {
			return err
		}
		lcp.restartCount.Store(_defaultRestartCounter)
		lcp.setState(StateAckSent, "rcrPlus "+state.String())
	case StateReqSent:
		// send conf-ack
		if err := lcp.sendConfACK(req); err != nil {
			return err
		}
		lcp.setState(StateAckSent, "rcrPlus "+state.String())
	case StateAckRcvd:
		// send conf-ack
		if err := lcp.sendConfACK(req); err != nil {
			return err
		}
		lcp.layerNotify(LayerNotifyUp)
		lcp.setState(StateOpened, "rcrPlus "+state.String())
	case StateAckSent:
		// send conf-ack
		if err := lcp.sendConfACK(req); err != nil {
			return err
		}
	case StateOpened, StateEchoReqSent:
		lcp.layerNotify(LayerNotifyDown)
		// send conf-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		// send conf-ack
		if err := lcp.sendConfACK(req); err != nil {
			return err
		}
		lcp.setState(StateAckSent, "rcrPlus "+state.String())
	default:
	}
	return nil
}

// rcrMinus is RCR- event (Receive-Configure-Request (Bad))
func (lcp *LCP) rcrMinus(req Packet, nak, reject []Option) error {
	state := lcp.getState()
	switch state {
	case StateClosed:
		// send term-ack
		if err := lcp.sendTermACK(req); err != nil {
			return err
		}
	case StateStopped:
		// send conf-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		// send conf-nak
		if err := lcp.sendNAKRejct(req, nak, reject); err != nil {
			return err
		}
		lcp.restartCount.Store(_defaultRestartCounter)
		lcp.setState(StateReqSent, "rcrMinus "+state.String())
	case StateReqSent, StateAckRcvd:
		// send conf-nak
		if err := lcp.sendNAKRejct(req, nak, reject); err != nil {
			return err
		}
	case StateAckSent:
		// send conf-nak
		if err := lcp.sendNAKRejct(req, nak, reject); err != nil {
			return err
		}
		lcp.setState(StateReqSent, "rcrMinus "+state.String())
	case StateOpened, StateEchoReqSent:
		// send conf-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		// send conf-nak
		if err := lcp.sendNAKRejct(req, nak, reject); err != nil {
			return err
		}
		lcp.layerNotify(LayerNotifyDown)
		lcp.setState(StateReqSent, "rcrMinus "+state.String())
	default:
	}
	return nil
}

// RCA event (Receive-Configure-Ack)
func (lcp *LCP) rca(req Packet) error {
	state := lcp.getState()
	switch state {
	case StateStopped, StateClosed:
		// send term-ack
		if err := lcp.sendTermACK(req); err != nil {
			return err
		}
	case StateReqSent:
		lcp.restartCount.Store(_defaultRestartCounter)
		lcp.setState(StateAckRcvd, "rca "+state.String())
	case StateAckRcvd:
		// send conf req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.setState(StateReqSent, "rca "+state.String())
	case StateAckSent:
		lcp.restartCount.Store(_defaultRestartCounter)
		lcp.layerNotify(LayerNotifyUp)
		lcp.setState(StateOpened, "rca "+state.String())
	case StateOpened, StateEchoReqSent:
		lcp.layerNotify(LayerNotifyDown)
		// send conf req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.setState(StateReqSent, "rca "+state.String())
	default:
	}
	return nil
}

// RCN event (Receive-Configure-Nak/Rej)
func (lcp *LCP) rcn(req Packet) error {
	switch req.Code {
	case CodeConfigureNak:
		lcp.OwnRule.HandlerConfNAK(req.Options)
	case CodeConfigureReject:
		lcp.OwnRule.HandlerConfRej(req.Options)
	}
	state := lcp.getState()
	switch state {
	case StateStopped, StateClosed:
		// send term-ack
		return lcp.sendTermACK(req)
	case StateReqSent:
		// send cfg-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.restartCount.Store(_defaultRestartCounter)
	case StateAckRcvd:
		// send cfg-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.setState(StateReqSent, "rcn "+state.String())
	case StateAckSent:
		// send cfg-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.restartCount.Store(_defaultRestartCounter)
	case StateOpened, StateEchoReqSent:
		// send cfg-req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.layerNotify(LayerNotifyDown)
		lcp.setState(StateReqSent, "rcn "+state.String())
	default:
	}
	return nil
}

// RTR event (Receive-Terminate-Request)
func (lcp *LCP) rtr(req Packet) error {
	state := lcp.getState()
	switch state {
	case StateClosed, StateStopped, StateClosing, StateStopping:
		// send term-ack
		if err := lcp.sendTermACK(req); err != nil {
			return err
		}
	case StateReqSent, StateAckRcvd, StateAckSent:
		if err := lcp.sendTermACK(req); err != nil {
			return err
		}
		lcp.setState(StateReqSent, "rtr "+state.String())
	case StateOpened, StateEchoReqSent:
		// send term-ack
		if err := lcp.sendTermACK(req); err != nil {
			return err
		}
		lcp.layerNotify(LayerNotifyDown)
		lcp.restartCount.Store(0)
		lcp.resetTimer()
		lcp.setState(StateStopping, "rtr "+state.String())
	default:
	}
	return nil
}

// RTA event (Receive-Terminate-Ack)
func (lcp *LCP) rta() error {
	lcp.logger.Debug().Msg("RTA (receive term-ack) event")
	state := lcp.getState()
	switch state {
	case StateClosing:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateClosed, "rta "+state.String())
	case StateStopping:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateStopped, "rta "+state.String())
	case StateAckRcvd:
		lcp.setState(StateReqSent, "rta "+state.String())
	case StateOpened, StateEchoReqSent:
		// send conf req
		if err := lcp.sendConfReq(); err != nil {
			return err
		}
		lcp.layerNotify(LayerNotifyDown)
		lcp.setState(StateReqSent, "rta "+state.String())
	default:
	}
	return nil
}

// RUC event (Receive-Unknown-Code)
func (lcp *LCP) ruc(req Packet) error {
	if state := lcp.getState(); state != StateInitial && state != StateStarting {
		// send code-rej
		return lcp.sendCodeReject(req)
	}
	return nil
}

// rxjPlus is RXJ+ event (Receive-Code-Reject / Receive-Protocol-Reject)
func (lcp *LCP) rxjPlus() {
	if lcp.getState() == StateAckRcvd {
		lcp.setState(StateReqSent, "rxjPlus")
	}
}

// rxjMnius is RXJ- event (Receive-Code-Reject / Receive-Protocol-Reject)
func (lcp *LCP) rxjMinus(req Packet) error {
	lcp.logger.Error().Msgf("Got a %v pkt", req.Code)
	state := lcp.getState()
	switch state {
	case StateStopped, StateClosed:
		lcp.layerNotify(LayerNotifyFinished)
	case StateClosing:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateClosed, "rxjMinus "+state.String())
	case StateStopping:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateStopped, "rxjMinus "+state.String())
	case StateReqSent, StateAckRcvd, StateAckSent:
		lcp.layerNotify(LayerNotifyFinished)
		lcp.setState(StateStopped, "rxjMinus "+state.String())
	case StateOpened, StateEchoReqSent:
		// send term-req
		if err := lcp.sendTermReq(); err != nil {
			return err
		}
		lcp.layerNotify(LayerNotifyDown)
		lcp.restartCount.Store(_defaultRestartCounter)
	default:
	}
	return nil
}

// RXR event (Receive-Echo-Request / Receive-Echo-Reply / Receive-Discard-Request)
func (lcp *LCP) rxr(req Packet) error {
	switch req.Code {
	case CodeEchoRequest:
		if state := lcp.getState(); state == StateOpened || state == StateEchoReqSent {
			return lcp.sendEchoReply(req)
		}
	case CodeEchoReply:
		if lcp.getState() == StateEchoReqSent {
			lcp.restartCount.Store(_defaultRestartCounter)
			lcp.setState(StateOpened, "rxr")
		}
	}
	return nil
}

// Actions

func (lcp *LCP) sendEchoRequest() error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeEchoRequest
	lcppkt.ID = uint8(lcp.requestID.Add(1) - 1)
	if mn := lcp.OwnRule.GetOption(uint8(OpTypeMagicNumber)); mn != nil {
		lcppkt.MagicNum = uint32(*(mn.(*OpMagicNum)))
	}
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	defer lcp.resetTimer()
	lcp.logger.Info().Str("lcp", lcppkt.String()).Msg("sending echo-request")
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendEchoReply(req Packet) error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeEchoReply
	lcppkt.ID = req.ID
	lcppkt.Options = []Option{}
	if mn := lcp.OwnRule.GetOption(uint8(OpTypeMagicNumber)); mn != nil {
		lcppkt.MagicNum = uint32(*(mn.(*OpMagicNum)))
	}
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	lcp.logger.Info().Msg("sending echo-reply")
	lcp.logger.Debug().Msg(lcppkt.String())
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendCodeReject(req Packet) error {
	pkt := NewPacket(lcp.protoType)
	pkt.Code = CodeCodeReject
	pkt.ID = uint8(lcp.requestID.Add(1) - 1)
	var err error
	if pkt.Payload, err = req.Serialize(); err != nil {
		return err
	}
	pktbytes, err := pkt.Serialize()
	if err != nil {
		return err
	}
	lcp.logger.Debug().Any("pkt", pkt.String()).Msg("sending code-reject")
	return lcp.send(pktbytes)
}

func (lcp *LCP) sendConfReq() error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeConfigureRequest
	lcppkt.ID = uint8(lcp.requestID.Add(1) - 1)
	lcppkt.Options = lcp.OwnRule.GetOptions()
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	defer lcp.resetTimer()
	lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending conf-req")
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendTermReq() error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeTerminateRequest
	lcppkt.ID = uint8(lcp.requestID.Add(1) - 1)
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	defer lcp.resetTimer()
	lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending term-req")
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendTermACK(req Packet) error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeTerminateAck
	lcppkt.ID = req.ID
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending term-ack")
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendNAKRejct(req Packet, nak, reject []Option) error {
	if len(nak) > 0 {
		lcppkt := NewPacket(lcp.protoType)
		lcppkt.Code = CodeConfigureNak
		lcppkt.ID = req.ID
		lcppkt.Options = nak
		lcpbytes, err := lcppkt.Serialize()
		if err != nil {
			return err
		}
		if err := lcp.send(lcpbytes); err != nil {
			return err
		}
		lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending conf-nak")
	}

	if len(reject) > 0 {
		lcppkt := NewPacket(lcp.protoType)
		lcppkt.Code = CodeConfigureReject
		lcppkt.ID = req.ID
		lcppkt.Options = reject
		lcpbytes, err := lcppkt.Serialize()
		if err != nil {
			return err
		}
		if err := lcp.send(lcpbytes); err != nil {
			return err
		}
		lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending conf-reject")
	}
	return nil
}

func (lcp *LCP) sendConfACK(req Packet) error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeConfigureAck
	lcppkt.ID = req.ID
	lcppkt.Options = req.Options
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending conf-ack")
	return lcp.send(lcpbytes)
}

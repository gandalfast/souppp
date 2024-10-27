// Package lcp implements LCP, IPCP and IPv6CP protocols
package lcp

import (
	"context"
	"fmt"
	"github.com/gandalfast/zouppp/ppp"
	"github.com/rs/zerolog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// LayerNotifyHandler is the handler function to handle Layer event (tlu/tld/tls/tlf as defined in RFC1661)
type LayerNotifyHandler func(ctx context.Context, evt LayerNotifyEvent)

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
		return nil, fmt.Errorf("unsupported auth protocol: %v", authProto)
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
	OwnRule     OwnOptionRule  // Handle own options
	PeerRule    PeerOptionRule // Handle peer's options
	layerNotify LayerNotifyHandler

	requestID             atomic.Uint32
	state                 *uint32
	restartCount          *uint32
	maxRestart            uint32
	restartTimerDuration  time.Duration
	restartTimer          *time.Timer
	keepAliveTimer        *time.Timer
	keepAliveInterval     time.Duration
	cancellRestartTimer   context.CancelFunc
	cancellkeepAliveTimer context.CancelFunc
	sendChan              chan []byte
	recvChan              chan []byte
}

const (
	// _defaultRestartCounter is the default LCP restart counter value
	_defaultRestartCounter = 3
	// _defaultRestartTimerDuration is the default restart timer duration
	_defaultRestartTimerDuration = 10 * time.Second
	// _defaultKeepAliveInterval is the default LCP keepalive interval
	_defaultKeepAliveInterval = 5 * time.Second
)

// NewLCP creates a new LCP/IPCP/IPv6CP according to the specific proto, runs over specified pppProto, calls h whenever there is layer event.
// optionly, LCPModifier(s) could be specified to change default config
func NewLCP(proto ppp.ProtocolNumber, pppProto *ppp.PPP, h LayerNotifyHandler, peerRule PeerOptionRule, optionRule OwnOptionRule) *LCP {
	lcp := new(LCP)
	logger := pppProto.Logger.With().Str("LCPProto", lcp.protoType.String()).Logger()
	lcp.logger = &logger
	lcp.protoType = proto
	lcp.OwnRule = optionRule
	lcp.PeerRule = peerRule
	lcp.layerNotify = h

	lcp.state = new(uint32)
	atomic.StoreUint32(lcp.state, uint32(StateInitial))
	lcp.maxRestart = _defaultRestartCounter
	lcp.restartCount = new(uint32)
	atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)

	lcp.restartTimerDuration = _defaultRestartTimerDuration
	lcp.keepAliveInterval = _defaultKeepAliveInterval

	lcp.sendChan, lcp.recvChan = pppProto.Register(lcp.protoType)
	return lcp
}

func (lcp *LCP) Start(ctx context.Context) {
	go lcp.recv(ctx)
}

func (lcp *LCP) setState(s State, caller string) {
	old := State(atomic.LoadUint32(lcp.state))
	atomic.StoreUint32(lcp.state, uint32(s))
	lcp.logger.Debug().Msgf("%v state transit %v -> %v", caller, old, s)
}

func (lcp *LCP) getState() State {
	return State(atomic.LoadUint32(lcp.state))
}

func (lcp *LCP) send(p []byte) error {
	ppkt, err := ppp.NewPacket(ppp.NewStaticSerializer(p), lcp.protoType).Serialize()
	if err != nil {
		return err
	}
	lcp.sendChan <- ppkt
	return nil
}

func (lcp *LCP) sendConfReq(ctx context.Context) error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeConfigureRequest
	lcppkt.ID = uint8(lcp.requestID.Add(1) - 1)
	lcppkt.Options = lcp.OwnRule.GetOptions()
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending conf-req")
	defer lcp.resetTimer(ctx)
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendTermReq(ctx context.Context) error {
	lcppkt := NewPacket(lcp.protoType)
	lcppkt.Code = CodeTerminateRequest
	lcppkt.ID = uint8(lcp.requestID.Add(1) - 1)
	lcpbytes, err := lcppkt.Serialize()
	if err != nil {
		return err
	}
	lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending term-req")
	defer lcp.resetTimer(ctx)
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendTermACK(req *Packet) error {
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

func (lcp *LCP) sendNAKRejct(req *Packet, nak, reject []Option) (err error) {
	var lcpbytes []byte
	if len(nak) > 0 {
		lcppkt := NewPacket(lcp.protoType)
		lcppkt.Code = CodeConfigureNak
		lcppkt.ID = req.ID
		lcppkt.Options = nak
		lcpbytes, err = lcppkt.Serialize()
		if err != nil {
			return
		}
		err = lcp.send(lcpbytes)
		if err != nil {
			return
		}
		lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending conf-nak")
	}

	if len(reject) > 0 {
		lcppkt := NewPacket(lcp.protoType)
		lcppkt.Code = CodeConfigureReject
		lcppkt.ID = req.ID
		lcppkt.Options = reject
		lcpbytes, err = lcppkt.Serialize()
		if err != nil {
			return
		}
		err = lcp.send(lcpbytes)
		if err != nil {
			return
		}
		lcp.logger.Info().Str("pkt", lcppkt.String()).Msg("sending conf-reject")
	}

	return
}

func (lcp *LCP) sendConfACK(req *Packet) error {
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

func (lcp *LCP) resetKeepAliveTimer(ctx context.Context) {
	lcp.logger.Debug().Msg("reset keepalive timer")
	if lcp.protoType != ppp.ProtoLCP {
		return
	}
	if lcp.keepAliveTimer == nil {
		lcp.keepAliveTimer = time.NewTimer(lcp.keepAliveInterval)
	} else {
		lcp.keepAliveTimer.Stop()
		lcp.keepAliveTimer.Reset(lcp.keepAliveInterval)
		lcp.cancellkeepAliveTimer()
	}
	var childctx context.Context
	childctx, lcp.cancellkeepAliveTimer = context.WithCancel(ctx)
	go func(c context.Context) {
		select {
		case <-lcp.keepAliveTimer.C:
			lcp.keepAliveTimeout(ctx)
		case <-c.Done():
		}
	}(childctx)
}

func (lcp *LCP) resetTimer(ctx context.Context) {
	lcp.logger.Debug().Msg("reset timer")
	if lcp.restartTimer == nil {
		lcp.restartTimer = time.NewTimer(lcp.restartTimerDuration)
	} else {
		lcp.restartTimer.Stop()
		lcp.restartTimer.Reset(lcp.restartTimerDuration)
		lcp.cancellRestartTimer()
	}
	var childctx context.Context
	childctx, lcp.cancellRestartTimer = context.WithCancel(ctx)
	go func(c context.Context) {
		select {
		case <-lcp.restartTimer.C:
			lcp.timeout(ctx)
		case <-c.Done():
		}
	}(childctx)
}

// Keepalive Timeout event, called by lcp.resetKeepAliveTimer()
func (lcp *LCP) keepAliveTimeout(ctx context.Context) {
	switch State(atomic.LoadUint32(lcp.state)) {
	case StateOpened:
		err := lcp.sendEchoRequest(ctx)
		if err != nil {
			lcp.logger.Error().Err(err).Msg("keepAliveTimeout")
			return
		}
		lcp.setState(StateEchoReqSent, "keepAliveTimeout")
	}
}

// Timeout event, called by lcp.resetTimer()
func (lcp *LCP) timeout(ctx context.Context) {
	defer atomic.AddUint32(lcp.restartCount, ^uint32(0))
	if atomic.LoadUint32(lcp.restartCount) == 0 {
		if atomic.LoadUint32(lcp.state) == uint32(StateEchoReqSent) {
			lcp.logger.Error().Msg("keepalive timeout")
		}
		lcp.toMinus(ctx)
	}
	lcp.toPlus(ctx)
}

// toPlus is TO+ event
func (lcp *LCP) toPlus(ctx context.Context) {
	lcp.logger.Debug().Msg("timer expired, TO+ event")
	var err error
	switch lcp.getState() {
	case StateClosing, StateStopping:
		//send term req
		err = lcp.sendTermReq(ctx)
	case StateReqSent, StateAckSent:
		//send conf req
		err = lcp.sendConfReq(ctx)
	case StateAckRcvd:
		//send conf req, this is actually send current version of config options
		err = lcp.sendConfReq(ctx)
		if err == nil {
			lcp.setState(StateReqSent, "toPlus")
		}
	case StateEchoReqSent:
		//send echo request
		err = lcp.sendEchoRequest(ctx)
	}
	if err != nil {
		lcp.logger.Error().Err(err).Msg("failed to process TO+ event")
	}
}

// toMinus is TO- event
func (lcp *LCP) toMinus(ctx context.Context) {
	lcp.logger.Debug().Msg("timer expired, TO- event")
	state := lcp.getState()
	switch state {
	case StateClosing:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateClosed, "toMinus "+state.String())
	case StateStopping:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateStopped, "toMinus "+state.String())
	case StateReqSent, StateAckSent, StateAckRcvd, StateEchoReqSent:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateStopped, "toMinus "+state.String())
	}
}

func (lcp *LCP) processRecvByte(ctx context.Context, pktbytes []byte) {
	if len(pktbytes) < 4 {
		lcp.logger.Warn().Msg("recvd LCP pkt too small")
		return
	}
	pkt := NewPacket(lcp.protoType)
	err := pkt.Parse(pktbytes)
	if err != nil {
		lcp.logger.Warn().Err(err).Msg("invalid LCP pkt")
		return
	}
	lcp.logger.Info().Str("pkt", pkt.String()).Msg("got a lcp pkt")

	switch pkt.Code {
	case CodeConfigureAck:
		if err := lcp.rca(ctx, pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RCA event")
		}
	case CodeConfigureRequest:
		nak, reject := lcp.PeerRule.HandlerConfReq(pkt.Options)
		if len(nak) == 0 && len(reject) == 0 {
			err = lcp.rcrPlus(ctx, pkt)
			if err != nil {
				lcp.logger.Error().Err(err).Msg("failed to process RCR+ event")
			}
			return
		}
		err = lcp.rcrMinus(ctx, pkt, nak, reject)
		if err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RCR event")
		}
	case CodeEchoReply, CodeEchoRequest, CodeDiscardRequest:
		err = lcp.rxr(ctx, pkt)
		if err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RXR event")
		}
	case CodeTerminateRequest:
		if err := lcp.rtr(ctx, pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RTR event")
		}
	case CodeTerminateAck:
		if err := lcp.rta(ctx); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RTA event")
		}
	case CodeConfigureNak, CodeConfigureReject:
		if err := lcp.rcn(ctx, pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RCN event")
		}
	case CodeCodeReject, CodeProtocolReject:
		if err := lcp.rxjMinus(ctx, pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process RXJ event")
		}
	default:
		if err := lcp.ruc(pkt); err != nil {
			lcp.logger.Error().Err(err).Msg("failed to handle RUC event")
		}
	}
}

func (lcp *LCP) recv(ctx context.Context) {
	// var err error
	// var n int
	for {
		select {
		case pktbytes := <-lcp.recvChan:
			lcp.processRecvByte(ctx, pktbytes)
		case <-ctx.Done():
			lcp.logger.Info().Msg("recv routine stopped")
			return
		}
	}
}

func (lcp *LCP) rcrPlus(ctx context.Context, req *Packet) (err error) {
	state := lcp.getState()
	switch state {
	case StateClosed:
		//send term-ack
		err = lcp.sendTermACK(req)
	case StateStopped:
		// send conf-req
		err = lcp.sendConfReq(ctx)
		if err != nil {
			return
		}
		// send conf-ack
		err = lcp.sendConfACK(req)
		if err != nil {
			return
		}
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
		lcp.setState(StateAckSent, "rcrPlus "+state.String())
	case StateReqSent:
		// send conf-ack
		err = lcp.sendConfACK(req)
		if err != nil {
			return
		}
		lcp.setState(StateAckSent, "rcrPlus "+state.String())
	case StateAckRcvd:
		//send conf-ack
		err = lcp.sendConfACK(req)
		if err != nil {
			return
		}
		lcp.layerNotify(ctx, LayerNotifyUp)
		lcp.setState(StateOpened, "rcrPlus "+state.String())
		lcp.resetKeepAliveTimer(ctx)
	case StateAckSent:
		// send conf-ack
		err = lcp.sendConfACK(req)
	case StateOpened, StateEchoReqSent:
		lcp.layerNotify(ctx, LayerNotifyDown)
		// send conf-req
		err = lcp.sendConfReq(ctx)
		if err != nil {
			return
		}
		// send conf-ack
		err = lcp.sendConfACK(req)
		if err != nil {
			return
		}
		lcp.setState(StateAckSent, "rcrPlus "+state.String())
	}
	return
}

func (lcp *LCP) rcrMinus(ctx context.Context, req *Packet, nak, reject []Option) (err error) {
	state := lcp.getState()
	switch state {
	case StateClosed:
		//send term-ack
		err = lcp.sendTermACK(req)
	case StateStopped:
		// send conf-req
		err = lcp.sendConfReq(ctx)
		if err != nil {
			return
		}
		// send conf-nak
		err = lcp.sendNAKRejct(req, nak, reject)
		if err != nil {
			return
		}
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
		lcp.setState(StateReqSent, "rcrMinus "+state.String())
	case StateReqSent, StateAckRcvd:
		// send conf-nak
		err = lcp.sendNAKRejct(req, nak, reject)
	case StateAckSent:
		// send conf-nak
		err = lcp.sendNAKRejct(req, nak, reject)
		if err != nil {
			return
		}
		lcp.setState(StateReqSent, "rcrMinus "+state.String())
	case StateOpened, StateEchoReqSent:
		// send conf-req
		err = lcp.sendConfReq(ctx)
		if err != nil {
			return
		}
		// send conf-nak
		err = lcp.sendNAKRejct(req, nak, reject)
		if err != nil {
			return
		}
		lcp.layerNotify(ctx, LayerNotifyDown)
		lcp.setState(StateReqSent, "rcrMinus "+state.String())
	}
	return
}

// RCA event
func (lcp *LCP) rca(ctx context.Context, req *Packet) (err error) {
	state := lcp.getState()
	switch state {
	case StateStopped, StateClosed:
		//send term-ack
		err = lcp.sendTermACK(req)
	case StateReqSent:
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
		lcp.setState(StateAckRcvd, "rca "+state.String())
	case StateAckRcvd:
		//send conf req
		err = lcp.sendConfReq(ctx)
		if err != nil {
			return
		}
		lcp.setState(StateReqSent, "rca "+state.String())
	case StateAckSent:
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
		lcp.layerNotify(ctx, LayerNotifyUp)
		lcp.setState(StateOpened, "rca "+state.String())
		lcp.resetKeepAliveTimer(ctx)
	case StateOpened, StateEchoReqSent:
		lcp.layerNotify(ctx, LayerNotifyDown)
		//send conf req
		err = lcp.sendConfReq(ctx)
		if err != nil {
			return
		}
		lcp.setState(StateReqSent, "rca "+state.String())
	}
	return
}

// RCN event
func (lcp *LCP) rcn(ctx context.Context, req *Packet) error {
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
		//send cfg-req
		err := lcp.sendConfReq(ctx)
		if err != nil {
			return err
		}
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
	case StateAckRcvd:
		//send cfg-req
		err := lcp.sendConfReq(ctx)
		if err != nil {
			return err
		}
		lcp.setState(StateReqSent, "rcn "+state.String())
	case StateAckSent:
		//send cfg-req
		err := lcp.sendConfReq(ctx)
		if err != nil {
			return err
		}
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
	case StateOpened, StateEchoReqSent:
		//send cfg-req
		err := lcp.sendConfReq(ctx)
		if err != nil {
			return err
		}
		lcp.layerNotify(ctx, LayerNotifyDown)
		lcp.setState(StateReqSent, "rcn "+state.String())
	}
	return nil
}

// PTR event
func (lcp *LCP) rtr(ctx context.Context, req *Packet) (err error) {
	state := lcp.getState()
	switch state {
	case StateClosed, StateStopped, StateClosing, StateStopping:
		//send term-ack
		err = lcp.sendTermACK(req)
	case StateReqSent, StateAckRcvd, StateAckSent:
		err = lcp.sendTermACK(req)
		if err != nil {
			return
		}
		lcp.setState(StateReqSent, "rtr "+state.String())
	case StateOpened, StateEchoReqSent:
		// send term-ack
		err = lcp.sendTermACK(req)
		if err != nil {
			return
		}
		lcp.layerNotify(ctx, LayerNotifyDown)
		atomic.StoreUint32(lcp.restartCount, 0)
		lcp.resetTimer(ctx)
		lcp.setState(StateStopping, "rtr "+state.String())
	}
	return
}

// RTA event
func (lcp *LCP) rta(ctx context.Context) error {
	lcp.logger.Debug().Msg("RTA (receive term-ack) event")
	state := lcp.getState()
	switch state {
	case StateClosing:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateClosed, "rta "+state.String())
	case StateStopping:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateStopped, "rta "+state.String())
	case StateAckRcvd:
		lcp.setState(StateReqSent, "rta "+state.String())
	case StateOpened, StateEchoReqSent:
		//send conf req
		err := lcp.sendConfReq(ctx)
		if err != nil {
			return err
		}
		lcp.layerNotify(ctx, LayerNotifyDown)
		lcp.setState(StateReqSent, "rta "+state.String())
	}
	return nil
}

// RUC event
func (lcp *LCP) ruc(req *Packet) error {
	switch lcp.getState() {
	case StateInitial, StateStarting:
		return nil
	}
	// send code-rej
	return lcp.sendCodeReject(req)
}

func (lcp *LCP) sendCodeReject(req *Packet) error {
	pkt := NewPacket(lcp.protoType)
	pkt.Code = CodeCodeReject
	pkt.ID = uint8(lcp.requestID.Add(1) - 1)
	pkt.Payload, _ = req.Serialize()
	pktbytes, err := pkt.Serialize()
	if err != nil {
		return err
	}
	lcp.logger.Debug().Any("pkt", pkt.String()).Msg("sending code-reject")
	return lcp.send(pktbytes)
}

// rxjPlus is RXJ+ event
func (lcp *LCP) rxjPlus() {
	switch lcp.getState() {
	case StateAckRcvd:
		lcp.setState(StateReqSent, "rxjPlus")
	}
}

// rxjMnius is RXJ- event
func (lcp *LCP) rxjMinus(ctx context.Context, req *Packet) error {
	lcp.logger.Error().Msgf("Got a %v pkt", req.Code)
	state := lcp.getState()
	switch state {
	case StateStopped, StateClosed:
		lcp.layerNotify(ctx, LayerNotifyFinished)
	case StateClosing:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateClosed, "rxjMinus "+state.String())
	case StateStopping:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateStopped, "rxjMinus "+state.String())
	case StateReqSent, StateAckRcvd, StateAckSent:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateStopped, "rxjMinus "+state.String())
	case StateOpened, StateEchoReqSent:
		// send term-req
		err := lcp.sendTermReq(ctx)
		if err != nil {
			return err
		}
		lcp.layerNotify(ctx, LayerNotifyDown)
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
	}
	return nil
}

func (lcp *LCP) sendEchoRequest(ctx context.Context) error {
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
	lcp.logger.Info().Str("lcp", lcppkt.String()).Msg("sending echo-request")
	defer lcp.resetTimer(ctx)
	return lcp.send(lcpbytes)
}

func (lcp *LCP) sendEchoReply(req *Packet) error {
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

// RXR event
func (lcp *LCP) rxr(ctx context.Context, req *Packet) error {
	switch req.Code {
	case CodeEchoRequest:
		switch lcp.getState() {
		case StateOpened, StateEchoReqSent:
			return lcp.sendEchoReply(req)
		}
	case CodeEchoReply:
		switch lcp.getState() {
		case StateEchoReqSent:
			atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
			lcp.setState(StateOpened, "rxr")
			lcp.resetKeepAliveTimer(ctx)
		}
	}
	return nil
}

// Up is lower layer up event, as defined in RFC1661
func (lcp *LCP) Up(ctx context.Context) (err error) {
	state := lcp.getState()
	switch state {
	case StateInitial:
		lcp.setState(StateClosed, "Up "+state.String())
	case StateStarting:
		err = lcp.sendConfReq(ctx)
		if err != nil {
			return
		}
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
		lcp.resetTimer(ctx)
		lcp.setState(StateReqSent, "Up "+state.String())
	}
	return
}

// Down is lower layer down event, as defined in RFC1661
func (lcp *LCP) Down(ctx context.Context) {
	state := lcp.getState()
	switch state {
	case StateStopped:
		lcp.layerNotify(ctx, LayerNotifyStarted)
		lcp.setState(StateStarting, "Down "+state.String())
	case StateReqSent, StateAckRcvd, StateAckSent:
		lcp.setState(StateStarting, "Down "+state.String())
	case StateOpened, StateEchoReqSent:
		lcp.layerNotify(ctx, LayerNotifyDown)
		lcp.setState(StateStarting, "Down "+state.String())
	}
}

// Open is admin Open event, as defined in RFC1661
func (lcp *LCP) Open(ctx context.Context) error {
	state := lcp.getState()
	switch state {
	case StateInitial:
		lcp.layerNotify(ctx, LayerNotifyStarted)
		lcp.setState(StateStarting, "Open "+state.String())
	case StateClosed:
		err := lcp.sendConfReq(ctx)
		if err != nil {
			return err
		}
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)
		lcp.setState(StateReqSent, "Open "+state.String())
	case StateClosing:
		lcp.setState(StateStopping, "Open "+state.String())
	}
	return nil
}

// Close is admin Close event, as defined in RFC1661
func (lcp *LCP) Close(ctx context.Context) {
	state := lcp.getState()
	switch state {
	case StateStarting:
		lcp.layerNotify(ctx, LayerNotifyFinished)
		lcp.setState(StateInitial, "Close "+state.String())
	case StateStopped:
		lcp.setState(StateClosed, "Close "+state.String())
	case StateStopping:
		lcp.setState(StateClosing, "Close "+state.String())
	case StateReqSent, StateAckRcvd, StateAckSent:
		// send term req
		err := lcp.sendTermReq(ctx)
		if err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process TO+ event")
			return
		}
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)

		lcp.setState(StateClosing, "Close "+state.String())
	case StateOpened, StateEchoReqSent:
		//send term req
		err := lcp.sendTermReq(ctx)
		if err != nil {
			lcp.logger.Error().Err(err).Msg("failed to process TO+ event")
			return
		}
		lcp.layerNotify(ctx, LayerNotifyDown)
		atomic.StoreUint32(lcp.restartCount, lcp.maxRestart)

		lcp.setState(StateClosing, "Close "+state.String())
	}
}

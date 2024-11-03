package client

import (
	"context"
	"errors"
	"fmt"
	"github.com/gandalfast/souppp/auth"
	"github.com/gandalfast/souppp/auth/chap"
	"github.com/gandalfast/souppp/auth/pap"
	"github.com/gandalfast/souppp/datapath"
	"github.com/gandalfast/souppp/etherconn"
	"github.com/gandalfast/souppp/ppp"
	"github.com/gandalfast/souppp/ppp/lcp"
	"github.com/gandalfast/souppp/pppoe"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"net"
	"sync/atomic"
	"time"
)

type session struct {
	isReady     atomic.Bool
	isClosed    atomic.Bool
	closed      chan struct{}
	cfg         *Setup
	dialChan    chan int8
	osInterface *datapath.TUNInterface
	etherConn   *etherconn.EtherConn
	pppoeProto  *pppoe.PPPoE
	pppProto    *ppp.PPP
	lcpProto    *lcp.LCP
	ipcpV4Proto *lcp.LCP
	ipv6cpProto *lcp.LCP
	// IPv4 Address
	assignedV4Addr net.IP
	// DHCPv6
	assignedIANAs []net.IP
	assignedIAPDs []*net.IPNet
}

func newSession(index int, cfg *Setup, relay etherconn.PacketRelay, blacklist lcp.Blacklist) (*session, error) {
	mac := cfg.StartMAC
	if index > 0 {
		var err error
		mac, err = incrementMACAddress(mac, int64(cfg.MacStep*uint(index)))
		if err != nil {
			return nil, fmt.Errorf("failed to generate mac address,%v", err)
		}
	}

	etherConn := etherconn.NewEtherConn(
		mac,
		relay,
		[]uint16{pppoe.EtherTypePPPoEDiscovery, pppoe.EtherTypePPPoESession},
		etherconn.WithReceiveMulticast(true),
	)

	cfg = cfg.Clone(index)
	logger := cfg.Logger.With().Str("ETH", etherConn.LocalAddr().String()).Logger()
	cfg.Logger = &logger

	s := &session{
		cfg:       cfg.Clone(index),
		closed:    make(chan struct{}),
		dialChan:  make(chan int8),
		etherConn: etherConn,
	}

	var tagList []pppoe.Tag
	if cfg.CircuitID != "" || cfg.RemoteID != "" {
		tagList = append(tagList, pppoe.NewCircuitRemoteIDTag(cfg.CircuitID, cfg.RemoteID))
	}

	s.pppoeProto = pppoe.NewPPPoE(etherConn, cfg.Logger, pppoe.WithTags(tagList))
	s.pppProto = ppp.NewPPP(s.pppoeProto, cfg.Logger, lcp.NewRejectPacket())

	defPeerRule, err := lcp.NewDefaultPeerOptionRule(cfg.AuthProto)
	if err != nil {
		cfg.Logger.Err(err).Int("index", index).Msg("Unable to define LCP default peer route")
		return nil, err
	}
	s.lcpProto = lcp.NewLCP(ppp.ProtoLCP, s.pppProto, s.lcpEvtHandler, defPeerRule, lcp.NewDefaultOwnOptionRule())
	s.ipcpV4Proto = lcp.NewLCP(ppp.ProtoIPCP, s.pppProto, s.ipcpEvtHandler, &lcp.DefaultIPCPPeerRule{}, lcp.NewDefaultIPCPOwnRule(blacklist))
	ipcp6rule := lcp.NewDefaultIP6CPRule(s.pppoeProto.LocalAddr().(*pppoe.Endpoint).L2EP)
	s.ipv6cpProto = lcp.NewLCP(ppp.ProtoIPv6CP, s.pppProto, s.ipcp6EvtHandler, ipcp6rule, ipcp6rule)

	return s, nil
}

func (s *session) Dial(ctx context.Context) error {
	if err := s.pppoeProto.Dial(ctx); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("unable to dial pppoe")
		return err
	}

	s.cfg.Logger.Info().Msg("pppoe open")

	s.pppProto.Start(ctx)
	s.lcpProto.Start(ctx)
	if err := s.lcpProto.OpenEvent(); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("unable to send LCP open event")
		return err
	}
	if err := s.lcpProto.UpEvent(); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("unable to send LCP up event")
		return err
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	counter := int8(0)
	for {
		select {
		case <-ctxTimeout.Done():
			return ctxTimeout.Err()
		case _, ok := <-s.closed:
			if !ok {
				return errors.New("session closed")
			}
		case value := <-s.dialChan:
			counter += value
			if counter == 0 {
				err := s.createDataPath(ctx)
				if err != nil {
					_ = s.Close()
				}
				return err
			}
		}
	}
}

func (s *session) Close() error {
	if !s.isClosed.CompareAndSwap(false, true) {
		// Already closed
		return nil
	}

	close(s.closed)
	s.isReady.Store(false)
	var errList []error

	// Close PPP session in network stack order
	if s.osInterface != nil {
		errList = append(errList, s.osInterface.Close())
	}
	errList = append(errList, s.ipv6cpProto.Close())
	errList = append(errList, s.ipcpV4Proto.Close())
	errList = append(errList, s.lcpProto.Close())
	errList = append(errList, s.pppProto.Close())
	errList = append(errList, s.pppoeProto.Close())
	errList = append(errList, s.etherConn.Close())
	return errors.Join(errList...)
}

func (s *session) lcpEvtHandler(evt lcp.LayerNotifyEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()
	s.cfg.Logger.Info().Msgf("LCP layer %v", evt)

	switch evt {
	case lcp.LayerNotifyUp:
		// run auth
		options := s.lcpProto.PeerRule.GetOptions()
		var opauthlist []lcp.Option
		for _, opt := range options {
			if opt.Type() == uint8(lcp.OpTypeAuthenticationProtocol) {
				opauthlist = append(opauthlist, opt)
			}
		}
		if len(opauthlist) == 0 {
			s.cfg.Logger.Error().Msg("no authentication method is negotiated")
			_ = s.Close()
			return
		}

		startingAuthTime := time.Now()
		authProto := opauthlist[0].(*lcp.OpAuthProto).Proto
		authenticator, err := s.getAuthHandler(authProto)
		if err != nil {
			s.cfg.Logger.Error().Err(err).Msg("unable to obtain authenticator")
			_ = s.Close()
			return
		}
		if err := authenticator.AuthSelf(ctx, s.cfg.UserName, s.cfg.Password); err != nil {
			s.cfg.Logger.Error().Err(err).Msg("auth failed")
			_ = s.Close()
			return
		}
		s.cfg.Logger.Info().TimeDiff("time", time.Now(), startingAuthTime).Msg("auth succeed")

		if s.cfg.IPv4 {
			s.dialChan <- 1
			s.ipcpV4Proto.Start(ctx)
			if err := s.ipcpV4Proto.OpenEvent(); err != nil {
				_ = s.Close()
				return
			}
			if err := s.ipcpV4Proto.UpEvent(); err != nil {
				_ = s.Close()
				return
			}
		}

		if s.cfg.IPv6 {
			s.dialChan <- 1
			s.ipv6cpProto.Start(ctx)
			if err := s.ipv6cpProto.OpenEvent(); err != nil {
				_ = s.Close()
				return
			}
			if err := s.ipv6cpProto.UpEvent(); err != nil {
				_ = s.Close()
				return
			}
		}
	case lcp.LayerNotifyDown, lcp.LayerNotifyFinished:
		_ = s.Close()
	default:
	}
}

func (s *session) getAuthHandler(authProto ppp.ProtocolNumber) (auth.Authenticator, error) {
	switch authProto {
	case ppp.ProtoCHAP:
		return chap.NewCHAP(s.pppProto), nil
	case ppp.ProtoPAP:
		return pap.NewPAP(s.pppProto, s.cfg.InitialAuthIdentifier, s.cfg.ConcurrentAuthRetries), nil
	default:
		return nil, errors.New("unkown auth method negoatied " + authProto.String())
	}
}

func (s *session) ipcpEvtHandler(evt lcp.LayerNotifyEvent) {
	s.cfg.Logger.Info().Msgf("IPCP layer %v", evt)
	switch evt {
	case lcp.LayerNotifyUp:
		if v4addrop := s.ipcpV4Proto.OwnRule.GetOption(uint8(lcp.OpIPAddress)); v4addrop != nil {
			s.assignedV4Addr = v4addrop.(*lcp.IPv4AddrOption).Addr
		}
		s.dialChan <- -1
	case lcp.LayerNotifyDown, lcp.LayerNotifyFinished:
		_ = s.Close()
	default:
	}
}

func (s *session) ipcp6EvtHandler(evt lcp.LayerNotifyEvent) {
	s.cfg.Logger.Info().Msgf("IPv6CP layer %v", evt)
	switch evt {
	case lcp.LayerNotifyUp:
		go func() {
			err := s.dialDHCPv6(context.Background())
			if err == nil {
				s.dialChan <- -1
			} else {
				_ = s.Close()
			}
		}()

	case lcp.LayerNotifyDown, lcp.LayerNotifyFinished:
		_ = s.Close()
	default:
	}
}

// getV6LLA returns the IPv6 LLA the composed of negotiated interface-id via IPv6CP
func (s *session) getV6LLA() (net.IP, error) {
	if s.ipv6cpProto != nil {
		if ifidop := s.ipv6cpProto.OwnRule.GetOption(uint8(lcp.IP6CPOpInterfaceIdentifier)); ifidop != nil {
			ifid := ifidop.GetPayload()
			if len(ifid) != 8 {
				return nil, errors.New("invalid interface id length")
			}
			lla := make([]byte, 16)
			copy(lla[:8], lcp.IPv6LinkLocalPrefix[:8])
			copy(lla[8:16], ifid)
			return lla, nil
		}
	}
	return nil, errors.New("ipv6cp is not up")
}

func (s *session) dialDHCPv6(ctx context.Context) error {
	if !s.cfg.DHCPv6IANA && !s.cfg.DHCPv6IAPD {
		return nil
	}

	s.cfg.Logger.Info().Msgf("dialing DHCPv6 IANA %v IAPD %v", s.cfg.DHCPv6IANA, s.cfg.DHCPv6IAPD)

	econn := ppp.NewConnAdapter(s.pppProto, ppp.ProtoIPv6)
	econn.Start(ctx)
	defer econn.Close()

	lla, err := s.getV6LLA()
	if err != nil {
		return err
	}

	localAddress, err := net.ResolveUDPAddr(
		"udp",
		fmt.Sprintf("[%v]:%v", lla, dhcpv6.DefaultClientPort),
	)
	if err != nil {
		return err
	}

	rudpconn, err := etherconn.NewSharingRUDPConn(localAddress, econn)
	if err != nil {
		s.cfg.Logger.Error().Err(err).Msg("failed to create SharedRUDPConn")
		return err
	}

	clnt, err := NewDHCP6Clnt(rudpconn, DHCP6Cfg{
		Mac:    s.cfg.StartMAC,
		Debug:  s.cfg.LogLevel == LogLvlDebug,
		NeedPD: s.cfg.DHCPv6IAPD,
		NeedNA: s.cfg.DHCPv6IANA,
	})
	if err != nil {
		s.cfg.Logger.Error().Err(err).Msg("failed to create DHCPv6 client")
		return err
	}
	if err := clnt.Dial(ctx); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("failed to dial using DHCPv6 client")
		return err
	}
	s.assignedIANAs = clnt.assignedIANAs
	s.assignedIAPDs = clnt.assignedIAPDs
	return nil
}

func (s *session) createDataPath(ctx context.Context) error {
	if s.osInterface != nil {
		return nil
	}
	s.cfg.Logger.Info().Msg("creating data path")

	options := s.lcpProto.PeerRule.GetOptions()
	var mruOpt lcp.Option
	for _, opt := range options {
		if opt.Type() == uint8(lcp.OpTypeMaximumReceiveUnit) {
			mruOpt = opt
			break
		}
	}

	var mru uint16 = 1498
	if mruOpt != nil {
		mru = uint16(*(mruOpt.(*lcp.OpMRU)))
	}

	var err error
	if s.osInterface, err = datapath.NewTUNIf(
		ctx,
		s.pppProto,
		s.cfg.PPPInterfaceName,
		append(s.assignedIANAs, s.assignedV4Addr),
		mru,
	); err != nil {
		return fmt.Errorf("failed to create datapath, %w", err)
	}
	return nil
}

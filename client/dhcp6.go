package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
	"github.com/insomniacslk/dhcp/iana"
	"net"
	"time"
)

// DHCP6Cfg holds configuration for DHCPv6.
type DHCP6Cfg struct {
	Mac            net.HardwareAddr
	NeedPD, NeedNA bool
	Debug          bool
}

// DHCP6Clnterface is a DHCPv6 client.
type DHCP6Clnterface struct {
	client        *nclient6.Client
	cfg           DHCP6Cfg
	assignedIANAs []net.IP
	assignedIAPDs []*net.IPNet
}

// NewDHCP6Clnt creates a new DHCPv6 client, using conn as transport.
// Cfg holds the configuration, localLLA is used for local link local address for DHCPv6 msg.
func NewDHCP6Clnt(conn net.PacketConn, cfg DHCP6Cfg) (*DHCP6Clnterface, error) {
	var mods []nclient6.ClientOpt
	if cfg.Debug {
		mods = append(mods, nclient6.WithDebugLogger(), nclient6.WithLogDroppedPackets())
	}

	client, err := nclient6.NewWithConn(conn, cfg.Mac, mods...)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCPv6 client, %w", err)
	}

	return &DHCP6Clnterface{
		cfg:    cfg,
		client: client,
	}, nil
}

// Dial completes a DHCPv6 exchange.
func (dc *DHCP6Clnterface) Dial(ctx context.Context) error {
	solicitMsg, err := dc.buildSolicit()
	if err != nil {
		return fmt.Errorf("failed to create solicit msg for %v, %v", dc.cfg.Mac, err)
	}
	adv, err := dc.client.SendAndRead(
		ctx,
		nclient6.AllDHCPRelayAgentsAndServers, solicitMsg,
		nclient6.IsMessageType(dhcpv6.MessageTypeAdvertise),
	)
	if err != nil {
		return fmt.Errorf("failed recv DHCPv6 advertisement for %v, %v", dc.cfg.Mac, err)
	}
	if err := dc.checkResponse(adv, false); err != nil {
		return fmt.Errorf("got invalid advertise msg for client %v, %v", dc.cfg.Mac, err)
	}

	request, err := newRequestFromAdv(adv)
	if err != nil {
		return fmt.Errorf("failed to build request msg for client %v, %v", dc.cfg.Mac, err)
	}
	reply, err := dc.client.SendAndRead(
		ctx,
		nclient6.AllDHCPRelayAgentsAndServers,
		request, nclient6.IsMessageType(dhcpv6.MessageTypeReply),
	)
	if err != nil {
		return fmt.Errorf("failed to recv DHCPv6 reply for %v, %v", dc.cfg.Mac, err)
	}

	if err := dc.checkResponse(reply, true); err != nil {
		return fmt.Errorf("got invalid reply msg for %v, %v", dc.cfg.Mac, err)
	}
	return nil
}

func (dc *DHCP6Clnterface) buildSolicit() (*dhcpv6.Message, error) {
	var optModList []dhcpv6.Modifier
	if dc.cfg.NeedNA {
		optModList = append(optModList, dhcpv6.WithIAID(getIAIDviaTime(0)))
	}
	if dc.cfg.NeedPD {
		optModList = append(optModList, dhcpv6.WithIAPD(getIAIDviaTime(1)))
	}

	duid := &dhcpv6.DUIDLL{
		HWType:        iana.HWTypeEthernet,
		LinkLayerAddr: dc.cfg.Mac,
	}
	m, err := dhcpv6.NewMessage()
	if err != nil {
		return nil, err
	}
	m.MessageType = dhcpv6.MessageTypeSolicit
	m.AddOption(dhcpv6.OptClientID(duid))
	m.AddOption(dhcpv6.OptRequestedOption(
		dhcpv6.OptionDNSRecursiveNameServer,
		dhcpv6.OptionDomainSearchList,
	))
	m.AddOption(dhcpv6.OptElapsedTime(0))
	for _, mod := range optModList {
		mod(m)
	}
	return m, nil
}

func (dc *DHCP6Clnterface) checkResponse(msg *dhcpv6.Message, save bool) error {
	if dc.cfg.NeedNA {
		addresses := msg.Options.OneIANA().Options.Addresses()
		if len(addresses) == 0 {
			return errors.New("no IANA address is assigned")
		}
		if save {
			for _, addr := range addresses {
				dc.assignedIANAs = append(dc.assignedIANAs, addr.IPv6Addr)
			}
		}
	}

	if dc.cfg.NeedPD {
		prefixes := msg.Options.OneIAPD().Options.Prefixes()
		if len(prefixes) == 0 {
			return errors.New("no IAPD prefix is assigned")
		}
		if save {
			for _, p := range prefixes {
				dc.assignedIAPDs = append(dc.assignedIAPDs, p.Prefix)
			}
		}
	}

	return nil
}

func newRequestFromAdv(adv *dhcpv6.Message, modifiers ...dhcpv6.Modifier) (*dhcpv6.Message, error) {
	if adv == nil {
		return nil, errors.New("ADVERTISE cannot be nil")
	} else if adv.MessageType != dhcpv6.MessageTypeAdvertise {
		return nil, errors.New("the passed ADVERTISE must have ADVERTISE type set")
	}

	// build REQUEST from ADVERTISE
	req, err := dhcpv6.NewMessage()
	if err != nil {
		return nil, err
	}
	req.MessageType = dhcpv6.MessageTypeRequest

	// add Client ID
	cid := adv.GetOneOption(dhcpv6.OptionClientID)
	if cid == nil {
		return nil, errors.New("client ID cannot be nil in ADVERTISE when building REQUEST")
	}
	req.AddOption(cid)

	// add Server ID
	sid := adv.GetOneOption(dhcpv6.OptionServerID)
	if sid == nil {
		return nil, errors.New("server ID cannot be nil in ADVERTISE when building REQUEST")
	}
	req.AddOption(sid)

	// add Elapsed Time
	req.AddOption(dhcpv6.OptElapsedTime(0))

	// add IA_NA
	if iaNa := adv.Options.OneIANA(); iaNa != nil {
		req.AddOption(iaNa)
	}

	// add IA_PD
	if iaPd := adv.GetOneOption(dhcpv6.OptionIAPD); iaPd != nil {
		req.AddOption(iaPd)
	}
	req.AddOption(dhcpv6.OptRequestedOption(
		dhcpv6.OptionDNSRecursiveNameServer,
		dhcpv6.OptionDomainSearchList,
	))

	// add OPTION_VENDOR_CLASS, only if present in the original request
	if vClass := adv.GetOneOption(dhcpv6.OptionVendorClass); vClass != nil {
		req.AddOption(vClass)
	}

	// apply modifiers
	for _, mod := range modifiers {
		mod(req)
	}
	return req, nil
}

func getIAIDviaTime(delta int64) (r [4]byte) {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutVarint(buf, time.Now().UnixNano()+delta)
	copy(r[:], buf[:4])
	return r
}

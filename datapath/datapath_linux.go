// Package datapath implements linux data path for PPPoE/PPP;
//
//	TODO: currently datapath does NOT do following:
//		- create default route with nexthop as the TUN interface
//		- apply DNS server address
package datapath

import (
	"context"
	"fmt"
	"github.com/gandalfast/souppp/ppp"
	"github.com/rs/zerolog"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"net"
)

// TUNInterface is the TUN interface for a opened PPP session
type TUNInterface struct {
	logger                 *zerolog.Logger
	pppProto               *ppp.PPP
	netInterface           *water.Interface
	sendChan               chan []byte
	v4recvChan, v6recvChan chan []byte
	closed                 chan struct{}
}

// NewTUNIf creates a new TUN interface supporting PPP protocol.
// The interface name must be specified in the parameters, and all the assigned addresses
// are copied into the TUN interface.
// MTU value is the value of peerMRU parameter.
func NewTUNIf(ctx context.Context, pppproto *ppp.PPP, name string, assignedAddrs []net.IP, peerMRU uint16) (tun *TUNInterface, err error) {
	tun = &TUNInterface{
		pppProto: pppproto,
		closed:   make(chan struct{}),
	}

	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	}

	// Create TUN interface
	if tun.netInterface, err = water.New(cfg); err != nil {
		return nil, fmt.Errorf("failed to create TUN interface %v, %w", cfg.Name, err)
	}

	// Enable network link
	link, _ := netlink.LinkByName(cfg.Name)
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to bring the TUN interface %v up, %w", cfg.Name, err)
	}

	// Add remote address
	for _, addr := range assignedAddrs {
		if addr == nil {
			continue
		}
		if !addr.IsUnspecified() && len(addr) > 0 {
			var addressMask string
			if addr.To4() != nil {
				addressMask = "/32"
				tun.sendChan, tun.v4recvChan = pppproto.Register(ppp.ProtoIPv4)
			} else {
				addressMask = "/128"
				tun.sendChan, tun.v6recvChan = pppproto.Register(ppp.ProtoIPv6)
			}

			addrString := addr.String() + addressMask
			netAddr, err := netlink.ParseAddr(addrString)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %v as IP addr, %w", addrString, err)
			}

			// Add default remote route to the interface
			if err := netlink.AddrAdd(link, netAddr); err != nil {
				return nil, fmt.Errorf("failed to add addr %v, %w", addrString, err)
			}
		}
	}

	// Adjust MTU based on PPP peer's MRU
	mtu := int(peerMRU)
	if mtu < 1280 {
		mtu = 1280
	}
	_ = netlink.LinkSetMTU(link, mtu)

	logger := pppproto.Logger.With().Str("Name", "datapath").Logger()
	tun.logger = &logger

	go tun.send(ctx)
	go tun.recv(ctx)
	return tun, nil
}

func (tif *TUNInterface) Close() error {
	tif.pppProto.Unregister(ppp.ProtoIPv4)
	tif.pppProto.Unregister(ppp.ProtoIPv6)
	close(tif.closed)
	return tif.netInterface.Close()
}

// send pkt to outside network
func (tif *TUNInterface) send(ctx context.Context) {
	for {
		// Read IPv4 / IPv6 packet to send from TUN interface
		buf := make([]byte, ppp.MaxPPPMsgSize)
		n, err := tif.netInterface.Read(buf)
		if err != nil {
			select {
			case _, ok := <-tif.closed:
				if !ok {
					// Do nothing if interface is closed
					return
				}
			default:
				tif.logger.Error().Err(err).Msg("failed to read net interface packet")
				return
			}
		}
		buf = buf[:n]

		// Check if context is still valid
		select {
		case <-ctx.Done():
			tif.logger.Info().Msg("send routine stopped")
			return
		case _, ok := <-tif.closed:
			if !ok {
				tif.logger.Info().Msg("send routine stopped")
				return
			}
		default:
		}

		// Packet is too small, discard
		if n < ppp.MinimumFrameSize {
			continue
		}

		// Check Version value from IPv4 / IPv6 header, and encapsulate
		// into PPP accordingly
		switch buf[0] >> 4 {
		case 4:
			pkt, err := ppp.NewPacket(ppp.NewStaticSerializer(buf[:n]), ppp.ProtoIPv4).Serialize()
			if err == nil {
				tif.sendChan <- pkt
			}
		case 6:
			pkt, err := ppp.NewPacket(ppp.NewStaticSerializer(buf[:n]), ppp.ProtoIPv6).Serialize()
			if err == nil {
				tif.sendChan <- pkt
			}
		default:
			tif.logger.Info().Msg("unable to send packet with unknown IP version")
			continue
		}
	}
}

// recv gets packet from outside network
func (tif *TUNInterface) recv(ctx context.Context) {
	for {
		var pktbytes []byte

		select {
		case <-ctx.Done():
			tif.logger.Info().Msg("recv routine stopped")
			return
		case _, ok := <-tif.closed:
			if !ok {
				tif.logger.Info().Msg("send routine stopped")
				return
			}
		case pktbytes = <-tif.v4recvChan:
			// Save data into pktbytes
		case pktbytes = <-tif.v6recvChan:
			// Save data into pktbytes
		}

		if len(pktbytes) < ppp.MinimumFrameSize {
			continue
		}

		if _, err := tif.netInterface.Write(pktbytes); err != nil {
			tif.logger.Error().Err(err).Msg("failed to send data to TUN interface")
			return
		}
	}
}

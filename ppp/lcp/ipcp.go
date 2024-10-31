package lcp

import (
	"errors"
	"net"
	"sync"
)

// IPv4AddrOption represents IPCP option contains a single IPv4 address
type IPv4AddrOption struct {
	AddrType IPCPOptionType
	Addr     net.IP
}

func (addr *IPv4AddrOption) Type() uint8 {
	return uint8(addr.AddrType)
}

func (addr *IPv4AddrOption) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	buf[0] = byte(addr.AddrType)
	buf[1] = byte(len(buf))
	copy(buf[2:6], addr.Addr.To4())
	return buf, nil
}

func (addr *IPv4AddrOption) Parse(buf []byte) (int, error) {
	if len(buf) < 6 {
		return 0, errors.New("not enough bytes")
	}
	if buf[1] != 6 {
		return 0, errors.New("len field is not 6")
	}
	addr.AddrType = IPCPOptionType(buf[0])
	addr.Addr = buf[2:6]
	return 6, nil
}

func (addr *IPv4AddrOption) GetPayload() []byte {
	return addr.Addr.To4()
}

func (addr *IPv4AddrOption) String() string {
	return addr.AddrType.String() + ":" + addr.Addr.String()
}

func (addr *IPv4AddrOption) Equal(b Option) bool {
	a, ok := b.(*IPv4AddrOption)
	if !ok {
		return false
	}
	return addr.Addr.Equal(a.Addr) && addr.AddrType == a.AddrType
}

// DefaultIPCPOwnRule is the default OwnOptionRule for the IPCP protocol,
// it implements OwnOptionRule interface
type DefaultIPCPOwnRule struct {
	Addr          net.IP
	DNS           net.IP
	SecondaryDNS  net.IP
	NBNS          net.IP
	SecondaryNBNS net.IP
	blacklist     Blacklist
	mux           sync.RWMutex
}

// GetOptions implements OwnOptionRule interface; a field will not be included as own option if it is nil
func (own *DefaultIPCPOwnRule) GetOptions() (r []Option) {
	own.mux.RLock()
	defer own.mux.RUnlock()
	if own.Addr != nil {
		r = append(r, &IPv4AddrOption{
			AddrType: OpIPAddress,
			Addr:     own.Addr,
		})
	}
	if own.DNS != nil {
		r = append(r, &IPv4AddrOption{
			AddrType: OpPrimaryDNSServerAddress,
			Addr:     own.DNS,
		})
	}
	if own.SecondaryDNS != nil {
		r = append(r, &IPv4AddrOption{
			AddrType: OpSecondaryDNSServerAddress,
			Addr:     own.SecondaryDNS,
		})
	}
	if own.NBNS != nil {
		r = append(r, &IPv4AddrOption{
			AddrType: OpPrimaryNBNSServerAddress,
			Addr:     own.NBNS,
		})
	}
	if own.SecondaryNBNS != nil {
		r = append(r, &IPv4AddrOption{
			AddrType: OpSecondaryNBNSServerAddress,
			Addr:     own.SecondaryNBNS,
		})
	}
	return r
}

// GetOption implements OwnOptionRule interface;
func (own *DefaultIPCPOwnRule) GetOption(o byte) Option {
	optType := IPCPOptionType(o)

	own.mux.RLock()
	defer own.mux.RUnlock()
	switch optType {
	case OpIPAddress:
		return &IPv4AddrOption{
			AddrType: optType,
			Addr:     own.Addr,
		}
	case OpPrimaryDNSServerAddress:
		return &IPv4AddrOption{
			AddrType: optType,
			Addr:     own.DNS,
		}
	case OpSecondaryDNSServerAddress:
		return &IPv4AddrOption{
			AddrType: optType,
			Addr:     own.SecondaryDNS,
		}
	case OpPrimaryNBNSServerAddress:
		return &IPv4AddrOption{
			AddrType: optType,
			Addr:     own.NBNS,
		}
	case OpSecondaryNBNSServerAddress:
		return &IPv4AddrOption{
			AddrType: optType,
			Addr:     own.SecondaryNBNS,
		}
	default:
		return nil
	}
}

// HandlerConfRej handles Conf reject packet.
// Option in conf-reject will not be included in next conf-req.
func (own *DefaultIPCPOwnRule) HandlerConfRej(received []Option) {
	own.mux.Lock()
	defer own.mux.Unlock()
	for _, o := range received {
		switch IPCPOptionType(o.Type()) {
		case OpIPAddress:
			own.Addr = nil
		case OpPrimaryDNSServerAddress:
			own.DNS = nil
		case OpSecondaryDNSServerAddress:
			own.SecondaryDNS = nil
		case OpPrimaryNBNSServerAddress:
			own.NBNS = nil
		case OpSecondaryNBNSServerAddress:
			own.SecondaryNBNS = nil
		}
	}
}

// HandlerConfNAK handles Conf nak packet.
// Option in conf-nak will be used as own value in next conf-req.
func (own *DefaultIPCPOwnRule) HandlerConfNAK(received []Option) error {
	own.mux.Lock()
	defer own.mux.Unlock()
	for _, o := range received {
		switch IPCPOptionType(o.Type()) {
		case OpIPAddress:
			own.Addr = o.(*IPv4AddrOption).Addr
			if ok := own.blacklist.IsValid(own.Addr); !ok {
				return errors.New("received blacklisted IP")
			}
		case OpPrimaryDNSServerAddress:
			own.DNS = o.(*IPv4AddrOption).Addr
		case OpSecondaryDNSServerAddress:
			own.SecondaryDNS = o.(*IPv4AddrOption).Addr
		case OpPrimaryNBNSServerAddress:
			own.NBNS = o.(*IPv4AddrOption).Addr
		case OpSecondaryNBNSServerAddress:
			own.SecondaryNBNS = o.(*IPv4AddrOption).Addr
		}
	}
	return nil
}

// NewDefaultIPCPOwnRule returns a new DefaultIPCPOwnRule,
// with all addresses set to 0.0.0.0
func NewDefaultIPCPOwnRule(blacklist Blacklist) *DefaultIPCPOwnRule {
	ip := net.ParseIP("0.0.0.0")
	return &DefaultIPCPOwnRule{
		Addr:          ip,
		DNS:           ip,
		SecondaryDNS:  ip,
		NBNS:          ip,
		SecondaryNBNS: ip,
		blacklist:     blacklist,
	}
}

// DefaultIPCPPeerRule is the default PeerOptionRule implementation.
// It ignores all peer options.
type DefaultIPCPPeerRule struct{}

// GetOptions always returns nil
func (peer *DefaultIPCPPeerRule) GetOptions() []Option {
	return nil
}

// HandlerConfReq will reject any options other than OpIPAddress, and ACK any OpIPAddress value;
func (peer *DefaultIPCPPeerRule) HandlerConfReq(received []Option) (nak, reject []Option) {
	for _, o := range received {
		switch IPCPOptionType(o.Type()) {
		case OpIPAddress:
		default:
			reject = append(reject, o)
		}
	}
	return nak, reject
}

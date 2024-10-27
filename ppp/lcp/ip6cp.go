package lcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

// IPv6LinkLocalPrefix is the IPv6 Link Local prefix
var IPv6LinkLocalPrefix = []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// InterfaceIDOption is the IPv6CP interface ID option
type InterfaceIDOption struct {
	interfaceID [8]byte
}

func (opt *InterfaceIDOption) Type() uint8 {
	return uint8(IP6CPOpInterfaceIdentifier)
}

func (opt *InterfaceIDOption) Serialize() ([]byte, error) {
	buf := make([]byte, 10)
	buf[0] = byte(IP6CPOpInterfaceIdentifier)
	buf[1] = byte(len(buf))
	copy(buf[2:], opt.interfaceID[:])
	return buf, nil
}

func (opt *InterfaceIDOption) Parse(buf []byte) (int, error) {
	if len(buf) < 10 {
		return 0, errors.New("not enough bytes")
	}
	if buf[1] != 10 {
		return 0, errors.New("len field is not 10")
	}
	copy(opt.interfaceID[:], buf[2:10])
	return 10, nil
}

func (opt *InterfaceIDOption) GetPayload() []byte {
	return opt.interfaceID[:]
}

func (opt *InterfaceIDOption) String() string {
	var s strings.Builder
	s.WriteString(IP6CPOpInterfaceIdentifier.String())
	s.WriteString(": ")
	for i := 0; i < 8; i += 2 {
		s.WriteString(fmt.Sprintf("%x%x", opt.interfaceID[i], opt.interfaceID[1+i]))
		if i < 6 {
			s.WriteByte(':')
		}
	}
	return s.String()
}

func (opt *InterfaceIDOption) Equal(b Option) bool {
	a, ok := b.(*InterfaceIDOption)
	if !ok {
		return false
	}
	return bytes.Equal(opt.interfaceID[:], a.interfaceID[:])
}

func (opt *InterfaceIDOption) parseUint64(v uint64) {
	binary.BigEndian.PutUint64(opt.interfaceID[:], v)
}

func (opt *InterfaceIDOption) toUint64() uint64 {
	return binary.BigEndian.Uint64(opt.interfaceID[:])
}

// DefaultIP6CPRule implements both OwnOptionRule and PeerOptionRule interface,
// negotiating only interface-id option.
type DefaultIP6CPRule struct {
	IfID          atomic.Uint64
	ifIDGenerator func() *InterfaceIDOption
}

// NewDefaultIP6CPRule returns a new DefaultIP6CPRule.
// It uses an interface-id option that is derived from MAC address.
func NewDefaultIP6CPRule(mac net.HardwareAddr) *DefaultIP6CPRule {
	r := &DefaultIP6CPRule{
		ifIDGenerator: genLCPInterfaceIDOptionByRFC7217(mac),
	}
	r.IfID.Store(r.ifIDGenerator().toUint64())
	return r
}

func genLCPInterfaceIDOptionByRFC7217(mac net.HardwareAddr) func() *InterfaceIDOption {
	const _rfc7217Key = "mysekey9823718dasdf902klsd"
	var counter atomic.Uint32

	return func() *InterfaceIDOption {
		// Use the current value, before the counter increase
		countValue := counter.Add(1)
		countValue++

		h := sha256.New()
		h.Write(IPv6LinkLocalPrefix)
		h.Write(mac)
		h.Write([]byte{uint8(countValue)})
		h.Write([]byte(_rfc7217Key))
		return &InterfaceIDOption{
			interfaceID: [8]byte(h.Sum(nil)[:8]),
		}
	}
}

// GetOptions implements OwnOptionRule interface, return own interface id
func (r *DefaultIP6CPRule) GetOptions() []Option {
	if r.IfID.Load() == 0 {
		return nil
	}
	opt := &InterfaceIDOption{}
	opt.parseUint64(r.IfID.Load())
	return []Option{opt}
}

// GetOption implements OwnOptionRule interface, return nil if t is not interface-id
func (r *DefaultIP6CPRule) GetOption(t uint8) Option {
	switch IPCP6OptionType(t) {
	case IP6CPOpInterfaceIdentifier:
		opt := &InterfaceIDOption{}
		opt.parseUint64(r.IfID.Load())
		return opt
	}
	return nil
}

// HandlerConfRej implements OwnOptionRule interface, if interface-id is rejected, then setting own interface-id to nil
func (r *DefaultIP6CPRule) HandlerConfRej(received []Option) {
	for _, opt := range received {
		if opt.Type() == uint8(IP6CPOpInterfaceIdentifier) {
			r.IfID.Store(0)
			break
		}
	}
}

// HandlerConfNAK implements OwnOptionRule interface, generate a new interface-id if interface-id is NAK-ed.
func (r *DefaultIP6CPRule) HandlerConfNAK(received []Option) {
	for _, opt := range received {
		if opt.Type() == uint8(IP6CPOpInterfaceIdentifier) {
			r.IfID.Store(r.ifIDGenerator().toUint64())
			break
		}
	}
}

// HandlerConfReq implements PeerOptionRule interface,
// section 4.1 of RFC5072 in terms of NAK or REJECT peer's interface-id.
func (r *DefaultIP6CPRule) HandlerConfReq(received []Option) (nak, reject []Option) {
	for _, o := range received {
		if o.Type() == uint8(IP6CPOpInterfaceIdentifier) {
			interfaceOpt, ok := o.(*InterfaceIDOption)
			if !ok {
				continue
			}

			optValue, currentIfIdValue := interfaceOpt.toUint64(), r.IfID.Load()
			if optValue == 0 && currentIfIdValue == 0 {
				reject = append(reject, o)
			} else if optValue == 0 || currentIfIdValue == 0 {
				newOption := &InterfaceIDOption{}
				newOption.parseUint64(currentIfIdValue)
				// Derive a new interface ID based on the original one,
				// using XOR with 0xFF
				newOption.interfaceID[7] = newOption.interfaceID[7] ^ 0xFF
				nak = append(nak, newOption)
			}
		}
	}

	return nak, reject
}

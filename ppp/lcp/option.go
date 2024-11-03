package lcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/gandalfast/souppp/ppp"
)

// Option is the LCP/IPCP/IPv6 option interface
type Option interface {
	// Type returns option type as uint8
	Type() uint8
	// Serialize option into bytes
	Serialize() ([]byte, error)
	// Parse buf into the option, return length of used bytes
	Parse(buf []byte) (int, error)
	// GetPayload returns payload bytes
	GetPayload() []byte
	// String returns a string representation of the option
	String() string
	// Equal returns true if b has same value and type
	Equal(b Option) bool
}

// OpMRU is the LCP MRU option
type OpMRU uint16

func (mru *OpMRU) Type() uint8 {
	return uint8(OpTypeMaximumReceiveUnit)
}

func (mru *OpMRU) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	buf[0] = byte(OpTypeMaximumReceiveUnit)
	buf[1] = byte(len(buf))
	binary.BigEndian.PutUint16(buf[2:4], uint16(*mru))
	return buf, nil
}

func (mru *OpMRU) Parse(buf []byte) (int, error) {
	if buf[0] != byte(OpTypeMaximumReceiveUnit) || buf[1] != 4 {
		return 0, fmt.Errorf("not a valid %v option", OpTypeMaximumReceiveUnit)
	}
	*mru = OpMRU(binary.BigEndian.Uint16(buf[2:4]))
	return 4, nil
}

func (mru *OpMRU) GetPayload() []byte {
	r := make([]byte, 2)
	binary.BigEndian.PutUint16(r, uint16(*mru))
	return r
}

func (mru *OpMRU) String() string {
	return fmt.Sprintf("%v:%d", OpTypeMaximumReceiveUnit, uint16(*mru))
}

func (mru *OpMRU) Equal(b Option) bool {
	p, ok := b.(*OpMRU)
	if !ok {
		return false
	}
	return *mru == *p
}

// OpAuthProto is the LCP auth protocol option
type OpAuthProto struct {
	Proto   ppp.ProtocolNumber
	CHAPAlg CHAPAuthAlg
	Payload []byte
}

// NewPAPAuthOp returns a new PAP OpAuthProto
func NewPAPAuthOp() *OpAuthProto {
	return &OpAuthProto{
		Proto: ppp.ProtoPAP,
	}
}

// NewCHAPAuthOp returns a new CHAP OpAuthProto with MD5
func NewCHAPAuthOp() *OpAuthProto {
	return &OpAuthProto{
		Proto:   ppp.ProtoCHAP,
		CHAPAlg: AlgCHAPwithMD5,
	}
}

func (auth *OpAuthProto) Type() uint8 {
	return uint8(OpTypeAuthenticationProtocol)
}

func (auth *OpAuthProto) Serialize() ([]byte, error) {
	if auth.Proto == ppp.ProtoNone {
		// no auth
		return nil, nil
	}
	if len(auth.Payload) > 251 {
		return nil, fmt.Errorf("payload of %v is too long", OpTypeAuthenticationProtocol)
	}

	buf := make([]byte, 4)
	buf[0] = byte(OpTypeAuthenticationProtocol)
	binary.BigEndian.PutUint16(buf[2:4], uint16(auth.Proto))

	switch auth.Proto {
	case ppp.ProtoCHAP:
		if auth.CHAPAlg != AlgNone {
			buf = append(buf, byte(auth.CHAPAlg))
			buf[1] = byte(len(buf))
			return buf, nil
		}
	case ppp.ProtoPAP:
		buf[1] = byte(len(buf))
		return buf, nil
	}

	buf[1] = byte(len(buf) + len(auth.Payload))
	return append(buf, auth.Payload...), nil
}

func (auth *OpAuthProto) Parse(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, errors.New("not enough bytes to parse an Auth-Protocol option")
	}
	if buf[0] != byte(OpTypeAuthenticationProtocol) {
		return 0, fmt.Errorf("not a valid %v option", OpTypeAuthenticationProtocol)
	}

	auth.Proto = ppp.ProtocolNumber(binary.BigEndian.Uint16(buf[2:4]))
	if buf[1] > 4 && auth.Proto == ppp.ProtoCHAP {
		auth.CHAPAlg = CHAPAuthAlg(buf[4])
	} else {
		auth.CHAPAlg = AlgNone
	}

	auth.Payload = buf[4:buf[1]]
	return int(buf[1]), nil
}

func (auth *OpAuthProto) GetPayload() []byte {
	return auth.Payload
}

func (auth *OpAuthProto) String() string {
	switch auth.Proto {
	case ppp.ProtoNone:
		return ""
	case ppp.ProtoCHAP:
		return fmt.Sprintf("%v:%v alg:%v", OpTypeAuthenticationProtocol, auth.Proto, auth.CHAPAlg)
	}
	return fmt.Sprintf("%v:%v (%d)", OpTypeAuthenticationProtocol, auth.Proto, len(auth.Payload))
}

func (auth *OpAuthProto) Equal(b Option) bool {
	a, ok := b.(*OpAuthProto)
	if !ok {
		return false
	}

	// Check if there is a different CHAP algorithm
	if auth.Proto == ppp.ProtoCHAP && auth.CHAPAlg != a.CHAPAlg {
		return false
	}

	return auth.Proto == a.Proto
}

// OpMagicNum is the LCP magic number option
type OpMagicNum uint32

func (mn *OpMagicNum) Type() uint8 {
	return uint8(OpTypeMagicNumber)
}

func (mn *OpMagicNum) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	buf[0] = byte(OpTypeMagicNumber)
	buf[1] = byte(len(buf))
	binary.BigEndian.PutUint32(buf[2:6], uint32(*mn))
	return buf, nil
}

func (mn *OpMagicNum) Parse(buf []byte) (int, error) {
	if buf[0] != byte(OpTypeMagicNumber) || buf[1] != 6 {
		return 0, fmt.Errorf("not a valid %v option", OpTypeMagicNumber)
	}
	*mn = OpMagicNum(binary.BigEndian.Uint32(buf[2:6]))
	return 6, nil
}

func (mn *OpMagicNum) GetPayload() []byte {
	r := make([]byte, 4)
	binary.BigEndian.PutUint32(r, uint32(*mn))
	return r
}

func (mn *OpMagicNum) String() string {
	return fmt.Sprintf("%v:%x", OpTypeMagicNumber, uint32(*mn))
}

func (mn *OpMagicNum) Equal(b Option) bool {
	a, ok := b.(*OpMagicNum)
	if !ok {
		return false
	}
	return *mn == *a
}

// GenericOption is a general LCP/IPCP/IPv6CP option that doesn't have
// any explicit mention in PPP protocol documentation.
type GenericOption struct {
	Code    uint8
	Proto   ppp.ProtocolNumber
	Payload []byte
}

func (gop *GenericOption) Type() uint8 {
	return gop.Code
}

func (gop *GenericOption) Serialize() ([]byte, error) {
	header := make([]byte, 2)
	header[0] = gop.Code
	if len(gop.Payload) > 253 {
		return nil, errors.New("option payload is too big")
	}
	header[1] = byte(len(header) + len(gop.Payload))
	return append(header, gop.Payload...), nil
}

func (gop *GenericOption) Parse(buf []byte) (int, error) {
	if len(buf) < 2 {
		return 0, errors.New("not enough bytes")
	}
	if buf[1] < 2 {
		return 0, errors.New("invalid length field")
	}
	gop.Code = buf[0]
	gop.Payload = buf[2:buf[1]]
	return int(buf[1]), nil
}

func (gop *GenericOption) GetPayload() []byte {
	return gop.Payload
}

func (gop *GenericOption) String() string {
	switch gop.Proto {
	case ppp.ProtoIPCP:
		return fmt.Sprintf("option %v: %v", IPCPOptionType(gop.Code), gop.Payload)
	case ppp.ProtoIPv6CP:
		return fmt.Sprintf("option %v: %v", IPCP6OptionType(gop.Code), gop.Payload)
	}
	return fmt.Sprintf("option %v: %v", OptionType(gop.Code), gop.Payload)
}

func (gop *GenericOption) Equal(b Option) bool {
	a, ok := b.(*GenericOption)
	if !ok {
		return false
	}
	if gop.Code != a.Code {
		return false
	}
	return bytes.Equal(gop.Payload, a.Payload)
}

func createOption(proto ppp.ProtocolNumber, b byte) Option {
	switch proto {
	case ppp.ProtoIPCP:
		switch IPCPOptionType(b) {
		case OpIPAddress, OpPrimaryDNSServerAddress, OpSecondaryDNSServerAddress,
			OpPrimaryNBNSServerAddress, OpSecondaryNBNSServerAddress:
			return new(IPv4AddrOption)
		default:
			return &GenericOption{
				Proto: ppp.ProtoIPCP,
			}
		}
	case ppp.ProtoIPv6CP:
		switch IPCP6OptionType(b) {
		case IP6CPOpInterfaceIdentifier:
			return new(InterfaceIDOption)
		default:
			return &GenericOption{
				Proto: ppp.ProtoIPv6CP,
			}
		}
	default:
		switch OptionType(b) {
		case OpTypeAuthenticationProtocol:
			return new(OpAuthProto)
		case OpTypeMagicNumber:
			return new(OpMagicNum)
		case OpTypeMaximumReceiveUnit:
			return new(OpMRU)
		default:
			return &GenericOption{
				Proto: ppp.ProtoLCP,
			}
		}
	}
}

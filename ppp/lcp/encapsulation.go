package lcp

import (
	"encoding/binary"
	"fmt"
	"github.com/gandalfast/zouppp/ppp"
	"strings"
)

// _maxOptions is the max number of options allowed in an LCP packet
const _maxOptions = 32

// Packet represents a LCP/IPCP/IPv6CP packet.
// It will be sent over PPP.
type Packet struct {
	// Proto is one of ProtoLCP, ProtoIPCP, ProtoIPv6CP
	Proto ppp.ProtocolNumber
	// Msg code
	Code MsgCode
	// Msg Id
	ID uint8
	// Msg length
	Len uint16
	// Magic Number if exists
	MagicNum uint32
	// Rejected protocol number, if exists
	RejectedProto ppp.ProtocolNumber
	// LCP allows multiple elements with the same type of option,
	// in the same order between request and response (requirement)
	Options []Option
	// Payload
	Payload []byte
}

func NewPacket(p ppp.ProtocolNumber) *Packet {
	return &Packet{
		Proto: p,
	}
}

func (p *Packet) Serialize() ([]byte, error) {
	header := make([]byte, 4)
	header[0] = uint8(p.Code)
	header[1] = p.ID

	payload := p.Payload
	for _, op := range p.Options {
		buf, err := op.Serialize()
		if err != nil {
			return nil, err
		}
		payload = append(payload, buf...)
	}

	// Echo packet includes the magic number
	var magicNumber []byte
	if p.Code == CodeEchoReply || p.Code == CodeEchoRequest {
		magicNumber = make([]byte, 4)
		binary.BigEndian.PutUint32(magicNumber, p.MagicNum)
	}

	length := len(header) + len(magicNumber) + len(payload)
	binary.BigEndian.PutUint16(header[2:4], uint16(length))
	return append(header, append(magicNumber, payload...)...), nil
}

func (p *Packet) Parse(buf []byte) error {
	if len(buf) < 4 {
		return fmt.Errorf("invalid PPP packet length %d", len(buf))
	}

	p.Code = MsgCode(buf[0])
	p.ID = buf[1]
	p.Len = binary.BigEndian.Uint16(buf[2:4])
	p.Payload = buf[4:p.Len]

	switch p.Code {
	case CodeConfigureRequest, CodeConfigureAck, CodeConfigureNak, CodeConfigureReject:
		if len(p.Payload) == 0 {
			return nil
		}

		offset := 0
		for i := 0; i < _maxOptions; i++ {
			op := createOption(p.Proto, p.Payload[offset])
			if op == nil {
				break
			}
			n, err := op.Parse(p.Payload[offset:])
			if err != nil {
				return fmt.Errorf("failed to parse LCP option #%d %v, %w", i+1, OptionType(p.Payload[offset]), err)
			}
			p.Options = append(p.Options, op)

			offset += n
			if offset >= len(p.Payload) {
				break
			}

			if i == _maxOptions-1 {
				return fmt.Errorf("invalid LCP packet, exceeded max number of options: %d", _maxOptions)
			}
		}
	case CodeEchoRequest, CodeEchoReply, CodeDiscardRequest:
		if len(buf) < 8 {
			return fmt.Errorf("not enough bytes for a LCP echo pkt, %v", buf)
		}
		p.MagicNum = binary.BigEndian.Uint32(buf[4:8])
		p.Payload = buf[8:]
	case CodeTerminateAck, CodeTerminateRequest, CodeCodeReject:
	case CodeProtocolReject:
		if len(buf) < 6 {
			return fmt.Errorf("not enough bytes for a LCP protocol reject pkt, %v", buf)
		}
		p.RejectedProto = ppp.ProtocolNumber(binary.BigEndian.Uint16(buf[4:6]))
	}
	return nil
}

// GetOption return a slice of options where the type is the same of optType.
func (p *Packet) GetOption(optType OptionType) (r []Option) {
	for _, o := range p.Options {
		if o.Type() == uint8(optType) {
			r = append(r, o)
		}
	}
	return r
}

func (p *Packet) String() string {
	var s strings.Builder
	s.WriteString(p.Proto.String())
	s.WriteString(" Code:")
	s.WriteString(p.Code.String())
	s.WriteString(fmt.Sprintf("\nID:%d\n", p.ID))
	s.WriteString(fmt.Sprintf("Len:%d\n", p.Len))
	s.WriteString("Options:\n")

	switch p.Code {
	case CodeEchoReply, CodeEchoRequest, CodeDiscardRequest:
		s.WriteString(fmt.Sprintf("Magic Number:%x\n", p.MagicNum))
	case CodeProtocolReject:
		s.WriteString("Rejected Protocol: ")
		s.WriteString(p.RejectedProto.String())
		s.WriteByte('\n')
	case CodeTerminateAck, CodeTerminateRequest:
		s.WriteString("Data: ")
		s.WriteString(string(p.Payload))
		s.WriteByte('\n')
	case CodeCodeReject:
	default:
		for _, op := range p.Options {
			s.WriteString(op.String())
			s.WriteByte('\n')
		}
	}

	return s.String()
}

// NewRejectPacket returns a new LCP over PPP packet to reject
// a specified packet with an invalid protocol.
func NewRejectPacket() func(b []byte) *ppp.Packet {
	reqID := uint8(0)
	return func(b []byte) *ppp.Packet {
		pkt := NewPacket(ppp.ProtoLCP)
		pkt.Code = CodeProtocolReject
		reqID++
		pkt.ID = reqID
		pkt.Payload = b
		return ppp.NewPacket(pkt, ppp.ProtoLCP)
	}
}

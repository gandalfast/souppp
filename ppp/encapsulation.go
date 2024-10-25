package ppp

import (
	"encoding/binary"
	"fmt"
)

// Packet represents PPP packet
type Packet struct {
	Proto   ProtocolNumber
	Payload Serializer
}

// Serialize into bytes, without copying, and no padding
func (pppPkt *Packet) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(pppPkt.Proto))
	body, err := pppPkt.Payload.Serialize()
	if err != nil {
		return nil, err
	}
	return append(buf, body...), nil
}

// Parse buf into PPPPacket
func (pppPkt *Packet) Parse(buf []byte) error {
	if len(buf) <= 2 {
		return fmt.Errorf("invalid PPP packet length %d", len(buf))
	}
	pppPkt.Proto = ProtocolNumber(binary.BigEndian.Uint16(buf[:2]))
	pppPkt.Payload = NewStaticSerializer(buf[2:])
	return nil
}

// NewPacket return a new PPP packet with protocol number and payload
func NewPacket(data Serializer, proto ProtocolNumber) *Packet {
	return &Packet{
		Proto:   proto,
		Payload: data,
	}
}

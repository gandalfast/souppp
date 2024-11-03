package pppoe

import (
	"encoding/binary"
	"fmt"
)

// _maxTags is the max number of tags allowed in a PPPoE packet
const _maxTags = 32

// First byte of the PPPoE packet
const _pppoeVersionType byte = 0x11

// Packet represents a PPPoE packet
type Packet struct {
	VersionType byte
	Code        Code
	SessionID   uint16
	Len         uint16
	Payload     []byte
	Tags        []Tag
}

// Parse bytes into packet
func (pkt *Packet) Parse(buf []byte) error {
	if len(buf) < 6 {
		return fmt.Errorf("invalid PPPoE packet length %d", len(buf))
	}

	pkt.VersionType = buf[0]
	if pkt.VersionType != _pppoeVersionType {
		return fmt.Errorf("invalid PPPoE version type, should be 0x11, got 0x%X ", pkt.VersionType)
	}
	pkt.Code = Code(buf[1])
	pkt.SessionID = binary.BigEndian.Uint16(buf[2:4])
	pkt.Len = binary.BigEndian.Uint16(buf[4:6])
	payload := buf[6 : 6+pkt.Len]

	if pkt.Code == CodeSession {
		// no parsing of tag for session pkt
		pkt.Payload = payload
		return nil
	}

	offset := 0
	for i := 0; i < _maxTags; i++ {
		tag := createTag(TagType(binary.BigEndian.Uint16(payload[offset : offset+2])))
		n, err := tag.Parse(payload[offset:])
		if err != nil {
			return fmt.Errorf("failed to parse PPPoE tag,%w", err)
		}
		offset += n
		pkt.Tags = append(pkt.Tags, tag)
		if offset >= len(payload) {
			// Finished tag parsing
			break
		}

		// Reached maximum tags but there are others to parse
		if i == _maxTags-1 {
			return fmt.Errorf("invalid PPPoE packet, exceeded max number of tags: %d", _maxTags)
		}
	}
	return nil
}

// Serialize packet into bytes
func (pkt *Packet) Serialize() ([]byte, error) {
	payload := pkt.Payload

	// Serialize tags into Payload when this isn't a Session packet
	if pkt.Code != CodeSession {
		if len(payload) > 0 {
			return nil, fmt.Errorf("invalid PPPoE payload length %d, expected 0", len(payload))
		}
		for _, tag := range pkt.Tags {
			buf, err := tag.Serialize()
			if err != nil {
				return nil, err
			}
			payload = append(payload, buf...)
		}
	}

	header := make([]byte, 6)
	header[0] = _pppoeVersionType
	header[1] = byte(pkt.Code)
	binary.BigEndian.PutUint16(header[2:4], pkt.SessionID)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(payload)))
	return append(header, payload...), nil
}

// GetTag return a slice of tags of type t
func (pkt *Packet) GetTag(t TagType) (r []Tag) {
	for _, tag := range pkt.Tags {
		if tag.Type() == uint16(t) {
			r = append(r, tag)
		}
	}
	return r
}

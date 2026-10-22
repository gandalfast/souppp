package chap

import (
	"encoding/binary"
)

// Packet represents a CHAP packet
type Packet struct {
	Code   Code
	ID     uint8
	Len    uint16
	ValLen uint8
	Value  []byte
	Name   []byte
	Msg    []byte
}

// Parse buf into cp
func (cp *Packet) Parse(buf []byte) error {
	if len(buf) < 4 {
		return InvalidPacketLengthError{
			length: len(buf),
		}
	}

	cp.Code = Code(buf[0])
	cp.ID = buf[1]
	cp.Len = binary.BigEndian.Uint16(buf[2:4])

	// The length field covers the header; it cannot exceed the bytes read.
	if cp.Len < 4 || int(cp.Len) > len(buf) {
		return InvalidPacketLengthError{
			length: int(cp.Len),
		}
	}
	buf = buf[:cp.Len]

	switch cp.Code {
	case CodeChallenge, CodeResponse:
		if cp.Len < 5 {
			return InvalidChallengeLengthError{
				length: int(cp.Len),
			}
		}
		// The value follows its 1-byte size; the name fills the rest.
		cp.ValLen = buf[4]
		if int(cp.Len) < 5+int(cp.ValLen) {
			return InvalidChallengeLengthError{
				length: int(cp.ValLen),
			}
		}
		cp.Value = buf[5 : 5+cp.ValLen]
		cp.Name = buf[5+cp.ValLen:]
	default:
		cp.Msg = buf[4:]
	}

	return nil
}

// Serialize cp into byte slice
func (cp *Packet) Serialize() ([]byte, error) {
	// CODE | ID | LEN | LEN
	buf := []byte{byte(cp.Code), cp.ID, 0x00, 0x00}

	switch cp.Code {
	case CodeChallenge, CodeResponse:
		if len(cp.Value) > 255 {
			return nil, InvalidChallengeLengthError{
				length: len(cp.Value),
			}
		}
		buf = append(buf, byte(len(cp.Value)))
		buf = append(buf, cp.Value...)
		buf = append(buf, cp.Name...)
	}

	length := len(buf)
	if length > 65535 {
		return nil, InvalidPacketLengthError{
			length: length,
		}
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	return buf, nil
}

package pap

import (
	"encoding/binary"
)

// Packet represents a PAP packet
type Packet struct {
	Code     Code
	ID       uint8
	Len      uint16
	PeerID   []byte
	Password []byte
	Msg      []byte
}

// Parse buf into pp
func (pp *Packet) Parse(buf []byte) error {
	if len(buf) < 4 {
		return InvalidPacketLengthError{
			length: len(buf),
		}
	}

	pp.Code = Code(buf[0])
	pp.ID = buf[1]
	pp.Len = binary.BigEndian.Uint16(buf[2:4])

	switch pp.Code {
	case CodeAuthRequest:
		if pp.Len < 6 {
			return InvalidAuthLengthError{
				length: int(pp.Len),
			}
		}
		if buf[4] == 0 || buf[4] > 249 {
			return InvalidPeerIDLengthError{
				length: int(buf[4]),
			}
		}
		pp.PeerID = buf[5 : 5+buf[4]]
		if buf[5+buf[4]] == 0 || buf[5+buf[4]] > 249 {
			return InvalidPasswordLengthError{
				length: int(buf[5+buf[4]]),
			}
		}
		pp.Password = buf[6+buf[4]:]
	default:
		if buf[4] > 250 {
			return InvalidMessageLengthError{
				length: int(buf[4]),
			}
		}
		pp.Msg = buf[5:]
	}
	return nil
}

// Serialize pp to byte slice
func (pp *Packet) Serialize() ([]byte, error) {
	// CODE | ID | LEN | LEN
	buf := []byte{byte(pp.Code), pp.ID, 0x00, 0x00}

	switch pp.Code {
	case CodeAuthRequest:
		if len(pp.PeerID) > 249 || len(pp.PeerID) == 0 {
			return nil, InvalidPeerIDLengthError{
				length: len(pp.PeerID),
			}
		}
		if len(pp.Password) > 249 {
			return nil, InvalidPasswordLengthError{
				length: len(pp.Password),
			}
		}
		buf = append(buf, byte(len(pp.PeerID)))
		buf = append(buf, pp.PeerID...)
		buf = append(buf, byte(len(pp.Password)))
		buf = append(buf, pp.Password...)
	default:
		if len(pp.Msg) > 250 {
			return nil, InvalidMessageLengthError{
				length: len(pp.Msg),
			}
		}
		buf = append(buf, byte(len(pp.Msg)))
		buf = append(buf, pp.Msg...)
	}

	if len(buf) > 65535 {
		return nil, InvalidPacketLengthError{
			length: len(buf),
		}
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	return buf, nil
}

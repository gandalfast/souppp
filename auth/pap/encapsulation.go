package pap

import "encoding/binary"

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

	// The length field covers the header; it cannot exceed the bytes read.
	if pp.Len < 4 || int(pp.Len) > len(buf) {
		return InvalidPacketLengthError{
			length: int(pp.Len),
		}
	}
	buf = buf[:pp.Len]

	switch pp.Code {
	case CodeAuthRequest:
		// Peer id and password each follow their 1-byte size.
		if pp.Len < 6 {
			return InvalidAuthLengthError{
				length: int(pp.Len),
			}
		}
		peerIDLen := int(buf[4])
		if peerIDLen == 0 || peerIDLen > 249 {
			return InvalidPeerIDLengthError{
				length: peerIDLen,
			}
		}
		if 5+peerIDLen+1 > len(buf) {
			return InvalidAuthLengthError{
				length: len(buf),
			}
		}
		pp.PeerID = buf[5 : 5+peerIDLen]
		passwordLen := int(buf[5+peerIDLen])
		if passwordLen == 0 || passwordLen > 249 || 6+peerIDLen+passwordLen > len(buf) {
			return InvalidPasswordLengthError{
				length: passwordLen,
			}
		}
		pp.Password = buf[6+peerIDLen : 6+peerIDLen+passwordLen]
	default:
		// The message follows its 1-byte size.
		if len(buf) < 5 {
			return InvalidMessageLengthError{
				length: len(buf) - 4,
			}
		}
		msgLen := int(buf[4])
		if msgLen > 250 || 5+msgLen > len(buf) {
			return InvalidMessageLengthError{
				length: msgLen,
			}
		}
		pp.Msg = buf[5 : 5+msgLen]
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

	length := len(buf)
	if length > 65535 {
		return nil, InvalidPacketLengthError{
			length: length,
		}
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	return buf, nil
}

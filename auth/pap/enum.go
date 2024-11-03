package pap

import "fmt"

type Code uint8

// List of PAP codes
const (
	CodeAuthRequest Code = 1
	CodeAuthACK     Code = 2
	CodeAuthNAK     Code = 3
)

func (c Code) String() string {
	switch c {
	case CodeAuthRequest:
		return "Auth-Request"
	case CodeAuthACK:
		return "Auth-ACK"
	case CodeAuthNAK:
		return "Auth-NAK"
	}
	return fmt.Sprintf("unknown (%d)", c)
}

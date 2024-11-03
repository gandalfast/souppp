package chap

import "fmt"

type Code uint8

// List of CHAP codes
const (
	CodeChallenge Code = 1
	CodeResponse  Code = 2
	CodeSuccess   Code = 3
	CodeFailure   Code = 4
)

func (c Code) String() string {
	switch c {
	case CodeChallenge:
		return "Challenge"
	case CodeResponse:
		return "Response"
	case CodeSuccess:
		return "Success"
	case CodeFailure:
		return "Failure"
	default:
		return fmt.Sprintf("unknown (%d)", uint8(c))
	}
}

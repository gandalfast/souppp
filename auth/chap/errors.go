package chap

import (
	"errors"
	"fmt"
)

var (
	AuthenticationFailed  = errors.New("auth failed")
	AuthenticationTimeout = errors.New("CHAP timeout")
	GatewayFailed         = errors.New("gateway failed")
)

type InvalidPacketLengthError struct {
	length int
}

func (e InvalidPacketLengthError) Error() string {
	return fmt.Sprintf("invalid CHAP packet length: %d", e.length)
}

type InvalidChallengeLengthError struct {
	length int
}

func (e InvalidChallengeLengthError) Error() string {
	return fmt.Sprintf("invalid CHAP challenge length: %d", e.length)
}

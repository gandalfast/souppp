package pap

import (
	"errors"
	"fmt"
)

var (
	AuthenticationFailed  = errors.New("auth failed")
	AuthenticationTimeout = errors.New("PAP timeout")
)

type InvalidPacketLengthError struct {
	length int
}

func (e InvalidPacketLengthError) Error() string {
	return fmt.Sprintf("invalid PAP packet length: %d", e.length)
}

type InvalidMessageLengthError struct {
	length int
}

func (e InvalidMessageLengthError) Error() string {
	return fmt.Sprintf("invalid PAP Msg length: %d", e.length)
}

type InvalidAuthLengthError struct {
	length int
}

func (e InvalidAuthLengthError) Error() string {
	return fmt.Sprintf("invalid PAP Auth request length: %d", e.length)
}

type InvalidPeerIDLengthError struct {
	length int
}

func (e InvalidPeerIDLengthError) Error() string {
	return fmt.Sprintf("invalid PAP Peer ID length: %d", e.length)
}

type InvalidPasswordLengthError struct {
	length int
}

func (e InvalidPasswordLengthError) Error() string {
	return fmt.Sprintf("invalid PAP Password length: %d", e.length)
}

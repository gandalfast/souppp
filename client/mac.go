package client

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
)

const (
	// Maximum bytes for a MAC Address
	_macMaxBytes = 6
	// Maximum value for a MAC Address
	_maximumMacAddr = (1 << (_macMaxBytes * 8)) - 1
)

// incrementMACAddress increment MAC address value by step value (can be negative), and return the result
func incrementMACAddress(macaddr net.HardwareAddr, step int64) (net.HardwareAddr, error) {
	length := len(macaddr)
	if length > _macMaxBytes {
		return nil, fmt.Errorf("MAC length is too large: %d > 6", length)
	}

	buf := make([]byte, 8)
	copy(buf[len(buf)-length:], macaddr)
	macAddrValue := binary.BigEndian.Uint64(buf)

	// Since MAC address is maximum 6 bytes long and an uint64 is 8,
	// first byte is always 0 and the integer is positive
	macAddrNewValue := int64(macAddrValue) + step

	if macAddrNewValue < 0 {
		return nil, fmt.Errorf("%v and step %d result in negative result", macaddr, step)
	} else if macAddrNewValue > _maximumMacAddr {
		return nil, fmt.Errorf("%v and step %d result exceeds FF:FF:FF:FF:FF:FF", macaddr, step)
	}

	newValueU64 := uint64(macAddrNewValue)
	binary.BigEndian.PutUint64(buf, newValueU64)

	// Get the bytes length of the new address
	bitsNum := bits.Len64(uint64(macAddrNewValue))
	newLength := bitsNum / 8
	if bitsNum%8 != 0 {
		newLength++
	}

	// Return the bytes for the increased MAC address
	return buf[len(buf)-newLength:], nil
}

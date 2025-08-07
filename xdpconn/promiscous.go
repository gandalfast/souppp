package xdpconn

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
)

// setPromiscuousMode put the interface in promiscuous mode, allowing us to receive
// Ethernet frames also when the destination address is different from the one of our
// network card, allowing us to obtain multiple MAC addresses.
func setPromiscuousMode(interfaceName string) error {
	target, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("couldn't query interface %s: %s", interfaceName, err)
	}

	// Convert uint16 to Big Endian
	protoBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(protoBuf, unix.ETH_P_ALL)
	convertedProto := binary.BigEndian.Uint16(protoBuf)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(convertedProto))
	if err != nil {
		return fmt.Errorf("couldn't open packet socket: %w", err)
	}

	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
		Ifindex: int32(target.Index),
		Type:    unix.PACKET_MR_PROMISC,
	})
}

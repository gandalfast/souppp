package ethernetconn

import "net"

func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

func pseudoHeaderChecksumV6(sourceIP, destIP *net.UDPAddr) (csum uint32) {
	srcIP := sourceIP.IP.To16()[:16]
	dstIP := destIP.IP.To16()[:16]
	for i := 0; i < 16; i += 2 {
		csum += uint32(srcIP[i]) << 8
		csum += uint32(srcIP[i+1])
		csum += uint32(dstIP[i]) << 8
		csum += uint32(dstIP[i+1])
	}
	return csum
}

func v6udpChecksum(headerAndPayload []byte, sourceIP, destIP *net.UDPAddr) uint16 {
	length := uint32(len(headerAndPayload))
	csum := pseudoHeaderChecksumV6(sourceIP, destIP)
	csum += uint32(17)
	csum += length & 0xffff
	csum += length >> 16
	return tcpipChecksum(headerAndPayload, csum)
}

func ipv4Checksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}

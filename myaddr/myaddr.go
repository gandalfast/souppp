// Copyright 2020 Hu Jun. All rights reserved.
// This project is licensed under the terms of the MIT license.
// license that can be found in the LICENSE file.

/*
Package myaddr is Go module that provides varies functions to processing address,
include IP address, MAC address and VLAN ID.
*/
package myaddr

import (
	"fmt"
	"math/big"
	"net"
)

// HWAddrtoBig convert hardware address to *big.Int
func HWAddrtoBig(addr net.HardwareAddr) *big.Int {
	r := new(big.Int)
	r.SetBytes(addr)
	return r
}

// BigtoHWAddr convert n to a hardware address, with specified alen
func BigtoHWAddr(n *big.Int, alen int) (net.HardwareAddr, error) {
	buf := n.Bytes()
	var delta int
	delta = alen - len(buf)
	if delta < 0 {
		return nil, fmt.Errorf("%v is too big for %d byte slice", n, alen)
	}
	rbuf := make([]byte, alen)
	copy(rbuf[delta:], buf)
	return rbuf, nil
}

// BigtoMACAddr convert n to a MAC address
func BigtoMACAddr(n *big.Int) (net.HardwareAddr, error) {
	return BigtoHWAddr(n, 6)
}

// AddrtoBig convert IP address to *big.Int
func AddrtoBig(addr net.IP) *big.Int {
	r := new(big.Int)
	if addr.To4() != nil {
		r.SetBytes(addr.To4()[:4])
	} else {
		r.SetBytes(addr.To16()[:16])
	}
	return r
}

// BigtoAddr convert n to IPv4 address if ipv4 is true, IPv6 address otherwise
func BigtoAddr(n *big.Int, ipv4 bool) (net.IP, error) {
	buf := n.Bytes()
	var alen = 4
	var delta int
	if ipv4 {
		delta = 4 - len(buf)
		if delta < 0 {
			//this should be an IPv6 address
			return nil, fmt.Errorf("%v is too big for an IPv4 address", n)
		}
	} else {
		delta = 16 - len(buf)
		if delta < 0 {
			return nil, fmt.Errorf("%v is too big for an IPv6 address", n)
		}
		alen = 16
	}
	rbuf := make([]byte, alen)
	copy(rbuf[delta:], buf)
	return rbuf, nil
}

// MAX Values
const (
	MaxIPv4AddrN   = 4294967295
	MaxMACAddrN    = 281474976710655
	MaxIPv6AddrStr = "340282366920938463463374607431768211455"
)

// IncMACAddr increase macaddr by step (could be negative), return the result
func IncMACAddr(macaddr net.HardwareAddr, step *big.Int) (net.HardwareAddr, error) {
	rn := big.NewInt(0).Add(HWAddrtoBig(macaddr), step)
	if rn.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("%v and step %d result in negative result", macaddr, step)
	}

	if rn.Cmp(big.NewInt(MaxMACAddrN)) == 1 {
		return nil, fmt.Errorf("%v and step %d result exceeds FF:FF:FF:FF:FF:FF", macaddr, step)
	}
	return BigtoMACAddr(rn)
}

// IncAddr increase addr by step (could be negative), return the result
func IncAddr(addr net.IP, step *big.Int) (net.IP, error) {
	rn := big.NewInt(0).Add(AddrtoBig(addr), step)
	if rn.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("%v and step %d result in negative result", addr, step)
	}
	if addr.To4() != nil {
		//ipv4
		if rn.Cmp(big.NewInt(MaxIPv4AddrN)) == 1 {
			return nil, fmt.Errorf("%v and step %d result exceeds 255.255.255.255", addr, step)
		}
		return BigtoAddr(rn, true)
	}
	//ipv6
	maxv6addr, _ := big.NewInt(0).SetString(MaxIPv6AddrStr, 0)
	if rn.Cmp(maxv6addr) == 1 {
		return nil, fmt.Errorf("%v and step %d result exceeds FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", addr, step)
	}
	return BigtoAddr(rn, false)
}

// GenAddrWithPrefix geneate an address = prefix + hostn.
// hostn must>=0
func GenAddrWithPrefix(prefix *net.IPNet, hostn *big.Int) (net.IP, error) {
	if hostn.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("%v is negative", hostn)
	}
	maskbits, totalmaskbits := prefix.Mask.Size()
	deltan := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(totalmaskbits-maskbits)), big.NewInt(0))
	if hostn.Cmp(deltan) >= 0 {
		return nil, fmt.Errorf("%v exceeds max allowed host value for prefix %v", hostn, prefix)
	}
	return IncAddr(prefix.IP, hostn)
}

// GenConnectionAddrStr return a string with following format:
// IPv4: <prefix><ip>:<port>
// IPv6: <prefix>[<ip>]:<port>
func GenConnectionAddrStr(prefix string, ip net.IP, port int) string {
	if ip.To4() != nil {
		return fmt.Sprintf("%v%v:%v", prefix, ip, port)
	}
	return fmt.Sprintf("%v[%v]:%v", prefix, ip, port)
}

// IncreaseVLANIDs increase a slice of VLAN Id (12 bit long) with specified step
func IncreaseVLANIDs(ids []uint16, step int) ([]uint16, error) {
	if len(ids) == 0 {
		return ids, nil
	}
	bigstr := ""
	for i := 0; i < len(ids); i++ {
		if ids[i] > 0xfff {
			return []uint16{}, fmt.Errorf("invalid VLAN id %d", ids[i])
		}
		s := big.NewInt(int64(ids[i])).Text(16)
		for i := 0; i < len(s)%3; i++ {
			s = "0" + s
		}
		bigstr += s
	}
	all := big.NewInt(0)
	if _, ok := all.SetString(bigstr, 16); !ok {
		return []uint16{}, fmt.Errorf("failed to increase, possible invaliud VLAN IDs %v", ids)
	}
	all.Add(all, big.NewInt(int64(step)))
	newbigstr := all.Text(16)
	for i := 0; i < len(newbigstr)%3; i++ {
		newbigstr = "0" + newbigstr
	}
	r := []uint16{}
	for i := 0; i < len(newbigstr); i += 3 {
		newv := big.NewInt(0)
		if _, ok := newv.SetString(newbigstr[i:i+3], 16); !ok {
			return []uint16{}, fmt.Errorf("failed conver a hex str to int, %v", newbigstr[i:i+3])
		}
		r = append(r, uint16(newv.Int64()))
	}
	return r, nil
}

// GetLLAFromMac return an IPv6 link local address from mac,
// based on Appendix A of RFC4291
func GetLLAFromMac(mac net.HardwareAddr) net.IP {
	var ifid [8]byte
	ifid[0] = mac[0] ^ 0b00000010
	copy(ifid[1:3], mac[1:3])
	copy(ifid[3:5], []byte{0xff, 0xfe})
	copy(ifid[5:], mac[3:6])
	return append([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0}, ifid[:]...)
}

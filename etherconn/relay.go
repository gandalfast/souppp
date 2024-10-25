package etherconn

import (
	"encoding/binary"
	"fmt"
	"log"
)

type RelayType string

const (
	RelayTypeXDP RelayType = "xdp"
	UnknownRelay RelayType = "unknown"
)

type LogFunc func(fmt string, a ...interface{})

func checkPacketBytes(p []byte) error {
	if len(p) < 14 {
		return fmt.Errorf("ethernet frame size is smaller than 14B")
	}
	return nil
}

func sendToChanWithCounter(receival *RelayReceival, ch chan *RelayReceival) {
	fullcounted := false
	if len(receival.EtherPayloadBytes) == 0 {
		return
	}
	for { //keep sending until pkt is sent to channel
		select {
		case ch <- receival:
			return
		default:
			<-ch //channel is full, remove the oldest pkt in channel
			if !fullcounted {
				log.Printf("recv chan has cap of %d and len %d\n", cap(ch), len(ch))
				fullcounted = true
			}
		}
	}
}

// getReceivalFromRcvPkt parse received ethernet pkt, p is a ethernet packet in byte slice,
func getReceivalFromRcvPkt(p []byte, auxdata []interface{}, relayType RelayType) *RelayReceival {
	// l2ep := newL2Endpoint()
	rcv := newRelayReceival()
	rcv.LocalEndpoint = newL2Endpoint()
	rcv.RemoteEndpoint = newL2Endpoint()
	rcv.EtherBytes = p
	copy(rcv.LocalEndpoint.HwAddr, p[:6])    //dst mac
	copy(rcv.RemoteEndpoint.HwAddr, p[6:12]) //src mac
	index := 12
	for {
		etype := binary.BigEndian.Uint16(p[index : index+2])
		if etype != 0x8100 && etype != 0x88a8 {
			rcv.LocalEndpoint.Etype = etype
			break
		}
		index += 4
	}
	rcv.EtherPayloadBytes = p[index+2:]

	var l4index int
	switch rcv.LocalEndpoint.Etype {
	case 0x0800: //ipv4
		rcv.RemoteIP = rcv.EtherPayloadBytes[12:16]
		rcv.LocalIP = rcv.EtherPayloadBytes[16:20]
		rcv.Protocol = rcv.EtherPayloadBytes[9]
		l4index = 20 //NOTE: this means no supporting of any ipv4 options
	case 0x86dd: //ipv6
		rcv.Protocol = rcv.EtherPayloadBytes[6]
		rcv.RemoteIP = rcv.EtherPayloadBytes[8:24]
		rcv.LocalIP = rcv.EtherPayloadBytes[24:40]
		l4index = 40 //NOTE: this means no supporting of any ipv6 options
	}

	switch rcv.Protocol {
	case 17: //udp
		rcv.RemotePort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index : l4index+2])
		rcv.LocalPort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index+2 : l4index+4])
		rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+8:]
	}
	rcv.RemoteEndpoint.Etype = rcv.LocalEndpoint.Etype
	return rcv
}

// handleRcvPkt is the function handle the received pkt from underlying socket, it is shared code for both RawPacketRelay and XDPPacketRelay
func handleRcvPkt(relayType RelayType, pktData []byte,
	logf LogFunc, recvList *ChanMap, mirrorToDefault bool,
	defaultRecvChan chan *RelayReceival, multicastList *ChanMap,
	ancData []interface{},
) {
	if checkPacketBytes(pktData) != nil {
		return
	}

	// var rmac net.HardwareAddr
	recvial := getReceivalFromRcvPkt(pktData, ancData, relayType)
	if logf != nil {
		logf("got pkt with l2epkey %v", recvial.LocalEndpoint.GetKey().String())
	}
	if rcvchan := recvList.Get(recvial.LocalEndpoint.GetKey()); rcvchan != nil {
		// found match etherconn
		//NOTE: create go routine here since sendToChanWithCounter will parse the pkt, need some CPU
		//NOTE2: update @ 10/15/2021, remove creating go routine, since it will create out-of-order issue
		sendToChanWithCounter(recvial, rcvchan)
		if mirrorToDefault && defaultRecvChan != nil {
			sendToChanWithCounter(recvial, defaultRecvChan)
		}
	} else {
		//TODO: could use an optimization here, where parsing only done once iso calling sendToChanWithCounter multiple times
		if recvial.LocalEndpoint.HwAddr[0]&0x1 == 1 { //multicast traffic
			mList := multicastList.GetList()
			zeroMList := false
			if len(mList) > 0 {
				for _, mrcvchan := range mList {
					recvial.EtherBytes = pktData
					//TODO: might need also a new gpacket here
					sendToChanWithCounter(recvial, mrcvchan)
				}
			} else {
				zeroMList = true
			}
			if defaultRecvChan != nil {
				sendToChanWithCounter(recvial, defaultRecvChan)
			} else {
				if zeroMList {
					if logf != nil {
						logf("ignored a multicast pkt")
					}
				}
			}
		} else { //unicast but can't find reciver
			if defaultRecvChan != nil {
				sendToChanWithCounter(recvial, defaultRecvChan)
			} else {
				if logf != nil {
					logf(fmt.Sprintf("can't find match l2ep %v", recvial.LocalEndpoint.GetKey().String()))
				}
			}
		}
	}
}

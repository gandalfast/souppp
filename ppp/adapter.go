package ppp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/gandalfast/souppp/etherconn"
	"net"
	"sync"
	"time"
)

// ConnAdapter wraps a PPP connection into the etherconn.SharedEthernetConn interface.
type ConnAdapter struct {
	ppp               *PPP
	proto             ProtocolNumber
	send, recv        chan []byte
	recvList          map[etherconn.L4HashKey]chan *etherconn.EthernetResponse
	recvListMtx       sync.RWMutex
	writeDeadline     time.Time
	writeDeadlineLock sync.RWMutex
}

const _defaultPerClntRecvChanDepth = 128

func NewConnAdapter(ppp *PPP, proto ProtocolNumber) *ConnAdapter {
	r := new(ConnAdapter)
	r.ppp = ppp // PPP session must be already started with Start()
	r.proto = proto
	r.send, r.recv = ppp.Register(proto)
	r.recvList = make(map[etherconn.L4HashKey]chan *etherconn.EthernetResponse)
	return r
}

func (c *ConnAdapter) Start(ctx context.Context) {
	go c.receiveHandling()
}

func (c *ConnAdapter) Register(k etherconn.L4HashKey) (torecvch chan *etherconn.EthernetResponse) {
	ch := make(chan *etherconn.EthernetResponse, _defaultPerClntRecvChanDepth)
	c.recvListMtx.Lock()
	if old, ok := c.recvList[k]; ok {
		close(old)
	}
	c.recvList[k] = ch
	c.recvListMtx.Unlock()
	return ch
}

func (c *ConnAdapter) Unregister(k etherconn.L4HashKey) {
	c.recvListMtx.Lock()
	if old, ok := c.recvList[k]; ok {
		close(old)
		delete(c.recvList, k)
	}
	c.recvListMtx.Unlock()
}

// WriteIPPktTo implements etherconn.SharedEthernetConn interface. dstmac is not used at all.
func (c *ConnAdapter) WriteIPPktTo(p []byte, _ net.HardwareAddr) (int, error) {
	c.writeDeadlineLock.RLock()
	deadline := c.writeDeadline
	c.writeDeadlineLock.RUnlock()

	proto := make([]byte, 2)
	switch p[0] >> 4 {
	case 4:
		binary.BigEndian.PutUint16(proto, uint16(ProtoIPv4))
	case 6:
		binary.BigEndian.PutUint16(proto, uint16(ProtoIPv6))
	default:
		return 0, fmt.Errorf("not an IP packet")
	}

	buf := make([]byte, len(p)+2)
	copy(buf[:2], proto)
	copy(buf[2:], p)

	ctx := context.Background()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel()
	}

	select {
	case <-ctx.Done():
		return 0, etherconn.ErrTimeOut
	case c.send <- buf:
		return len(p), nil
	}
}

// SetWriteDeadline sets deadline for WriteIPPktTo
func (c *ConnAdapter) SetWriteDeadline(t time.Time) error {
	c.writeDeadlineLock.Lock()
	c.writeDeadline = t
	c.writeDeadlineLock.Unlock()
	return nil
}

func (c *ConnAdapter) Close() error {
	c.ppp.Unregister(c.proto)

	c.recvListMtx.Lock()
	for key, ch := range c.recvList {
		close(ch)
		delete(c.recvList, key)
	}
	c.recvListMtx.Unlock()
	return nil
}

func (c *ConnAdapter) receiveHandling() {
	for {
		select {
		case buf, ok := <-c.recv:
			if !ok {
				return
			}

			received, err := parsePacketIP(buf)
			if err != nil {
				continue
			}

			ch, ok := c.recvList[etherconn.NewL4HashKeyWithEthernet(received)]
			if !ok {
				continue
			}

			// Found registered channel
			finished := false
			for !finished {
				select {
				case ch <- received:
					finished = true
				default:
					// channel is full, remove oldest packet
					<-ch
				}
			}
		}
	}
}

func parsePacketIP(pkt []byte) (*etherconn.EthernetResponse, error) {
	if len(pkt) < MinimumFrameSize {
		return nil, fmt.Errorf("pkt smaller than 20 bytes")
	}

	rcv := &etherconn.EthernetResponse{
		EtherPayloadBytes: pkt,
	}

	// Parse IP packet header
	var l4index int
	switch pkt[0] >> 4 {
	case 4: // IPv4
		rcv.RemoteIP = rcv.EtherPayloadBytes[12:16]
		rcv.LocalIP = rcv.EtherPayloadBytes[16:20]
		rcv.Protocol = rcv.EtherPayloadBytes[9]
		l4index = 20 //NOTE: this means no supporting of any ipv4 options
	case 6: // IPv6
		rcv.Protocol = rcv.EtherPayloadBytes[6]
		rcv.RemoteIP = rcv.EtherPayloadBytes[8:24]
		rcv.LocalIP = rcv.EtherPayloadBytes[24:40]
		l4index = 40 //NOTE: this means no supporting of any ipv6 options
	default:
		return nil, errors.New("not an IP packet")
	}

	switch rcv.Protocol {
	case 17: // UDP
		rcv.RemotePort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index : l4index+2])
		rcv.LocalPort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index+2 : l4index+4])
		rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+8:]
	case 58: // ICMPv6
		rcv.RemotePort = uint16(rcv.EtherPayloadBytes[l4index])
		rcv.LocalPort = rcv.RemotePort
		rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+4:]
	}
	return rcv, nil
}

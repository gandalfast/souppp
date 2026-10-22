package ppp

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gandalfast/souppp/ethernetconn"
	"github.com/rs/zerolog"
)

// failingConn is a net.PacketConn whose reads time out until fail is
// closed, after which they return a permanent error, as a PPPoE session
// the peer terminated does.
type failingConn struct {
	mu       sync.Mutex
	deadline time.Time
	fail     chan struct{}
}

var errTransportGone = errors.New("transport gone")

func (c *failingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	wait := time.Hour
	if !deadline.IsZero() {
		wait = time.Until(deadline)
	}
	select {
	case <-c.fail:
		return 0, nil, errTransportGone
	case <-time.After(wait):
		return 0, nil, ethernetconn.ErrTimeOut
	}
}

func (c *failingConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *failingConn) Close() error                              { return nil }
func (c *failingConn) LocalAddr() net.Addr                       { return nil }
func (c *failingConn) SetDeadline(t time.Time) error             { return c.SetReadDeadline(t) }
func (c *failingConn) SetWriteDeadline(time.Time) error          { return nil }
func (c *failingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func reject(b []byte) *Packet { return NewPacket(NewStaticSerializer(b), ProtoLCP) }

// TestFatalReadClosesProtocolChannels checks that when the transport
// fails for good, every registered protocol's receive channel is closed,
// so the protocols learn that the lower layer is gone, and that a later
// Close or Unregister is still safe.
func TestFatalReadClosesProtocolChannels(t *testing.T) {
	conn := &failingConn{fail: make(chan struct{})}
	logger := zerolog.Nop()
	p := NewPPP(conn, &logger, reject)
	_, lcpRecv := p.Register(ProtoLCP)
	_, ipcpRecv := p.Register(ProtoIPCP)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	close(conn.fail)
	for name, ch := range map[string]chan []byte{"LCP": lcpRecv, "IPCP": ipcpRecv} {
		select {
		case _, ok := <-ch:
			if ok {
				t.Fatalf("%s received data instead of a closed channel", name)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s receive channel still open 2s after the transport failed", name)
		}
	}
	p.Unregister(ProtoLCP)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

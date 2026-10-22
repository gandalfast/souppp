package lcp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gandalfast/souppp/ethernetconn"
	"github.com/gandalfast/souppp/ppp"
	"github.com/rs/zerolog"
)

// fakeConn is a net.PacketConn that records what PPP writes and never
// receives anything: ReadFrom waits for its deadline and times out, as
// the PPPoE connection does on a silent peer.
type fakeConn struct {
	mu       sync.Mutex
	written  [][]byte
	deadline time.Time
	closed   chan struct{}
}

func newFakeConn() *fakeConn {
	return &fakeConn{closed: make(chan struct{})}
}

func (c *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	wait := time.Until(deadline)
	if deadline.IsZero() {
		wait = time.Hour
	}
	select {
	case <-time.After(wait):
		return 0, nil, ethernetconn.ErrTimeOut
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte(nil), p...))
	return len(p), nil
}

func (c *fakeConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// codesWritten returns the LCP message codes of the LCP packets PPP wrote.
func (c *fakeConn) codesWritten() []MsgCode {
	c.mu.Lock()
	defer c.mu.Unlock()
	var codes []MsgCode
	for _, b := range c.written {
		if len(b) >= 3 && ppp.ProtocolNumber(uint16(b[0])<<8|uint16(b[1])) == ppp.ProtoLCP {
			codes = append(codes, MsgCode(b[2]))
		}
	}
	return codes
}

func countCode(codes []MsgCode, code MsgCode) int {
	n := 0
	for _, c := range codes {
		if c == code {
			n++
		}
	}
	return n
}

// events collects layer notifications.
type events struct {
	mu   sync.Mutex
	seen []LayerNotifyEvent
	ch   chan LayerNotifyEvent
}

func newEvents() *events {
	return &events{ch: make(chan LayerNotifyEvent, 16)}
}

func (e *events) handle(evt LayerNotifyEvent) {
	e.mu.Lock()
	e.seen = append(e.seen, evt)
	e.mu.Unlock()
	e.ch <- evt
}

func (e *events) wait(t *testing.T, want LayerNotifyEvent, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case evt := <-e.ch:
			if evt == want {
				return
			}
		case <-deadline:
			e.mu.Lock()
			seen := append([]LayerNotifyEvent(nil), e.seen...)
			e.mu.Unlock()
			t.Fatalf("no %v event within %v; events seen: %v", want, timeout, seen)
		}
	}
}

// waitState waits for the LCP to reach state want. A layer event is
// notified before the state changes, so a state read right after an event
// may still see the previous one.
func waitState(t *testing.T, l *LCP, want State) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if l.getState() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state = %v, want %v", l.getState(), want)
}

// newTestLCP returns an LCP over a PPP on a silent fake connection, with the
// restart timeout and keepalive interval shortened to d.
func newTestLCP(t *testing.T, d time.Duration, handler LayerNotifyHandler) (*LCP, *fakeConn) {
	t.Helper()
	conn := newFakeConn()
	logger := zerolog.Nop()
	p := ppp.NewPPP(conn, &logger, NewRejectPacket())
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	peerRule, err := NewDefaultPeerOptionRule(ppp.ProtoCHAP)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLCP(ppp.ProtoLCP, p, handler, peerRule, NewDefaultOwnOptionRule())
	l.restartTimeout = d
	l.keepAliveInterval = d
	t.Cleanup(func() {
		_ = l.Close()
		_ = p.Close()
		cancel()
	})
	return l, conn
}

// TestRestartTimerRetransmitsUntilCounterExpires checks that an unanswered
// Configure-Request is retransmitted on every restart timeout until the
// restart counter runs out, when the layer finishes, as RFC 1661 section
// 4.6 requires. The counter starts at 3, so three requests go out.
func TestRestartTimerRetransmitsUntilCounterExpires(t *testing.T) {
	ev := newEvents()
	l, conn := newTestLCP(t, 40*time.Millisecond, ev.handle)
	l.Start(context.Background())
	if err := l.OpenEvent(); err != nil {
		t.Fatal(err)
	}
	if err := l.UpEvent(); err != nil {
		t.Fatal(err)
	}

	ev.wait(t, LayerNotifyFinished, 2*time.Second)
	if n := countCode(conn.codesWritten(), CodeConfigureRequest); n != _defaultRestartCounter {
		t.Fatalf("%d Configure-Requests sent, want %d (one per restart timeout until the counter expires)", n, _defaultRestartCounter)
	}
	waitState(t, l, StateStopped)
}

// TestKeepAliveDetectsDeadPeer checks that an opened LCP keeps sending
// Echo-Requests, and that a peer that never replies is detected: the
// echo is retransmitted until the restart counter runs out and the layer
// goes down and finishes.
func TestKeepAliveDetectsDeadPeer(t *testing.T) {
	ev := newEvents()
	l, conn := newTestLCP(t, 40*time.Millisecond, ev.handle)
	l.setState(StateOpened, "test")
	l.Start(context.Background())

	ev.wait(t, LayerNotifyFinished, 2*time.Second)
	if n := countCode(conn.codesWritten(), CodeEchoRequest); n < 2 {
		t.Fatalf("%d Echo-Requests sent before giving up on the peer, want at least 2", n)
	}
	waitState(t, l, StateStopped)
}

// TestKeepAliveContinuesAfterReply checks that the keepalive is periodic: a
// replied Echo-Request is followed by another one at the next interval.
func TestKeepAliveContinuesAfterReply(t *testing.T) {
	ev := newEvents()
	l, conn := newTestLCP(t, 40*time.Millisecond, ev.handle)
	l.setState(StateOpened, "test")
	l.Start(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	replied := 0
	for time.Now().Before(deadline) {
		if n := countCode(conn.codesWritten(), CodeEchoRequest); n > replied {
			reply := NewPacket(ppp.ProtoLCP)
			reply.Code = CodeEchoReply
			reply.ID = uint8(n)
			b, err := reply.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			l.processReceivedBytes(b)
			replied = n
			if replied >= 3 {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if replied < 3 {
		t.Fatalf("only %d Echo-Requests in 2s with every one answered, want at least 3 (a periodic keepalive)", replied)
	}
	if s := l.getState(); s != StateOpened {
		t.Fatalf("state with an answering peer = %v, want %v", s, StateOpened)
	}
	select {
	case evt := <-ev.ch:
		t.Fatalf("unexpected layer event %v with an answering peer", evt)
	default:
	}
}

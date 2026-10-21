package lcp

import (
	"context"
	"testing"
	"time"

	"github.com/gandalfast/souppp/ppp"
	"github.com/rs/zerolog"
)

// newOpenedLCP returns a started LCP in the Opened state over a PPP that
// does no I/O, reporting its layer events on the returned channel.
func newOpenedLCP(t *testing.T) (*LCP, *ppp.PPP, chan LayerNotifyEvent) {
	t.Helper()
	logger := zerolog.Nop()
	p := ppp.NewPPP(nil, &logger, NewRejectPacket())
	events := make(chan LayerNotifyEvent, 8)
	peerRule, err := NewDefaultPeerOptionRule(ppp.ProtoCHAP)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLCP(ppp.ProtoLCP, p, func(e LayerNotifyEvent) { events <- e }, peerRule, NewDefaultOwnOptionRule())
	l.setState(StateOpened, "test")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	return l, p, events
}

// TestLowerLayerClosingBringsTheLayerDown checks that when PPP closes the
// protocol's receive channel, because the transport is gone, the LCP
// raises the Down event: the layer is notified and the automaton leaves
// Opened for Starting, as RFC 1661 section 4.4 requires on Down.
func TestLowerLayerClosingBringsTheLayerDown(t *testing.T) {
	l, p, events := newOpenedLCP(t)
	p.Unregister(ppp.ProtoLCP)

	select {
	case evt := <-events:
		if evt != LayerNotifyDown {
			t.Fatalf("event %v, want %v", evt, LayerNotifyDown)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no layer event 2s after the lower layer closed")
	}
	deadline := time.Now().Add(time.Second)
	for l.getState() != StateStarting && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s := l.getState(); s != StateStarting {
		t.Fatalf("state after the lower layer closed = %v, want %v", s, StateStarting)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestOwnCloseReportsNoDownEvent checks that closing the LCP itself, which
// also closes its receive channel, is not taken for the lower layer going
// away: no Down event is raised.
func TestOwnCloseReportsNoDownEvent(t *testing.T) {
	l, _, events := newOpenedLCP(t)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case evt := <-events:
		t.Fatalf("event %v after the LCP's own Close, want none", evt)
	case <-time.After(200 * time.Millisecond):
	}
}

// Package client is a PPPoE client lib
package client

import (
	"context"
	"errors"
	"github.com/gandalfast/souppp/etherconn"
	"github.com/gandalfast/souppp/ppp/lcp"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// Client represents a PPPoE/PPP sessions lifetime handler (aka a Pool)
type Client struct {
	cfg        *Setup
	relayConn  etherconn.PacketRelay
	sessionMtx sync.RWMutex
	sessions   []*session
	blacklist  lcp.Blacklist
	closed     chan struct{}
}

// NewClient creates a new Client instance
func NewClient(relayConn etherconn.PacketRelay, cfg *Setup) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Client{
		cfg:       cfg,
		relayConn: relayConn,
		sessions:  make([]*session, cfg.NumOfClients),
		blacklist: lcp.NewDefaultBlacklist(),
		closed:    make(chan struct{}),
	}, nil
}

// SetBlacklist adds a custom IP blacklist to avoid the usage of
// some specific addresses in the PPP sessions.
func (c *Client) SetBlacklist(blacklist lcp.Blacklist) {
	c.blacklist = blacklist
}

// Dial starts all the required initial sessions.
// It returns an error only if all the sessions failed, and there is no
// client running after the call to this function.
// If at least one session handshake succeed, and there are some failed
// sessions, the failed sessions will be restarted in another goroutine
// asynchronously.
// If this function returns an error, the current Client can't be used anymore,
// and it's the equivalent of a call to Close().
func (c *Client) Dial(ctx context.Context) error {
	var wg sync.WaitGroup

	errList := make([]error, len(c.sessions))
	for i := range c.sessions {
		wg.Add(1)
		go func(i int) {
			s, err := c.dialSession(ctx, i)
			if err != nil {
				errList[i] = err
			}
			c.sessions[i] = s
			wg.Done()

			// Retry connection asynchronously if there was an error
			if err != nil {
				_ = c.dialSessionLoop(ctx, i)
			}
		}(i)
	}

	wg.Wait()

	// Check if there is at least one good connection dialed
	counter := 0
	for _, err := range errList {
		if err != nil {
			counter++
		}
	}

	// Return the error only if every connection is in the failed state
	if counter == len(c.sessions) {
		_ = c.Close()
		return errors.Join(errList...)
	}

	return nil
}

// NumSessions returns the total number of target concurrent PPPoE sessions.
func (c *Client) NumSessions() int {
	return len(c.sessions)
}

// IsSessionValid returns true if the specified session at index i
// (in the range 0 <= i < NumSessions) is currently up and ready.
func (c *Client) IsSessionValid(index int) bool {
	if index < 0 || index >= len(c.sessions) {
		return false
	}

	c.sessionMtx.RLock()
	defer c.sessionMtx.RUnlock()

	s := c.sessions[index]
	if s == nil {
		return false
	}
	return s.isReady.Load()
}

// GetValidSession returns a random index i (in the range 0 <= i < NumSessions) ,
// that is currently up and ready.
func (c *Client) GetValidSession(ctx context.Context) (int, error) {
	length := c.NumSessions()
	index := rand.IntN(length)

	for {
		if c.IsSessionValid(index) {
			return index, nil
		}
		index++
		if index >= len(c.sessions) {
			index = 0
		}

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
	}
}

// RestartSession manually restarts a PPPoE session specified at the index i
// (in the range 0 <= i < NumSessions), and if it's successful, it returns the
// list of old IP addresses assigned to previous session that has been
// replaced.
func (c *Client) RestartSession(ctx context.Context, index int) (oldIPs []net.IP, err error) {
	if index < 0 || index >= len(c.sessions) {
		return nil, errors.New("invalid session index")
	}

	c.sessionMtx.Lock()
	s := c.sessions[index]
	if s != nil && s.isReady.Load() {
		s.isReady.Store(false)
	}
	c.sessionMtx.Unlock()

	if s == nil {
		return nil, errors.New("session is not started")
	}

	oldIPs = append(s.assignedIANAs, s.assignedV4Addr)
	if err := s.Close(); err != nil {
		c.cfg.Logger.Error().Err(err).Int("index", index).Msg("Unable to close session in RestartSession")
	}

	return oldIPs, c.dialSessionLoop(ctx, index)
}

func (c *Client) Close() error {
	c.cfg.Logger.Info().Msg("PPP Close")
	close(c.closed)

	var errList []error
	c.sessionMtx.Lock()
	for _, s := range c.sessions {
		if s == nil {
			continue
		}
		s.isReady.Store(false)
		errList = append(errList, s.Close())
	}
	c.sessionMtx.Unlock()

	return errors.Join(errList...)
}

func (c *Client) dialSessionLoop(ctx context.Context, index int) error {
	duration := c.cfg.Timeout * 3 / 2
	t := time.NewTimer(duration)
	for {
		select {
		case <-ctx.Done():
			return errors.New("context canceled")
		case _, ok := <-c.closed:
			if !ok {
				return errors.New("client closed")
			}
		default:
			newSess, err := c.dialSession(ctx, index)
			if err != nil {
				c.cfg.Logger.Info().Err(err).Int("index", index).Msg("Unable to restart session in dialSessionLoop")
				<-t.C
				t.Reset(duration)
			} else {
				c.cfg.Logger.Info().Err(err).Int("index", index).Msg("Added created session in dialSessionLoop")
				c.sessionMtx.Lock()
				c.sessions[index] = newSess
				c.sessionMtx.Unlock()
				t.Stop()
				return nil
			}
		}
	}
}

func (c *Client) dialSession(ctx context.Context, index int) (*session, error) {
	s, err := newSession(index, c.cfg, c.relayConn, c.blacklist)
	if err != nil {
		return nil, err
	}

	if err := s.Dial(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

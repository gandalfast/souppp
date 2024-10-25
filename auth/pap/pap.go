// Package pap implements PAP protocol as specified in RFC1334
package pap

import (
	"context"
	"errors"
	"github.com/gandalfast/zouppp/pppoe/lcp"
	"github.com/rs/zerolog"
	"time"
)

const (
	_defaultTimeout     = 4 * time.Second
	_defaultRetryNumber = 3
)

// PAP is the PAP protocol implementation
type PAP struct {
	logger    *zerolog.Logger
	sendChan  chan []byte
	recvChan  chan []byte
	requestID uint8
}

// NewPAP creates a new PAP instance with uname, Password;
// uses pppProtol as the underlying PPP protocol;
func NewPAP(pppProto *lcp.PPP) *PAP {
	r := new(PAP)
	r.sendChan, r.recvChan = pppProto.Register(lcp.ProtoPAP)
	logger := pppProto.GetLogger().With().Str("Name", "PAP").Logger()
	r.logger = &logger
	return r
}

func (pap *PAP) getResponse(ctx context.Context, req Packet) (resp Packet, err error) {
	for i := 0; i < _defaultRetryNumber; i++ {
		// Increase request ID counter
		pap.requestID++
		req.ID = pap.requestID

		// Send request
		pppData, err := lcp.NewPPPPkt(&req, lcp.ProtoPAP).Serialize()
		if err != nil {
			return resp, err
		}
		pap.sendChan <- pppData
		pap.logger.Debug().Any("req", req).Msg("sent PAP auth request")

		// Parse response
		resp, err = func(resp Packet) (Packet, error) {
			ctx, cancel := context.WithTimeout(ctx, _defaultTimeout)
			defer cancel()

			select {
			case <-ctx.Done():
				// Retry to send authentication request in the next retry
				return resp, ctx.Err()
			case responseBytes := <-pap.recvChan:
				if err := resp.Parse(responseBytes); err != nil {
					pap.logger.Warn().Err(err).Msg("got invalid PAP response")
					return resp, err
				}
				if resp.Code != CodeAuthACK && resp.Code != CodeAuthNAK {
					pap.logger.Warn().Uint8("code", uint8(resp.Code)).Msg("got a PAP non-response")
					return resp, errors.New("got a PAP non-response")
				}

				// Response is valid
				pap.logger.Debug().Any("resp", resp).Msg("got PAP response")
				return resp, nil
			}
		}(resp)
		if err == nil {
			return resp, nil
		}
	}
	return resp, AuthenticationTimeout
}

func (pap *PAP) AuthSelf(ctx context.Context, username, password string) error {
	resp, err := pap.getResponse(ctx, Packet{
		Code:     CodeAuthRequest,
		PeerID:   []byte(username),
		Password: []byte(password),
	})
	if err != nil {
		return err
	}

	if resp.Code != CodeAuthACK {
		return AuthenticationFailed
	}

	return nil
}

// Package chap implments CHAPwithMD5 as specified in RFC1994
package chap

import (
	"context"
	"crypto/md5"
	"github.com/gandalfast/zouppp/pppoe/lcp"
	"github.com/rs/zerolog"
	"time"
)

const _defaultTimeout = 10 * time.Second

// CHAP is the CHAP protocol implementation
type CHAP struct {
	logger   *zerolog.Logger
	sendChan chan []byte
	recvChan chan []byte
}

// NewCHAP creates a new CHAP instance with specified uname,passwd; using pppProto as underlying PPP protocol
func NewCHAP(pppProto *lcp.PPP) *CHAP {
	r := new(CHAP)
	r.sendChan, r.recvChan = pppProto.Register(lcp.ProtoCHAP)
	logger := pppProto.GetLogger().With().Str("Name", "CHAP").Logger()
	r.logger = &logger
	return r
}

func (chap *CHAP) send(ctx context.Context, data lcp.Serializer) error {
	ctx, cancel := context.WithTimeout(ctx, _defaultTimeout)
	defer cancel()

	serializedData, err := lcp.NewPPPPkt(data, lcp.ProtoCHAP).Serialize()
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return AuthenticationTimeout
	default:
		chap.sendChan <- serializedData
	}
	return nil
}

func (chap *CHAP) getInitialResponse(ctx context.Context) (pkt Packet, err error) {
	ctx, cancel := context.WithTimeout(ctx, _defaultTimeout)
	defer cancel()

	var done bool
	for !done {
		select {
		case b := <-chap.recvChan:
			if err := pkt.Parse(b); err != nil {
				chap.logger.Warn().Err(err).Msg("got an invalid CHAP pkt")
				break
			}
			if pkt.Code == CodeChallenge {
				done = true
				break
			}
		case <-ctx.Done():
			return pkt, AuthenticationTimeout
		}
	}

	return pkt, nil
}

func (chap *CHAP) getFinalResponse(ctx context.Context) (pkt Packet, err error) {
	ctx, cancel := context.WithTimeout(ctx, _defaultTimeout)
	defer cancel()

	var done bool
	for !done {
		select {
		case b := <-chap.recvChan:
			if err := pkt.Parse(b); err != nil {
				chap.logger.Warn().Err(err).Msg("got an invalid CHAP pkt")
				break
			}
			if pkt.Code == CodeSuccess || pkt.Code == CodeFailure {
				done = true
				break
			}
		case <-ctx.Done():
			return pkt, AuthenticationTimeout
		}
	}

	return pkt, nil
}

func (chap *CHAP) AuthSelf(ctx context.Context, username, password string) error {
	challenge, err := chap.getInitialResponse(ctx)
	if err != nil {
		return err
	}
	chap.logger.Debug().Any("pkt", challenge).Msg("got CHAP challenge")
	resp := Packet{
		Code: CodeResponse,
		ID:   challenge.ID,
	}

	toBuf := append([]byte{challenge.ID}, []byte(password)...)
	toBuf = append(toBuf, challenge.Value...)
	chap.logger.Debug().Msgf("hashing id %x, passwd %s,challege %x", challenge.ID, password, challenge.Value)
	h := md5.New()
	h.Write(toBuf)
	resp.Value = h.Sum(nil)
	chap.logger.Debug().Msgf("hash value is %x", resp.Value)

	resp.Name = []byte(username)
	err = chap.send(ctx, &resp)
	if err != nil {
		chap.logger.Warn().Err(err).Msg("failed to send CHAP response")
		return AuthenticationFailed
	}

	chap.logger.Debug().Any("pkt", resp).Msg("CHAP response sent")
	finalresp, err := chap.getFinalResponse(ctx)
	if err != nil {
		chap.logger.Warn().Err(err).Msg("failed to get final CHAP response")
		return AuthenticationFailed
	}
	chap.logger.Debug().Any("resp", finalresp).Msg("got CHAP final response")

	if finalresp.Code == CodeFailure {
		return GatewayFailed
	}
	return nil
}

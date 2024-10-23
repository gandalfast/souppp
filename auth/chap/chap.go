// Package chap implments CHAPwithMD5 as specified in RFC1994
package chap

import (
	"context"
	"crypto/md5"
	"fmt"
	"github.com/gandalfast/zouppp/lcp"
	"github.com/rs/zerolog"
	"time"
)

// CHAP is the CHAP protocol
type CHAP struct {
	sendChan chan []byte
	recvChan chan []byte
	logger   *zerolog.Logger
	timeout  time.Duration
}

// DefaultTimeout is the default timeout for CHAP
const DefaultTimeout = 10 * time.Second

// NewCHAP creates a new CHAP instance with specified uname,passwd; using pppProto as underlying PPP protocol
func NewCHAP(pppProto *lcp.PPP) *CHAP {
	r := new(CHAP)
	r.sendChan, r.recvChan = pppProto.Register(lcp.ProtoCHAP)
	logger := pppProto.GetLogger().With().Str("Name", "CHAP").Logger()
	r.logger = &logger
	r.timeout = DefaultTimeout
	return r
}

func (chap *CHAP) send(p []byte) error {
	t := time.NewTimer(chap.timeout)
	defer t.Stop()
	ppkt, err := lcp.NewPPPPkt(lcp.NewStaticSerializer(p), lcp.ProtoCHAP).Serialize()
	if err != nil {
		return err
	}
	select {
	case <-t.C:
		return fmt.Errorf("send timeout")
	default:
		chap.sendChan <- ppkt
	}
	return nil
}

func (chap *CHAP) getResponse(final bool) (pkt *Pkt, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), chap.timeout)
	defer cancel()

	var done bool
	for !done {
		select {
		case b := <-chap.recvChan:
			pkt = new(Pkt)
			if err := pkt.Parse(b); err != nil {
				chap.logger.Warn().Err(err).Msg("got an invalid CHAP pkt")
				break
			}
			if (!final && pkt.Code == CodeChallenge) || (final && (pkt.Code == CodeSuccess || pkt.Code == CodeFailure)) {
				done = true
				break
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("CHAP authentication failed, timeout")
		}
	}

	return pkt, nil
}

// AUTHSelf auth self to peer, return nil if auth succeeds
func (chap *CHAP) AuthSelf(ctx context.Context, username, password string) error {
	challenge, err := chap.getResponse(false)
	if err != nil {
		return err
	}
	chap.logger.Debug().Any("challenge", challenge).Msg("got CHAP challenge")
	resp := new(Pkt)
	resp.Code = CodeResponse
	resp.ID = challenge.ID

	h := md5.New()
	toBuf := append([]byte{challenge.ID}, []byte(password)...)
	toBuf = append(toBuf, challenge.Value...)
	chap.logger.Debug().Msgf("hashing id %x, passwd %s,challege %x", challenge.ID, password, challenge.Value)
	h.Write(toBuf)
	resp.Value = h.Sum(nil)
	chap.logger.Debug().Msgf("hash value is %x", resp.Value)

	resp.Name = []byte(username)
	b, err := resp.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize CHAP response,%w", err)
	}
	err = chap.send(b)
	if err != nil {
		return fmt.Errorf("failed to send CHAP response,%w", err)
	}
	chap.logger.Debug().Any("resp", resp).Msg("send CHAP response")
	finalresp, err := chap.getResponse(true)
	if err != nil {
		return fmt.Errorf("failed to get final CHAP response,%w", err)
	}
	chap.logger.Debug().Any("resp", finalresp).Msg("got CHAP final response")
	if finalresp.Code == CodeFailure {
		return fmt.Errorf("gateway returned failed")
	}
	return nil
}

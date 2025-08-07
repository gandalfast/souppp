package xdpconn

import (
	"errors"
	"fmt"
	"github.com/asavie/xdp"
	"github.com/gandalfast/souppp/ethernetconn"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
	"runtime"
	"slices"
	"syscall"
	"time"
)

type xdpSock struct {
	logger  *zerolog.Logger
	sock    *xdp.Socket
	queueId int
	relay   *XDPRelay
	closed  chan struct{}
}

func newXdpSocket(
	logger *zerolog.Logger,
	queueId int,
	sockOpt *xdp.SocketOptions,
	xRelay *XDPRelay,
) (*xdpSock, error) {
	sock, err := xdp.NewSocket(xRelay.ifLink.Attrs().Index, queueId, sockOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to create new XDP socket for queue %d, %w", queueId, err)
	}
	if err := xRelay.bpfProg.Register(queueId, sock.FD()); err != nil {
		return nil, fmt.Errorf("failed to register xdp socket to program for queue %d, %w", queueId, err)
	}

	l := logger.With().Str("socket", "XDP").Logger()
	return &xdpSock{
		logger:  &l,
		relay:   xRelay,
		sock:    sock,
		queueId: queueId,
		closed:  make(chan struct{}),
	}, nil
}

func (s *xdpSock) start() {
	s.relay.socksWg.Add(2)
	go s.receive()
	go s.send(s.relay.sendingMode)
}

func (s *xdpSock) Close() error {
	close(s.closed)
	return nil
}

func (s *xdpSock) send(mode xdpSendingMode) {
	defer s.relay.socksWg.Done()
	runtime.LockOSThread()
	dataList := make([][]byte, 32)
	dataListLen := len(dataList)
	if mode != XDPSendingModeBatch {
		dataListLen = 1
	}

	timeoutDuration := 3 * time.Second
	t := time.NewTimer(timeoutDuration)
	defer t.Stop()

	for {
		select {
		case <-s.closed:
			return
		default:
		}

		sentPackets := 0
		finished := false
		for !finished {
			t.Reset(timeoutDuration)
			select {
			case data := <-s.relay.framesToSendChan:
				dataList[sentPackets] = data
				sentPackets++
				if sentPackets >= dataListLen {
					if !t.Stop() {
						<-t.C
					}
					finished = true
				}
			case <-t.C:
				if sentPackets > 0 {
					if !t.Stop() {
						<-t.C
					}
					finished = true
				}
			}
		}
		if sentPackets == 0 {
			continue
		}

		descriptors := s.sock.GetDescs(sentPackets, false)
		if len(descriptors) < sentPackets {
			s.logger.Debug().Msgf("unable to get xdp desc, need %d, but got %d", sentPackets, len(descriptors))
			return
		}

		for i := 0; i < sentPackets; i++ {
			copy(s.sock.GetFrame(descriptors[i]), dataList[i])
			descriptors[i].Len = uint32(len(dataList[i]))
		}

		numSubmitted := s.sock.Transmit(descriptors)
		if numSubmitted != sentPackets {
			s.logger.Debug().Msgf("failed to submit pkt to xdp tx ring, need to send %d, only sent %d", sentPackets, numSubmitted)
			return
		}

		// NOTE: use any value >=0 as Poll argument will cause unexpected issue during high throughput
		var err error
		if numSubmitted, err = s.polling(-1, false); err != nil {
			s.logger.Debug().Err(err).Msg("xdp socket poll failed")
			return
		}
		s.logger.Debug().Msgf("xdp sock %d sent %d", s.queueId, numSubmitted)
	}
}

func (s *xdpSock) receive() {
	defer s.relay.socksWg.Done()
	runtime.LockOSThread()
	for {
		select {
		case <-s.closed:
			return
		default:
		}

		if n := s.sock.NumFreeFillSlots(); n > 0 {
			s.sock.Fill(s.sock.GetDescs(n, true))
		}

		numRx, err := s.polling(-1, true)
		if err != nil && errors.Is(err, syscall.ETIMEDOUT) {
			continue
		} else if err != nil {
			s.logger.Debug().Msgf("poll error, abort, %v", err)
			return
		} else {
			// No error
			if numRx <= 0 {
				continue
			}

			rxDescriptors := s.sock.Receive(numRx)
			for i := 0; i < len(rxDescriptors); i++ {
				packetData := slices.Clone(s.sock.GetFrame(rxDescriptors[i]))
				s.handleReceivedPacket(packetData)
			}
		}
	}
}

func (s *xdpSock) polling(timeout int, rx bool) (int, error) {
	var events int16
	if rx && s.sock.NumFilled() > 0 {
		events |= unix.POLLIN
	}
	if !rx && s.sock.NumTransmitted() > 0 {
		events |= unix.POLLOUT
	}
	if events == 0 {
		return 0, nil
	}

	pollingFileDescriptor := []unix.PollFd{
		{
			Fd:     int32(s.sock.FD()),
			Events: events,
		},
	}

	var err error = unix.EINTR
	for errors.Is(err, unix.EINTR) {
		_, err = unix.Poll(pollingFileDescriptor, timeout)
	}

	if rx {
		return s.sock.NumReceived(), nil
	}

	numCompleted := s.sock.NumCompleted()
	if numCompleted > 0 {
		s.sock.Complete(numCompleted)
	}
	return numCompleted, nil
}

// handleReceivedPacket is the function handle the received pkt from underlying socket, it is shared code for both RawPacketRelay and XDPPacketRelay
func (s *xdpSock) handleReceivedPacket(framesData []byte) {
	if len(framesData) < _minimumEthernetFrameSize {
		return
	}

	// Obtain
	localAddress := &ethernetconn.L2Endpoint{
		HwAddr:       make([]byte, 6),
		EthernetType: ethernetconn.ParseEthernetType(framesData),
	}
	copy(localAddress.HwAddr, framesData[:6])

	routingKey := localAddress.GetKey()
	s.logger.Debug().Msgf("got pkt with l2epkey %s", routingKey.String())

	s.relay.listMtx.RLock()
	unicastReceiver, ok := s.relay.rxList[routingKey]
	s.relay.listMtx.RUnlock()

	if ok {
		s.sendDataToChan(framesData, unicastReceiver.ch)
		return
	}

	// multicast traffic
	if localAddress.HwAddr[0]&0x1 == 1 {
		var multicastList []chan []byte
		s.relay.listMtx.RLock()
		for _, receiver := range s.relay.multicastList {
			multicastList = append(multicastList, receiver.ch)
		}
		s.relay.listMtx.RUnlock()

		for _, multicastChan := range multicastList {
			s.sendDataToChan(framesData, multicastChan)
		}
		if len(multicastList) == 0 {
			s.logger.Debug().Msg("ignored a multicast packet")
		}
	} else {
		// unicast, receiver not found
		s.logger.Debug().Msgf("can't find matching l2ep %s", routingKey.String())
	}
}

func (s *xdpSock) sendDataToChan(received []byte, ch chan []byte) {
	for { //keep sending until pkt is sent to channel
		select {
		case <-s.closed:
			return
		case ch <- received:
			return
		default:
			<-ch // channel is full, remove the oldest pkt in channel
		}
	}
}

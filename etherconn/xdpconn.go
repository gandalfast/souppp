package etherconn

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/rs/zerolog"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// xdpSendingMode is the TX mode of XDPRelay
type xdpSendingMode string

const (
	// XDPSendingModeSingle is the TX mode where the forwarder sends a packet a time, this is the default mode
	XDPSendingModeSingle xdpSendingMode = "single"
	// XDPSendingModeBatch is the TX mode where the forwarder sends a batch of packets a time,
	// only use this mode when there is a high number of TX
	XDPSendingModeBatch xdpSendingMode = "batch"
)

const (
	// _minimumEthernetFrameSize is the minimum size of an Ethernet frame
	_minimumEthernetFrameSize = 14
	// _defaultXDPChunkSize is the default size for XDP UMEM chunk
	_defaultXDPChunkSize = 4096
	// _defaultXDPUMEMNumOfTrunk is the default number of UMEM trunks
	_defaultXDPUMEMNumOfTrunk = 16384
	// _defaultSendChanDepth is the default value for PacketRelay send channel depth, e.g. send buffer
	_defaultSendChanDepth = 1024
	// _defaultReceiveChanDepth is the default value for every EtherConn registered client's receive channel depth. e.g. receive buffer
	_defaultReceiveChanDepth = 1024
)

// getInterfaceQueueNum uses ethtool to get number of combined queue of the interface, return 1 if failed to get the info
func getInterfaceQueueNum(interfaceName string) (int, error) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return -1, err
	}
	defer ethHandle.Close()

	// Retrieve channels
	chans, err := ethHandle.GetChannels(interfaceName)
	if err != nil {
		return 1, nil
	}
	result := int(chans.CombinedCount)
	if result <= 0 {
		result = 1
	}
	return result, nil
}

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
	go s.receive()
	go s.send(s.relay.sendingMode)
}

func (s *xdpSock) Close() error {
	close(s.closed)
	return s.sock.Close()
}

func (s *xdpSock) send(mode xdpSendingMode) {
	runtime.LockOSThread()
	dataList := make([][]byte, 32)
	dataListLen := len(dataList)
	if mode != XDPSendingModeBatch {
		dataListLen = 1
	}

	timeoutDuration := 3 * time.Second
	t := time.NewTimer(timeoutDuration)

	for {
		select {
		case <-s.closed:
			t.Stop()
			return
		default:
		}

		sentPackets := 0
		finished := false
		for !finished {
			t.Reset(timeoutDuration)
			select {
			case data := <-s.relay.toSendChan:
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

		descriptions := s.sock.GetDescs(sentPackets, false)
		if len(descriptions) < sentPackets {
			s.logger.Debug().Msgf("unable to get xdp desc, need %d, but got %d", sentPackets, len(descriptions))
			return
		}

		for i := 0; i < sentPackets; i++ {
			copy(s.sock.GetFrame(descriptions[i]), dataList[i])
			descriptions[i].Len = uint32(len(dataList[i]))
		}

		numSubmitted := s.sock.Transmit(descriptions)
		if numSubmitted != sentPackets {
			s.logger.Debug().Msgf("failed to submit pkt to xdp tx ring, need to send %d, only sent %d", sentPackets, numSubmitted)
			return
		}

		// NOTE: use any value >=0 as Poll argument will cause unexpected issue during high throughput
		var err error
		if _, numSubmitted, err = s.sock.Poll(-1); err != nil {
			s.logger.Debug().Err(err).Msg("xdp socket poll failed")
			return
		}
		s.logger.Debug().Msgf("xdp sock %d sent %d", s.queueId, numSubmitted)
	}
}

func (s *xdpSock) receivePolling(timeout int) (int, error) {
	pollingFileDescriptor := []unix.PollFd{
		{
			Fd:     int32(s.sock.FD()),
			Events: int16(unix.POLLIN),
		},
	}

	var err error = unix.EINTR
	for errors.Is(err, unix.EINTR) {
		_, err = unix.Poll(pollingFileDescriptor, timeout)
	}
	if err != nil {
		return 0, err
	}

	return s.sock.NumReceived(), nil
}

func (s *xdpSock) receive() {
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

		numRx, err := s.receivePolling(-1)
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

			rxDescriptions := s.sock.Receive(numRx)
			for i := 0; i < len(rxDescriptions); i++ {
				packetData := slices.Clone(s.sock.GetFrame(rxDescriptions[i]))
				s.handleReceivedPacket(packetData)
			}
		}
	}
}

type ethernetMapEntry struct {
	registrationID int
	ch             chan *EthernetResponse
	stop           chan struct{}
}

// XDPRelay uses Linux AF_XDP socket as the underlying forwarding mechanism, so
// it achieves higher performance than RawSocketRelay in multicore setup,
// XDPRelay usage notes:
//  1. for virtio interface, the number of queues provisioned needs to be 2x of number CPU cores VM has, binding will fail otherwise.
//  2. AF_XDP is still relative new, see XDP kernel&driver support status: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp
//  3. For best performance:
//     a) use NIC multiple queues and multiple routine(with runtime.LockOSThread()) to drive the traffic
//     b) the number of routines >= number of NIC queues
type XDPRelay struct {
	logger *zerolog.Logger
	ifName string
	ifLink netlink.Link

	// eBPF
	bpfProg     *xdp.Program
	bpfEtypeMap *ebpf.Map

	// XDP
	sendingMode          xdpSendingMode
	perClntRecvChanDepth uint
	sendChanDepth        uint
	//maxEtherFrameSize can be only be 2048 or 4096
	maxEtherFrameSize uint
	umemNumOfTrunks   uint
	sockList          []*xdpSock
	queueIDList       []int

	// Ethernet
	recvEtypes        []uint16
	toSendChan        chan []byte
	listMtx           sync.RWMutex
	registrationCount atomic.Uint32
	recvList          map[L2EndpointKey]ethernetMapEntry
	multicastList     map[L2EndpointKey]ethernetMapEntry
}

// XDPRelayOption could be used in NewXDPRelay to customize XDPRelay upon creation
type XDPRelayOption func(xr *XDPRelay)

// WithQueueID specifies a list of interface queue id (start from 0) that the XDPRelay binds to;
// by default, XDPRelay will use all queues.
// note: only use this option if you know what you are doing, since this could cause lower performance or XDPRelay unable to receive some of packets.
func WithQueueID(qidlist []int) XDPRelayOption {
	return func(xr *XDPRelay) {
		xr.queueIDList = append(xr.queueIDList, qidlist...)
	}
}

// WithSendingMode set the XDPRelay's sending mode to m
func WithSendingMode(m xdpSendingMode) XDPRelayOption {
	return func(xr *XDPRelay) {
		xr.sendingMode = m
	}
}

// WithXDPUMEMNumOfTrunk specifies the number of UMEM trunks,
// must be power of 2.
// the Fill/Completion/TX/RX ring size is half of specified value;
func WithXDPUMEMNumOfTrunk(num uint) XDPRelayOption {
	if num%2 != 0 {
		return nil
	}
	return func(xr *XDPRelay) {
		xr.umemNumOfTrunks = num
	}
}

// WithXDPUMEMChunkSize specifies the XDP UMEM size,
// which implicitly set the max packet size could be handled by XDPRelay,
// must be either 4096 or 2048 (kernel XDP limitation)
func WithXDPUMEMChunkSize(fsize uint) XDPRelayOption {
	if fsize != 4096 && fsize != 2048 {
		return nil
	}
	return func(xr *XDPRelay) {
		xr.maxEtherFrameSize = fsize
	}
}

// WithXDPSendChanDepth set the dep  th in sending channel
func WithXDPSendChanDepth(depth uint) XDPRelayOption {
	return func(relay *XDPRelay) {
		relay.sendChanDepth = depth
	}
}

// WithXDPPerClntRecvChanDepth set the depth in receiving channel for each registered
func WithXDPPerClntRecvChanDepth(depth uint) XDPRelayOption {
	return func(relay *XDPRelay) {
		relay.perClntRecvChanDepth = depth
	}
}

// NewXDPRelay creates a new instance of XDPRelay,
// by default, the XDPRelay binds to all queues of the specified interface
func NewXDPRelay(logger *zerolog.Logger, ifname string, ethernetTypes []uint16, options ...XDPRelayOption) (*XDPRelay, error) {
	l := logger.With().Str("Interface", ifname).Logger()
	if len(ethernetTypes) == 0 {
		ethernetTypes = []uint16{_ethernetTypeARP, _ethernetTypeIPv4, _ethernetTypeIPv6}
	}

	r := &XDPRelay{
		logger:               &l,
		ifName:               ifname,
		sendingMode:          XDPSendingModeSingle,
		perClntRecvChanDepth: _defaultReceiveChanDepth,
		sendChanDepth:        _defaultSendChanDepth,
		maxEtherFrameSize:    _defaultXDPChunkSize,
		umemNumOfTrunks:      _defaultXDPUMEMNumOfTrunk,
		recvEtypes:           ethernetTypes,
		recvList:             make(map[L2EndpointKey]ethernetMapEntry),
		multicastList:        make(map[L2EndpointKey]ethernetMapEntry),
	}

	var err error
	if r.ifLink, err = netlink.LinkByName(ifname); err != nil {
		return nil, err
	}
	if err := setPromiscuousMode(ifname); err != nil {
		return nil, fmt.Errorf("failed to set %v to Promisc mode,%w", ifname, err)
	}

	for _, o := range options {
		o(r)
	}

	r.toSendChan = make(chan []byte, r.sendChanDepth)

	// generate queueIDList
	if len(r.queueIDList) == 0 {
		numQ, err := getInterfaceQueueNum(ifname)
		if err != nil {
			return nil, err
		}
		for i := 0; i < numQ; i++ {
			r.queueIDList = append(r.queueIDList, i)
		}
	}

	// Use built-in eBPF program
	if r.bpfProg, r.bpfEtypeMap, err = loadBuiltinEBPFProg(); err != nil {
		return nil, fmt.Errorf("failed to create built-in xdp kernel program, %w", err)
	}

	// Load EtherTypes into map
	for _, et := range r.recvEtypes {
		if err := r.bpfEtypeMap.Put(et, uint16(1)); err != nil {
			return nil, fmt.Errorf("failed to add ethertype %d into ebpf map, %v", et, err)
		}
	}
	if err := r.bpfProg.Attach(r.ifLink.Attrs().Index); err != nil {
		return nil, fmt.Errorf("failed to attach new program, %w", err)
	}

	socketOP := &xdp.SocketOptions{
		NumFrames:              int(r.umemNumOfTrunks),
		FrameSize:              int(r.maxEtherFrameSize),
		FillRingNumDescs:       int(r.umemNumOfTrunks / 2),
		CompletionRingNumDescs: int(r.umemNumOfTrunks / 2),
		RxRingNumDescs:         int(r.umemNumOfTrunks / 2),
		TxRingNumDescs:         int(r.umemNumOfTrunks / 2),
	}

	for _, qid := range r.queueIDList {
		xsk, err := newXdpSocket(r.logger, qid, socketOP, r)
		if err != nil {
			return nil, err
		}
		xsk.start()
		r.sockList = append(r.sockList, xsk)
	}
	return r, nil
}

func (xr *XDPRelay) InterfaceName() string {
	return xr.ifName
}

// NumSocket returns number of XDP socket
func (xr *XDPRelay) NumSocket() int {
	return len(xr.sockList)
}

func (xr *XDPRelay) Register(ks []L2EndpointKey, recvMulticast bool) (chan *EthernetResponse, chan []byte, chan struct{}, int) {
	ch := make(chan *EthernetResponse, xr.perClntRecvChanDepth)
	stop := make(chan struct{})
	registrationID := int(xr.registrationCount.Add(1) - 1)

	xr.listMtx.Lock()
	for i := range ks {
		old, ok := xr.recvList[ks[i]]
		if ok {
			select {
			case <-old.stop:
				close(old.stop)
			}
		}
		xr.recvList[ks[i]] = ethernetMapEntry{
			registrationID: registrationID,
			ch:             ch,
			stop:           stop,
		}
	}
	xr.listMtx.Unlock()

	if recvMulticast {
		// NOTE: only set one key in multicast, otherwise the EtherConn will receive multiple copies
		xr.listMtx.Lock()
		old, ok := xr.multicastList[ks[0]]
		if ok {
			close(old.stop)
		}
		xr.multicastList[ks[0]] = ethernetMapEntry{
			registrationID: registrationID,
			ch:             ch,
			stop:           stop,
		}
		xr.listMtx.Unlock()
	}

	return ch, xr.toSendChan, stop, registrationID
}

func (xr *XDPRelay) Unregister(registrationID int) {
	xr.listMtx.Lock()
	for key, r := range xr.multicastList {
		if r.registrationID == registrationID {
			close(r.stop)
			delete(xr.multicastList, key)
		}
	}
	for key, r := range xr.recvList {
		if r.registrationID == registrationID {
			close(r.stop)
			delete(xr.recvList, key)
		}
	}
	xr.listMtx.Unlock()
}

func (xr *XDPRelay) Close() error {
	xr.logger.Debug().Msg("relay stopping")

	xr.listMtx.Lock()
	for _, r := range xr.multicastList {
		close(r.stop)
	}

	for _, r := range xr.recvList {
		close(r.stop)
	}
	xr.listMtx.Unlock()

	for _, sock := range xr.sockList {
		_ = sock.Close()
	}

	for _, qid := range xr.queueIDList {
		_ = xr.bpfProg.Unregister(qid)
	}

	_ = xr.bpfProg.Detach(xr.ifLink.Attrs().Index)
	return xr.bpfProg.Close()
}

//go:embed xdpethfilter_kern.o
var builtXDPProgBinary []byte

func loadBuiltinEBPFProg() (*xdp.Program, *ebpf.Map, error) {
	return loadEBPFProgViaReader(
		bytes.NewReader(builtXDPProgBinary),
		"xdp_redirect_func",
		"qidconf_map",
		"xsks_map",
		"etype_list",
	)
}

func loadEBPFProgViaReader(r io.ReaderAt, funcname, qidmapname, xskmapname, ethertypemap string) (*xdp.Program, *ebpf.Map, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(r)
	if err != nil {
		return nil, nil, err
	}

	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, err
	}

	prog := new(xdp.Program)
	var ok bool
	if prog.Program, ok = col.Programs[funcname]; !ok {
		return nil, nil, fmt.Errorf("can't find a function named %v", funcname)
	}
	if prog.Queues, ok = col.Maps[qidmapname]; !ok {
		return nil, nil, fmt.Errorf("can't find a queue map named %v", qidmapname)
	}
	if prog.Sockets, ok = col.Maps[xskmapname]; !ok {
		return nil, nil, fmt.Errorf("can't find a socket map named %v", xskmapname)
	}

	var elist *ebpf.Map
	if elist, ok = col.Maps[ethertypemap]; !ok {
		return nil, nil, fmt.Errorf("can't find a ether list map named %v", ethertypemap)
	}

	return prog, elist, nil
}

// setPromiscuousMode put the interface in Promisc mode
func setPromiscuousMode(interfaceName string) error {
	target, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("couldn't query interface %s: %s", interfaceName, err)
	}

	// Convert uint16 to Big Endian
	protoBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(protoBuf, unix.ETH_P_ALL)
	convertedProto := binary.BigEndian.Uint16(protoBuf)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(convertedProto))
	if err != nil {
		return fmt.Errorf("couldn't open packet socket: %w", err)
	}

	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
		Ifindex: int32(target.Index),
		Type:    unix.PACKET_MR_PROMISC,
	})
}

// handleReceivedPacket is the function handle the received pkt from underlying socket, it is shared code for both RawPacketRelay and XDPPacketRelay
func (s *xdpSock) handleReceivedPacket(pktData []byte) {
	if len(pktData) < _minimumEthernetFrameSize {
		return
	}

	receivedData := parseReceivedData(pktData)
	fmt.Println("ZZZZZZZZZZ")

	s.logger.Debug().Msgf("got pkt with l2epkey %v", receivedData.LocalEndpoint.GetKey().String())

	s.relay.listMtx.RLock()
	received, ok := s.relay.recvList[receivedData.LocalEndpoint.GetKey()]
	s.relay.listMtx.RUnlock()

	if ok {
		sendDataToChan(receivedData, received.ch)
		return
	}

	// multicast traffic
	if receivedData.LocalEndpoint.HwAddr[0]&0x1 == 1 {
		var mList []chan *EthernetResponse
		s.relay.listMtx.RLock()
		for _, r := range s.relay.multicastList {
			mList = append(mList, r.ch)
		}
		s.relay.listMtx.RUnlock()

		if len(mList) > 0 {
			for _, multicastChan := range mList {
				receivedData.EtherBytes = pktData
				sendDataToChan(receivedData, multicastChan)
			}
		} else {
			s.logger.Debug().Msg("ignored a multicast pkt")
		}
	} else {
		// unicast, receiver not found
		s.logger.Debug().Msgf("can't find match l2ep %s", receivedData.LocalEndpoint.GetKey().String())
	}
}

func sendDataToChan(received *EthernetResponse, ch chan *EthernetResponse) {
	if len(received.EtherPayloadBytes) == 0 {
		return
	}
	for { //keep sending until pkt is sent to channel
		select {
		case ch <- received:
			return
		default:
			<-ch // channel is full, remove the oldest pkt in channel
		}
	}
}

// parseReceivedData parse received ethernet pkt, p is a ethernet packet in byte slice,
func parseReceivedData(p []byte) *EthernetResponse {
	rcv := &EthernetResponse{
		EtherBytes:     p,
		LocalEndpoint:  &L2Endpoint{},
		RemoteEndpoint: &L2Endpoint{},
	}

	copy(rcv.LocalEndpoint.HwAddr, p[:6])    // dst mac
	copy(rcv.RemoteEndpoint.HwAddr, p[6:12]) // src mac

	index := 12
	for {
		ethernetType := binary.BigEndian.Uint16(p[index : index+2])
		if ethernetType != 0x8100 && ethernetType != 0x88a8 {
			rcv.LocalEndpoint.EthernetType = ethernetType
			break
		}
		index += 4
	}
	rcv.EtherPayloadBytes = p[index+2:]

	var l4index int
	switch rcv.LocalEndpoint.EthernetType {
	case _ethernetTypeIPv4: //ipv4
		rcv.RemoteIP = rcv.EtherPayloadBytes[12:16]
		rcv.LocalIP = rcv.EtherPayloadBytes[16:20]
		rcv.Protocol = rcv.EtherPayloadBytes[9]
		l4index = 20 // NOTE: this means no supporting of any ipv4 options
	case _ethernetTypeIPv6: //ipv6
		rcv.Protocol = rcv.EtherPayloadBytes[6]
		rcv.RemoteIP = rcv.EtherPayloadBytes[8:24]
		rcv.LocalIP = rcv.EtherPayloadBytes[24:40]
		l4index = 40 // NOTE: this means no supporting of any ipv6 options
	}

	switch rcv.Protocol {
	case 17: // UDP
		rcv.RemotePort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index : l4index+2])
		rcv.LocalPort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index+2 : l4index+4])
		rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+8:]
	}
	rcv.RemoteEndpoint.EthernetType = rcv.LocalEndpoint.EthernetType

	fmt.Println(rcv)

	return rcv
}

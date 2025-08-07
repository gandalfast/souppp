package xdpconn

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/gandalfast/souppp/ethernetconn"
	"github.com/rs/zerolog"
	"github.com/vishvananda/netlink"
)

// xdpSendingMode is the TX mode of XDPRelay
type xdpSendingMode string

const (
	// XDPSendingModeSingle is the TX mode where the forwarder sends a packet a time, this is the default mode
	XDPSendingModeSingle = xdpSendingMode("single")
	// XDPSendingModeBatch is the TX mode where the forwarder sends a batch of packets a time,
	// only use this mode when there is a high number of TX
	XDPSendingModeBatch = xdpSendingMode("batch")
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

type ethernetMapEntry struct {
	registrationID int
	ch             chan []byte
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
	closed atomic.Bool

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
	socketsList       []*xdpSock
	socksWg           sync.WaitGroup
	queueIDList       []int

	// Ethernet
	ethernetTypes     []uint16
	framesToSendChan  chan []byte
	rxList            map[ethernetconn.L2EndpointKey]ethernetMapEntry
	multicastList     map[ethernetconn.L2EndpointKey]ethernetMapEntry
	listMtx           sync.RWMutex
	registrationCount atomic.Uint32
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

	r := &XDPRelay{
		logger:               &l,
		sendingMode:          XDPSendingModeSingle,
		perClntRecvChanDepth: _defaultReceiveChanDepth,
		sendChanDepth:        _defaultSendChanDepth,
		maxEtherFrameSize:    _defaultXDPChunkSize,
		umemNumOfTrunks:      _defaultXDPUMEMNumOfTrunk,
		ethernetTypes:        ethernetTypes,
		rxList:               make(map[ethernetconn.L2EndpointKey]ethernetMapEntry),
		multicastList:        make(map[ethernetconn.L2EndpointKey]ethernetMapEntry),
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

	// sendChanDepth could have been changed in the specified options,
	// so we create here the buffered channel
	r.framesToSendChan = make(chan []byte, r.sendChanDepth)

	queuesNumber, err := getInterfaceQueuesNumber(ifname)
	if err != nil {
		return nil, err
	}

	// Generate queueIDList: 0, 1, 2, ...
	for i := 0; i < queuesNumber; i++ {
		r.queueIDList = append(r.queueIDList, i)
	}

	// Use built-in eBPF program
	if r.bpfProg, r.bpfEtypeMap, err = loadBuiltinEBPFProg(); err != nil {
		return nil, fmt.Errorf("failed to create built-in xdp kernel program, %w", err)
	}

	// Load EtherTypes into map
	for _, ethernetType := range r.ethernetTypes {
		if err := r.bpfEtypeMap.Put(ethernetType, uint16(1)); err != nil {
			return nil, fmt.Errorf("failed to add ethertype %d into ebpf map, %v", ethernetType, err)
		}
	}
	if err := r.bpfProg.Attach(r.ifLink.Attrs().Index); err != nil {
		return nil, fmt.Errorf("failed to attach new program, %w", err)
	}

	socketOptions := &xdp.SocketOptions{
		NumFrames:              int(r.umemNumOfTrunks),
		FrameSize:              int(r.maxEtherFrameSize),
		FillRingNumDescs:       int(r.umemNumOfTrunks / 2),
		CompletionRingNumDescs: int(r.umemNumOfTrunks / 2),
		RxRingNumDescs:         int(r.umemNumOfTrunks / 2),
		TxRingNumDescs:         int(r.umemNumOfTrunks / 2),
	}

	for _, queueID := range r.queueIDList {
		socket, err := newXdpSocket(r.logger, queueID, socketOptions, r)
		if err != nil {
			return nil, err
		}
		socket.start()
		r.socketsList = append(r.socketsList, socket)
	}
	return r, nil
}

func (xr *XDPRelay) Register(ks []ethernetconn.L2EndpointKey, multicast bool) (chan []byte, chan []byte, chan struct{}, int) {
	ch := make(chan []byte, xr.perClntRecvChanDepth)
	stop := make(chan struct{})
	registrationID := int(xr.registrationCount.Add(1))

	xr.listMtx.Lock()
	for i := range ks {
		xr.rxList[ks[i]] = ethernetMapEntry{
			registrationID: registrationID,
			ch:             ch,
			stop:           stop,
		}
	}
	xr.listMtx.Unlock()

	if multicast {
		// NOTE: only set one key in multicast, otherwise the EtherConn will receive multiple copies
		xr.listMtx.Lock()
		xr.multicastList[ks[0]] = ethernetMapEntry{
			registrationID: registrationID,
			ch:             ch,
			stop:           stop,
		}
		xr.listMtx.Unlock()
	}

	return ch, xr.framesToSendChan, stop, registrationID
}

func (xr *XDPRelay) Unregister(registrationID int) {
	// There is only one channel shared between all the registrations
	// with the same registration ID, we need to close it only once
	var chanClosed bool
	xr.listMtx.Lock()
	for key, old := range xr.multicastList {
		if old.registrationID == registrationID {
			if !chanClosed {
				close(old.stop)
				chanClosed = true
			}
			delete(xr.multicastList, key)
		}
	}
	for key, old := range xr.rxList {
		if old.registrationID == registrationID {
			if !chanClosed {
				close(old.stop)
				chanClosed = true
			}
			delete(xr.rxList, key)
		}
	}
	xr.listMtx.Unlock()
}

func (xr *XDPRelay) Close() error {
	if !xr.closed.CompareAndSwap(false, true) {
		// Make sure to close only once
		return nil
	}

	xr.logger.Debug().Msg("relay stopping")

	// Signal closing to socket goroutines
	for _, s := range xr.socketsList {
		_ = s.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		xr.socksWg.Wait()
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}

	// Close XDP sockets
	for _, s := range xr.socketsList {
		_ = s.sock.Close()
	}

	for _, queueID := range xr.queueIDList {
		_ = xr.bpfProg.Unregister(queueID)
	}

	_ = xr.bpfProg.Detach(xr.ifLink.Attrs().Index)
	return xr.bpfProg.Close()
}

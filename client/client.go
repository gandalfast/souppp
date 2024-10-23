// Package client is a PPPoE client lib
package client

import (
	"context"
	"fmt"
	"github.com/gandalfast/zouppp/auth/chap"
	"github.com/gandalfast/zouppp/auth/pap"
	"github.com/gandalfast/zouppp/myaddr"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gandalfast/zouppp/datapath"
	"github.com/gandalfast/zouppp/lcp"
	"github.com/gandalfast/zouppp/pppoe"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/hujun-open/etherconn"
	"github.com/hujun-open/mywg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// VarName is the placeholder in PPPIfName/RID/CID/UserName/Password of Setup that will be replaced by client id
const VarName = "@ID"

func genStrFunc(s string, id int) string {
	if strings.Contains(s, VarName) {
		ss := strings.ReplaceAll(s, VarName, "%d")
		return fmt.Sprintf(ss, id)
	}
	return s
}

const (
	// StateInitial is the initial ZouPPP state
	StateInitial uint32 = iota
	// StateDialing is when ZouPPP is dialing
	StateDialing
	// StateOpen is after ZouPPP finished dialing, successfully reached open for all enabled NCP
	StateOpen
	// StateClosing is when ZouPPP is closing
	StateClosing
	// StateClosed is when ZouPPP is closed
	StateClosed
)

func stateStr(s uint32) string {
	switch s {
	case StateInitial:
		return "initial"
	case StateDialing:
		return "dialing"
	case StateOpen:
		return "open"
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	}
	return "unkown"
}

// ZouPPP represents a single PPPoE/PPP client session
type ZouPPP struct {
	cfg               *Config
	pppoeProto        *pppoe.PPPoE
	pppProto          *lcp.PPP
	fastpath          *datapath.TUNIF
	createFastPathMux *sync.Mutex
	lcpProto          *lcp.LCP
	ipcpProto         *lcp.LCP
	ipv6cpProto       *lcp.LCP
	logger            *zap.Logger
	ncpWG             *mywg.MyWG
	dialWG            *sync.WaitGroup
	onceDoneDialWG    *sync.Once
	onceSendResult    *sync.Once
	sessionWG         *sync.WaitGroup
	cancelFunc        context.CancelFunc
	state             *uint32
	dialSucceed       bool
	result            *DialResult
	assignedV4Addr    net.IP
	assignedIANAs     []net.IP
	assignedIAPDs     []*net.IPNet
}

// NewZouPPP creates a new ZouPPP instance, dialwg is done when dial finishes,
// sessionwg is done when whole session terminates after dailing succeeds
func NewZouPPP(econn *etherconn.EtherConn, cfg *Config,
	options ...ZouPPPModifier) (zou *ZouPPP, err error) {
	zou = new(ZouPPP)
	zou.cfg = cfg
	zou.logger = cfg.setup.logger.Named(econn.LocalAddr().String())
	taglist := []pppoe.Tag{pppoe.NewSvcTag("")}
	if cfg.CID != "" || cfg.RID != "" {
		taglist = append(taglist, pppoe.NewCircuitRemoteIDTag(cfg.CID, cfg.RID))
	}
	zou.pppoeProto = pppoe.NewPPPoE(econn,
		zou.logger,
		pppoe.WithTags(taglist))
	if err != nil {
		return nil, err
	}
	zou.ncpWG = mywg.NewMyWG()
	// if zou.cfg.setup.IPv4 {
	// 	zou.ncpWG.Add(1)
	// }
	// if zou.cfg.setup.IPv6 {
	// 	zou.ncpWG.Add(1)
	// }
	// if zou.cfg.setup.DHCPv6IANA || zou.cfg.setup.DHCPv6IAPD {
	// 	zou.ncpWG.Add(1)
	// }
	zou.onceSendResult = new(sync.Once)
	zou.result = new(DialResult)
	zou.result.R = ResultFailure
	zou.result.PPPoEEP = zou.pppoeProto.LocalAddr().(*pppoe.Endpoint)
	zou.createFastPathMux = new(sync.Mutex)
	zou.state = new(uint32)
	atomic.StoreUint32(zou.state, StateInitial)
	for _, option := range options {
		option(zou)
	}
	return
}

// ZouPPPModifier is a function provides addtional configuration for NewZouPPP()
type ZouPPPModifier func(zou *ZouPPP)

// WithDialWG specifies a WaitGroup, which will be done after ZouPPP finishes dialing
func WithDialWG(wg *sync.WaitGroup) ZouPPPModifier {
	return func(zou *ZouPPP) {
		zou.dialWG = wg
		zou.onceDoneDialWG = new(sync.Once)
	}
}

// WithSessionWG specifies a WaitGroup, which will be done after closed after reach open state
func WithSessionWG(wg *sync.WaitGroup) ZouPPPModifier {
	return func(zou *ZouPPP) {
		zou.sessionWG = wg
	}
}

func doneWG(wg *sync.WaitGroup, once *sync.Once) {
	if wg != nil {
		if once != nil {
			once.Do(func() { wg.Done() })
		} else {
			wg.Done()
		}
	}
}

func addWG(wg *sync.WaitGroup, delta int) {
	if wg != nil {
		wg.Add(delta)
	}
}

// Dial dial PPPoE/LCP/PAPorCHAP/NCPs
func (zou *ZouPPP) Dial(ctx context.Context) {
	needTOTerminate := true
	atomic.StoreUint32(zou.state, StateDialing)
	defer func() {
		if needTOTerminate {
			zou.cancelMe()
		}
	}()
	zou.result.StartTime = time.Now()
	var childctx context.Context
	childctx, zou.cancelFunc = context.WithCancel(ctx)
	err := zou.pppoeProto.Dial(childctx)
	if err != nil {
		zou.logger.Error(err.Error())
		return
	}
	zou.logger.Info("pppoe open")
	zou.pppProto = lcp.NewPPP(childctx, zou.pppoeProto, zou.pppoeProto.GetLogger())
	defPeerRule, err := lcp.NewDefaultPeerOptionRule(zou.cfg.setup.AuthProto)
	if err != nil {
		zou.logger.Error(err.Error())
		return
	}
	zou.lcpProto = lcp.NewLCP(childctx, lcp.ProtoLCP, zou.pppProto, zou.lcpEvtHandler, lcp.WithPeerOptionRule(defPeerRule))
	err = zou.lcpProto.Open(childctx)
	if err != nil {
		zou.logger.Error(err.Error())
		return
	}
	zou.lcpProto.Up(childctx)
	needTOTerminate = false
}

// Close shutdown the client
func (zou *ZouPPP) Close() {
	zou.pppoeProto.Close()
	zou.cancelMe()
}

func (zou *ZouPPP) cancelMe() {
	s := atomic.LoadUint32(zou.state)
	zou.logger.Sugar().Debugf("zouppp stopped at state %v", stateStr(s))
	switch s {
	case StateClosed, StateClosing:
		return
	}
	switch s {
	case StateInitial, StateDialing:
		zou.reportDialResult()
	}
	if s == StateOpen {
		//no need to report result here, since the result should already been reported
		doneWG(zou.sessionWG, nil)
	}
	atomic.StoreUint32(zou.state, StateClosing)
	zou.cancelFunc()

}

func (zou *ZouPPP) reportDialResult() {
	doneWG(zou.dialWG, zou.onceDoneDialWG)
	zou.onceSendResult.Do(func() {
		zou.result.DialFinishTime = time.Now()
		zou.result.R = ResultFailure
		if atomic.LoadUint32(zou.state) == StateOpen {
			zou.result.R = ResultSuccess
		}
		if zou.cfg.setup.resultCh != nil {
			select {
			case <-zou.cfg.setup.stopResultCh:
				return
			default:
			}
			select {
			case <-zou.cfg.setup.stopResultCh:
				return
			case zou.cfg.setup.resultCh <- zou.result:
			}
		}
	})

}

func (zou *ZouPPP) waitForDialDone(ctx context.Context) {

	select {
	case <-ctx.Done(): //cancelled
		zou.ncpWG.Cancel()
		zou.ncpWG.Wait()
		atomic.StoreUint32(zou.state, StateClosed)
	case <-zou.ncpWG.FinishChan: //NCP dial finished
		addWG(zou.sessionWG, 1)
		zou.dialSucceed = true
		atomic.StoreUint32(zou.state, StateOpen)
	}
	if zou.cfg.setup.Apply {
		err := zou.createDatapath(ctx)
		if err != nil {
			zou.logger.Error(err.Error())
		}
	}
	zou.reportDialResult()
}

func (zou *ZouPPP) lcpEvtHandler(ctx context.Context, evt lcp.LayerNotifyEvent) {
	zou.logger.Sugar().Infof("LCP layer %v", evt)
	needTOTerminate := true
	defer func() {
		if needTOTerminate {
			zou.cancelMe()
		}
	}()
	switch evt {
	case lcp.LCPLayerNotifyUp:
		//run auth
		opauthlist := zou.lcpProto.PeerRule.GetOptions().Get(uint8(lcp.OpTypeAuthenticationProtocol))
		if len(opauthlist) == 0 {
			zou.logger.Error("no authentication method is negotiated")
			return
		}
		authProto := zou.lcpProto.PeerRule.GetOptions().Get(uint8(lcp.OpTypeAuthenticationProtocol))[0].(*lcp.LCPOpAuthProto).Proto
		switch authProto {
		case lcp.ProtoCHAP:
			chapProto := chap.NewCHAP(zou.cfg.UserName, zou.cfg.Password, zou.pppProto)
			err := chapProto.AUTHSelf()
			if err != nil {
				zou.logger.Sugar().Errorf("auth failed,%v", err)
				return
			}
			zou.logger.Info("auth succeed")
		case lcp.ProtoPAP:
			papProto := pap.NewPAP(zou.cfg.UserName, zou.cfg.Password, zou.pppProto)
			err := papProto.AuthSelf()
			if err != nil {
				zou.logger.Sugar().Errorf("auth failed,%v", err)
				return
			}
			zou.logger.Info("auth succeed")
		default:
			zou.logger.Sugar().Errorf("unkown auth method negoatied %v", authProto)
			return

		}
		launchWaitRoutine := false
		if zou.cfg.setup.IPv4 {
			zou.ipcpProto = lcp.NewLCP(ctx, lcp.ProtoIPCP, zou.pppProto, zou.ipcpEvtHandler,
				lcp.WithOwnOptionRule(lcp.NewDefaultIPCPOwnRule()),
				lcp.WithPeerOptionRule(&lcp.DefaultIPCPPeerRule{}),
			)
			err := zou.ipcpProto.Open(ctx)
			if err != nil {
				return
			}
			zou.ncpWG.Add(1)
			go zou.waitForDialDone(ctx)
			launchWaitRoutine = true
			zou.ipcpProto.Up(ctx)
		}
		if zou.cfg.setup.IPv6 {
			ipcp6rule := lcp.NewDefaultIP6CPRule(ctx, zou.pppoeProto.LocalAddr().(*pppoe.Endpoint).L2EP.HwAddr)
			zou.ipv6cpProto = lcp.NewLCP(ctx, lcp.ProtoIPv6CP, zou.pppProto, zou.ipcp6EvtHandler,
				lcp.WithOwnOptionRule(ipcp6rule),
				lcp.WithPeerOptionRule(ipcp6rule),
			)
			err := zou.ipv6cpProto.Open(ctx)
			if err != nil {
				return
			}
			zou.ncpWG.Add(1)
			if !launchWaitRoutine {
				go zou.waitForDialDone(ctx)
			}
			zou.ipv6cpProto.Up(ctx)
		}
	case lcp.LCPLayerNotifyDown, lcp.LCPLayerNotifyFinished:
		return
	default:
	}
	needTOTerminate = false
}

func (zou *ZouPPP) createDatapath(ctx context.Context) error {

	zou.createFastPathMux.Lock()
	defer zou.createFastPathMux.Unlock()
	if zou.fastpath != nil {
		return nil
	}
	zou.logger.Info("creating datapath")
	var err error
	mruop := zou.lcpProto.PeerRule.GetOptions().GetFirst((uint8(lcp.OpTypeMaximumReceiveUnit)))
	var mru uint16 = 1498
	if mruop != nil {
		mru = uint16(*(mruop.(*lcp.LCPOpMRU)))
	}

	var v6ifid []byte
	if zou.ipv6cpProto != nil {
		if ifidop := zou.ipv6cpProto.OwnRule.GetOption(uint8(lcp.IP6CPOpInterfaceIdentifier)); ifidop != nil {
			ifid := [8]byte(*ifidop.(*lcp.InterfaceIDOption))
			v6ifid = ifid[:]
		}
	}

	zou.fastpath, err = datapath.NewTUNIf(ctx, zou.pppProto, zou.cfg.PPPIfName,
		append(zou.assignedIANAs, zou.assignedV4Addr),
		v6ifid,
		mru,
	)
	if err != nil {
		return fmt.Errorf("failed to create datapath, %w", err)
	}
	return nil

}

// GetV6LLA returns the IPv6 LLA the compsoed of negotiated interface-id via IPv6CP
func (zou *ZouPPP) GetV6LLA() (net.IP, error) {
	if zou.ipv6cpProto != nil {
		if ifidop := zou.ipv6cpProto.OwnRule.GetOption(uint8(lcp.IP6CPOpInterfaceIdentifier)); ifidop != nil {
			ifid := [8]byte(*ifidop.(*lcp.InterfaceIDOption))
			lla := make([]byte, 16)
			copy(lla[:8], lcp.IPv6LinkLocalPrefix[:8])
			copy(lla[8:16], ifid[:])
			return lla, nil
		}
	}
	return nil, fmt.Errorf("ipv6cp is not up")
}

func (zou *ZouPPP) ipcpEvtHandler(ctx context.Context, evt lcp.LayerNotifyEvent) {
	zou.logger.Sugar().Infof("IPCP layer %v", evt)
	switch evt {
	case lcp.LCPLayerNotifyUp:
		defer zou.ncpWG.Done()
		if v4addrop := zou.ipcpProto.OwnRule.GetOption(uint8(lcp.OpIPAddress)); v4addrop != nil {
			zou.assignedV4Addr = v4addrop.(*lcp.IPv4AddrOption).Addr
		}
	case lcp.LCPLayerNotifyDown, lcp.LCPLayerNotifyFinished:
		zou.cancelMe()
		return
	}
}
func (zou *ZouPPP) dialDHCPv6(ctx context.Context) {
	defer zou.ncpWG.Done()
	if zou.cfg.setup.DHCPv6IANA || zou.cfg.setup.DHCPv6IAPD {
		zou.logger.Sugar().Infof("dialing DHCPv6 IANA %v IAPD %v", zou.cfg.setup.DHCPv6IANA, zou.cfg.setup.DHCPv6IAPD)
		childctx, cancel := context.WithCancel(ctx)
		econn := lcp.NewPPPConn(childctx, zou.pppProto, lcp.ProtoIPv6)
		defer econn.Close()
		defer cancel()
		lla, _ := zou.GetV6LLA()
		rudpconn, err := etherconn.NewSharingRUDPConn(fmt.Sprintf("[%v]:%v",
			lla, dhcpv6.DefaultClientPort), econn,
			[]etherconn.RUDPConnOption{etherconn.WithAcceptAny(true)})
		if err != nil {
			zou.logger.Sugar().Errorf("failed to create SharingRUDPConn %v", err)
			return
		}
		clnt, err := NewDHCP6Clnt(rudpconn, &DHCP6Cfg{
			Mac:    zou.cfg.Mac,
			Debug:  zou.cfg.setup.LogLevel == LogLvlDebug,
			NeedPD: zou.cfg.setup.DHCPv6IAPD,
			NeedNA: zou.cfg.setup.DHCPv6IANA,
		}, lla)
		if err != nil {
			zou.logger.Sugar().Errorf("failed to create DHCPv6 client, %v", err)
			return
		}
		err = clnt.Dial()
		if err != nil {
			zou.logger.Error(err.Error())
			return
		}
		zou.assignedIANAs = clnt.assignedIANAs
		zou.assignedIAPDs = clnt.assignedIAPDs

	}

}
func (zou *ZouPPP) ipcp6EvtHandler(ctx context.Context, evt lcp.LayerNotifyEvent) {
	zou.logger.Sugar().Infof("IPv6CP layer %v", evt)
	switch evt {
	case lcp.LCPLayerNotifyUp:
		defer zou.ncpWG.Done()
		zou.ncpWG.Add(1)
		go zou.dialDHCPv6(ctx)

	case lcp.LCPLayerNotifyDown, lcp.LCPLayerNotifyFinished:
		zou.cancelMe()
		return
	}
}

// Result is the ZouPPP dial result
type Result int

const (
	// ResultSuccess means dialing succeed
	ResultSuccess Result = iota
	// ResultFailure means dialing failed
	ResultFailure
)

func (er Result) String() string {
	switch er {
	case ResultSuccess:
		return "success"
	case ResultFailure:
		return "failed"
	default:
		return "unknow result"
	}
}

// DialResult contains ZouPPP dailing result info
type DialResult struct {
	// R is the result
	R Result
	// PPPoEEP is the PPPOEEndpoint, identify the ZouPPP
	PPPoEEP *pppoe.Endpoint
	// StartTime is when dailing starts
	StartTime time.Time
	// DialFinishTime is when dailing finishes
	DialFinishTime time.Time
}

// Setup holds common configruation for creating one or mulitple ZouPPP sessions
type Setup struct {
	// logger
	logger *zap.Logger
	// Ifname is the binding intereface name
	Ifname string `alias:"i" usage:"listening interface name"`
	// NumOfClients is the number of clients to be created
	NumOfClients uint `alias:"n" usage:"number of PPPoE clients"`
	// StartMAC is the starting mac address for all the sessions
	StartMAC net.HardwareAddr `alias:"mac" usage:"start MAC address"`
	// MacStep is the mac address step to increase for each session
	MacStep uint `usage:"MAC step to increase for each client"`
	// StartVLANs is the starting vlans for all the sessions
	StartVLANs etherconn.VLANs `alias:"vlan" usage:"start VLAN id, could be Dot1q or QinQ"`
	// VLANStep is the vlan step to increase for each session
	VLANStep uint `usage:"VLAN step to increase for each client"`
	// ExcludedVLANs is the slice of vlan id to skip, apply to all layer of vlans
	ExcludedVLANs []uint16 `usage:"a list of excluded VLAN id, apply to all layer of vlans"`
	// Interval is the amount of time to wait between launching each session
	Interval time.Duration `usage:"amount of time to wait between launching each session"`
	LogLevel LoggingLvl    `alias:"l" usage:"log levl, err|info|debug"`
	// if Apply is true, then create a PPP interface with assigned addresses; could be set to false if only to test protocol
	Apply bool `usage:"if Apply is true, then create a PPP interface with assigned addresses; could be set to false if only to test protocol"`
	// number of Retries
	Retry   uint          `usage:"number of setup retry"`
	Timeout time.Duration `usage:"setup timeout"`
	// AuthProto is the authenticaiton protocol to use, e.g. lcp.ProtoCHAP
	AuthProto lcp.PPPProtocolNumber `usage:"auth protocol, PAP or CHAP"`
	// each ZouPPP session will send dialing result to resultCh
	resultCh chan *DialResult
	// close stopResultCh as signal result collecting should stop
	stopResultCh chan struct{}
	// RID is the BBF remote-id PPPoE tag
	RID string `usage:"BBF remote-id"`
	// CID is the BBF circuit-id PPPoE tag
	CID string `usage:"BBF circuit-id"`
	// UserName for PAP/CHAP auth
	UserName string `alias:"u" usage:"PAP/CHAP username"`
	// Password for PAP/CHAP auth
	Password string `alias:"p" usage:"PAP/CHAP password"`
	// the name of PPP interface created after successfully dialing
	PPPIfName string `usage:"name of PPP interface created after successfully dialing, must contain @ID"`
	// Run IPCP if true
	IPv4 bool `alias:"v4" usage:"run IPCP"`
	// Run IPv6CP if true
	IPv6 bool `alias:"v6" usage:"run IPv6CP"`
	// run DHCPv6 over PPP if true
	DHCPv6IANA bool `usage:"run DHCPv6 over PPP to get an IANA address"`
	DHCPv6IAPD bool `usage:"run DHCPv6 over PPP to get an IAPD prefix"`
	// enable profiling for dev
	Profiling bool `usage:"enable profiling, dev use only"`
	// use XDP to forward packet
	XDP bool `usage:"use XDP to forward packet"`
}

const resultChannelDepth = 128

// DefaultSetup returns a Setup with following defaults:
// - no vlan, use the mac of interface ifname
// - no debug
// - single client
// - CHAP, IPv4 only
func DefaultSetup() *Setup {
	r := new(Setup)
	r.resultCh = make(chan *DialResult, resultChannelDepth)
	r.stopResultCh = make(chan struct{})
	// r.logger, err = NewDefaultZouPPPLogger(LogLvlErr)
	// if err != nil {
	// 	return nil, err
	// }
	// if ifname == "" || uname == "" {
	// 	return nil, fmt.Errorf("ifname or username is empty")
	// }
	// iff, err := net.InterfaceByName(ifname)
	// if err != nil {
	// 	return nil, fmt.Errorf("can't find interface %v,%w", ifname, err)
	// }

	// r.Ifname = ifname
	r.NumOfClients = 1
	// r.StartMAC = iff.HardwareAddr
	r.Apply = true
	r.AuthProto = lcp.ProtoCHAP
	// r.UserName = uname
	// r.Password = upass
	r.PPPIfName = DefaultPPPIfNameTemplate
	r.IPv4 = true
	r.IPv6 = false
	return r
}

func (setup *Setup) Init() error {
	var err error
	setup.logger, err = NewDefaultZouPPPLogger(setup.LogLevel)
	if err != nil {
		return err
	}
	if setup.Ifname == "" {
		return fmt.Errorf("interface name can't be empty")
	}
	if setup.NumOfClients == 0 {
		return fmt.Errorf("number of clients can't be zero")
	}
	iff, err := net.InterfaceByName(setup.Ifname)
	if err != nil {
		return fmt.Errorf("can't find interface %v,%w", setup.Ifname, err)
	}
	if len(setup.StartMAC) == 0 {
		setup.StartMAC = iff.HardwareAddr
	}
	if !strings.Contains(setup.PPPIfName, VarName) {
		return fmt.Errorf("ppp interface name must contain %v", VarName)
	}
	return nil
}

func (setup *Setup) excluded(vids []uint16) bool {
	for _, vid := range vids {
		for _, extv := range setup.ExcludedVLANs {
			if extv == vid {
				return true
			}
		}
	}
	return false
}

func (setup *Setup) Close() {
	close(setup.stopResultCh)
}

func (setup *Setup) Logger() *zap.Logger {
	return setup.logger
}

// Config hold client specific configuration
type Config struct {
	Mac       net.HardwareAddr
	VLANs     etherconn.VLANs
	setup     *Setup
	RID       string
	CID       string
	UserName  string
	Password  string
	PPPIfName string
}

// NewDefaultZouPPPLogger create a default logger with specified log level
func NewDefaultZouPPPLogger(logl LoggingLvl) (*zap.Logger, error) {
	cfg := &zap.Config{
		Encoding:    "console",
		Level:       zap.NewAtomicLevelAt(logLvlToZapLvl(logl)),
		OutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:       "message",
			LevelKey:         "level",
			NameKey:          "name",
			CallerKey:        "caller",
			TimeKey:          "time",
			EncodeLevel:      zapcore.CapitalLevelEncoder,
			EncodeTime:       zapcore.TimeEncoderOfLayout("2006-01-02/15:04:05"),
			EncodeCaller:     zapcore.ShortCallerEncoder,
			ConsoleSeparator: " ",
		},
	}
	return cfg.Build()
}

// GenClientConfigurations creates clients specific configruations per setup
func GenClientConfigurations(setup *Setup) ([]*Config, error) {
	r := []*Config{}
	clntmac := setup.StartMAC
	vlans := setup.StartVLANs
	var err error
	for i := 0; i < int(setup.NumOfClients); i++ {
		ccfg := Config{}
		ccfg.setup = setup
		//assign mac
		ccfg.Mac = clntmac
		if i > 0 {
			ccfg.Mac, err = myaddr.IncMACAddr(clntmac, big.NewInt(int64(setup.MacStep)))
			if err != nil {
				return nil, fmt.Errorf("failed to generate mac address,%v", err)
			}

		}
		clntmac = ccfg.Mac
		//assign vlan
		ccfg.VLANs = vlans.Clone()

		incvidFunc := func(ids, excludes []uint16, step int) ([]uint16, error) {
			newids := ids
			for i := 0; i < 10; i++ {
				newids, err = myaddr.IncreaseVLANIDs(newids, step)
				if err != nil {
					return []uint16{}, err
				}
				excluded := false
			L1:
				for _, v := range newids {
					for _, exc := range excludes {
						if v == exc {
							excluded = true
							break L1
						}
					}
				}
				if !excluded {
					return newids, nil
				}
			}
			return []uint16{}, fmt.Errorf("you shouldn't see this")
		}

		if (len(vlans) > 0 && i > 0) || setup.excluded(vlans.IDs()) {
			rids, err := incvidFunc(vlans.IDs(), setup.ExcludedVLANs, int(setup.VLANStep))
			if err != nil {
				return nil, fmt.Errorf("failed to generate vlan id,%v", err)
			}
			err = ccfg.VLANs.SetIDs(rids)
			if err != nil {
				return nil, fmt.Errorf("failed to generate and apply vlan id,%v", err)
			}
		}
		vlans = ccfg.VLANs
		//options

		ccfg.RID = genStrFunc(setup.RID, i)
		ccfg.CID = genStrFunc(setup.CID, i)
		ccfg.UserName = genStrFunc(setup.UserName, i)
		ccfg.Password = genStrFunc(setup.Password, i)
		ccfg.PPPIfName = genStrFunc(setup.PPPIfName, i)
		if ccfg.PPPIfName == setup.PPPIfName {
			return nil, fmt.Errorf("PPP interface name doesn't contain %v", VarName)
		}
		r = append(r, &ccfg)
	}
	return r, nil
}

// ResultSummary is the summary stats of dialup results
type ResultSummary struct {
	// Total is the total number of sessions
	Total uint
	// Success is the total number of sessions suceessfully finished dailup
	Success uint
	// Failed is the total number of sessions failed to finish dailup
	Failed uint
	// LessThanTenSecond is the total number of sessions suceessfully finished dailup within 10 seconds
	LessThanTenSecond uint
	// Shortest is the amount of time that fastest session finishes dialup successfully
	Shortest time.Duration
	// Longest is the amount of time that the slowest session finishes dialup successfully
	Longest time.Duration
	// SuccessTotalTime is the total amount of time of all success session finish dialup
	SuccessTotalTime time.Duration
	// TotalTime is the total amount of time of all session finish dialup
	TotalTime time.Duration
	// AvgSuccessTime is the average amount of time of a success session finish dialup
	AvgSuccessTime time.Duration
	setup          *Setup
}

func (rs ResultSummary) String() string {
	r := "Result Summary\n"
	r += fmt.Sprintf("total: %d\n", rs.Total)
	r += fmt.Sprintf("Success:%d\n", rs.Success)
	r += fmt.Sprintf("Failed:%d\n", rs.Failed)
	r += fmt.Sprintf("Duration:%v\n", rs.TotalTime)
	r += fmt.Sprintf("Interval:%v\n", rs.setup.Interval)
	totalSuccessSeconds := (float64(rs.SuccessTotalTime) / float64(time.Second))
	if totalSuccessSeconds == 0 {
		r += fmt.Sprintln(`Setup rate: n\a`)
	} else {
		r += fmt.Sprintf("Setup rate:%v\n", float64(rs.Success)/totalSuccessSeconds)
	}

	r += fmt.Sprintf("Fastest success:%v\n", rs.Shortest)
	r += fmt.Sprintf("Success within 10 seconds:%v\n", rs.LessThanTenSecond)
	r += fmt.Sprintf("Slowest success:%v\n", rs.Longest)
	r += fmt.Sprintf("Avg success time:%v\n", rs.AvgSuccessTime)
	return r
}

const maxDuration = time.Duration(int64(^uint64(0) >> 1))

// CollectResults use setup.ResultCh to collect dialup results, and generate a ResultSummary in the end, send it via resultch
func CollectResults(setup *Setup, resultch chan *ResultSummary) {
	summary := new(ResultSummary)
	summary.setup = setup
	totalSuccessTime := time.Duration(0)
	summary.Shortest = maxDuration
	summary.Longest = time.Duration(0)
	var beginTime, endTime time.Time
	beginTime = time.Now()
L1:
	for {
		select {
		case <-setup.stopResultCh:
			break L1
		case r := <-setup.resultCh:
			completeTime := r.DialFinishTime.Sub(r.StartTime)
			if completeTime < 0 {
				completeTime = 0
			}
			switch r.R {
			case ResultSuccess:
				summary.Success++
				if completeTime < 10*time.Second {
					summary.LessThanTenSecond++
				}
				if completeTime > summary.Longest {
					summary.Longest = completeTime
				}
				if completeTime < summary.Shortest {
					summary.Shortest = completeTime
				}
				totalSuccessTime += completeTime
			case ResultFailure:
				summary.Failed++
			}
			if r.StartTime.Before(beginTime) {
				beginTime = r.StartTime
			}
			if r.R == ResultSuccess {
				if r.DialFinishTime.After(endTime) {
					endTime = r.DialFinishTime
				}
			}
			summary.Total++
			if summary.Total == setup.NumOfClients {
				break L1
			}

		}
	}
	if summary.Success != 0 {
		summary.AvgSuccessTime = totalSuccessTime / time.Duration(summary.Success)
	} else {
		summary.AvgSuccessTime = 0
	}
	summary.SuccessTotalTime = endTime.Sub(beginTime)
	if summary.Shortest == maxDuration {
		summary.Shortest = 0
	}
	resultch <- summary
}

// DefaultPPPIfNameTemplate is the default PPP interface name
const DefaultPPPIfNameTemplate = "zouppp@ID"

// LoggingLvl is the logging level of client
type LoggingLvl uint

const (
	// LogLvlErr only log error msg
	LogLvlErr LoggingLvl = iota
	// LogLvlInfo logs error + info msg
	LogLvlInfo
	// LogLvlDebug logs error + info + debug msg
	LogLvlDebug
)

func (lvl LoggingLvl) MarshalText() (text []byte, err error) {
	switch lvl {
	case LogLvlErr:
		return []byte("err"), nil
	case LogLvlInfo:
		return []byte("info"), nil
	case LogLvlDebug:
		return []byte("debug"), nil
	}
	return nil, fmt.Errorf("unknown logging lvl %d", lvl)
}

func (lvl *LoggingLvl) UnmarshalText(text []byte) error {
	input := strings.TrimSpace(strings.ToLower(string(text)))
	switch input {
	case "err":
		*lvl = LogLvlErr
	case "info":
		*lvl = LogLvlInfo
	case "debug":
		*lvl = LogLvlDebug
	default:
		return fmt.Errorf("unknown logging level, %s", string(text))
	}
	return nil
}

func logLvlToZapLvl(l LoggingLvl) zapcore.Level {
	switch l {
	case LogLvlErr:
		return zapcore.ErrorLevel
	case LogLvlInfo:
		return zapcore.InfoLevel
	default:
		return zapcore.DebugLevel
	}
}

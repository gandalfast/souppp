package client

import (
	"errors"
	"fmt"
	"github.com/gandalfast/souppp/ppp"
	"github.com/rs/zerolog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// _varName is the placeholder in PPP IfName that will be replaced by client id
const _varName = "@ID"

func genStrFunc(s string, id int) string {
	if !strings.Contains(s, _varName) {
		return s
	}
	return strings.ReplaceAll(s, _varName, strconv.Itoa(id))
}

// _defaultPPPIfNameTemplate is the default PPP interface name
const _defaultPPPIfNameTemplate = "souppp@ID"

// Setup holds common configuration for creating one or multiple Client sessions
type Setup struct {
	Logger   *zerolog.Logger
	LogLevel LoggingLvl

	// if Apply is true, then create a PPP TUN interface with assigned addresses
	Apply bool
	// Timeout is the connection setup time limit
	Timeout time.Duration
	// NumOfClients is the number of clients to be created
	NumOfClients uint
	// StartMAC is the starting MAC address for all the sessions
	StartMAC net.HardwareAddr
	// MacStep is the mac address step to increase for each session
	MacStep uint

	// InterfaceName is the binding ethernet interface name
	InterfaceName string
	// Name of PPP interface created after successfully dialing, must contain @ID
	PPPInterfaceName string
	// RID is the BBF remote-id PPPoE tag
	RID string
	// CID is the BBF circuit-id PPPoE tag
	CID string
	// AuthProto is the authentication protocol to use, e.g. lcp.ProtoCHAP or lcp.ProtoPAP
	AuthProto ppp.ProtocolNumber
	// UserName for PAP/CHAP auth
	UserName string
	// Password for PAP/CHAP auth
	Password string
	// Run IPCP if true
	IPv4 bool
	// Run IPv6CP if true
	IPv6 bool
	// Run DHCPv6 over PPP if true
	DHCPv6IANA bool
	DHCPv6IAPD bool
}

// DefaultSetup returns a basic default Setup with following defaults:
// - no vlan, use the mac of interface ifname
// - no debug mode
// - 10 seconds dial timeout
// - single client
// - CHAP, IPv4 only
func DefaultSetup() *Setup {
	return &Setup{
		NumOfClients:     1,
		Apply:            true,
		AuthProto:        ppp.ProtoCHAP,
		PPPInterfaceName: _defaultPPPIfNameTemplate,
		IPv4:             true,
		IPv6:             false,
		Timeout:          10 * time.Second,
	}
}

func (setup *Setup) Validate() error {
	if setup.Logger == nil {
		logger, err := newDefaultLogger(setup.LogLevel)
		if err != nil {
			return err
		}
		setup.Logger = logger
	}

	if setup.InterfaceName == "" {
		return errors.New("interface name can't be empty")
	} else if setup.NumOfClients == 0 {
		return errors.New("number of clients can't be zero")
	} else if !strings.Contains(setup.PPPInterfaceName, _varName) {
		return errors.New("ppp interface name must contain " + _varName)
	}

	if len(setup.StartMAC) == 0 {
		iff, err := net.InterfaceByName(setup.InterfaceName)
		if err != nil {
			return fmt.Errorf("can't find interface %v,%w", setup.InterfaceName, err)
		}
		setup.StartMAC = iff.HardwareAddr
	}

	if setup.NumOfClients > 1 && setup.MacStep == 0 {
		setup.MacStep = 1
	}

	return nil
}

func (setup *Setup) Clone(index int) *Setup {
	return &Setup{
		Logger:           setup.Logger,
		LogLevel:         setup.LogLevel,
		Apply:            setup.Apply,
		Timeout:          setup.Timeout,
		NumOfClients:     setup.NumOfClients,
		StartMAC:         setup.StartMAC,
		MacStep:          setup.MacStep,
		InterfaceName:    setup.InterfaceName,
		PPPInterfaceName: genStrFunc(setup.PPPInterfaceName, index),
		RID:              genStrFunc(setup.RID, index),
		CID:              genStrFunc(setup.CID, index),
		AuthProto:        setup.AuthProto,
		UserName:         genStrFunc(setup.UserName, index),
		Password:         genStrFunc(setup.Password, index),
		IPv4:             setup.IPv4,
		IPv6:             setup.IPv6,
		DHCPv6IANA:       setup.DHCPv6IANA,
		DHCPv6IAPD:       setup.DHCPv6IAPD,
	}
}

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

// newDefaultLogger create a default Logger with specified log level
func newDefaultLogger(logl LoggingLvl) (*zerolog.Logger, error) {
	logger := zerolog.New(os.Stdout).Level(logLvlToZapLvl(logl))
	return &logger, nil
}

func logLvlToZapLvl(l LoggingLvl) zerolog.Level {
	switch l {
	case LogLvlErr:
		return zerolog.ErrorLevel
	case LogLvlInfo:
		return zerolog.InfoLevel
	default:
		return zerolog.DebugLevel
	}
}

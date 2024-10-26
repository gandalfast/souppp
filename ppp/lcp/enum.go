package lcp

import "fmt"

// MsgCode is the LCP message Code
type MsgCode uint8

// LCP message codes
const (
	CodeConfigureRequest MsgCode = 0x01
	CodeConfigureAck     MsgCode = 0x02
	CodeConfigureNak     MsgCode = 0x03
	CodeConfigureReject  MsgCode = 0x04
	CodeTerminateRequest MsgCode = 0x05
	CodeTerminateAck     MsgCode = 0x06
	CodeCodeReject       MsgCode = 0x07
	CodeProtocolReject   MsgCode = 0x08
	CodeEchoRequest      MsgCode = 0x09
	CodeEchoReply        MsgCode = 0x0A
	CodeDiscardRequest   MsgCode = 0x0B
)

func (code MsgCode) String() string {
	switch code {
	case CodeConfigureRequest:
		return "ConfReq"
	case CodeConfigureAck:
		return "ConfACK"
	case CodeConfigureNak:
		return "ConfNak"
	case CodeConfigureReject:
		return "ConfReject"
	case CodeTerminateRequest:
		return "TermReq"
	case CodeTerminateAck:
		return "TermACK"
	case CodeCodeReject:
		return "CodeReject"
	case CodeProtocolReject:
		return "ProtoReject"
	case CodeEchoRequest:
		return "EchoReq"
	case CodeEchoReply:
		return "EchoReply"
	case CodeDiscardRequest:
		return "DiscardReq"
	default:
		return fmt.Sprintf("unknown (%d)", uint8(code))
	}
}

// OptionType is the LCP option type
type OptionType uint8

// LCP option types
const (
	OpTypeMaximumReceiveUnit                OptionType = 0x01
	OpTypeAuthenticationProtocol            OptionType = 0x03
	OpTypeQualityProtocol                   OptionType = 0x04
	OpTypeMagicNumber                       OptionType = 0x05
	OpTypeProtocolFieldCompression          OptionType = 0x07
	OpTypeAddressandControlFieldCompression OptionType = 0x08
)

func (op OptionType) String() string {
	switch op {
	case OpTypeMaximumReceiveUnit:
		return "MRU"
	case OpTypeAuthenticationProtocol:
		return "AuthProto"
	case OpTypeQualityProtocol:
		return "QualityProto"
	case OpTypeMagicNumber:
		return "MagicNum"
	case OpTypeProtocolFieldCompression:
		return "ProtoFieldComp"
	case OpTypeAddressandControlFieldCompression:
		return "AddContrlFieldComp"
	default:
		return fmt.Sprintf("unknown (%d)", uint8(op))
	}
}

// State is the LCP protocol state
type State uint32

// LCP protocol state as defined in RFC1661
const (
	StateInitial State = iota
	StateStarting
	StateClosed
	StateStopped
	StateClosing
	StateStopping
	StateReqSent
	StateAckRcvd
	StateAckSent
	StateOpened
	StateEchoReqSent
)

func (s State) String() string {
	switch s {
	case StateInitial:
		return "Initial"
	case StateStarting:
		return "Starting"
	case StateClosed:
		return "Closed"
	case StateStopped:
		return "Stopped"
	case StateClosing:
		return "Closing"
	case StateStopping:
		return "Stopping"
	case StateReqSent:
		return "ReqSent"
	case StateAckRcvd:
		return "AckRcvd"
	case StateAckSent:
		return "AckSent"
	case StateOpened:
		return "Opened"
	case StateEchoReqSent:
		return "EchoReqSent"
	default:
		return fmt.Sprintf("unknown (%d)", uint32(s))
	}
}

// CHAPAuthAlg is the auth algorithm of CHAP
type CHAPAuthAlg uint8

// List of CHAP algorithms
const (
	AlgNone            CHAPAuthAlg = 0x00
	AlgCHAPwithMD5     CHAPAuthAlg = 0x05
	AlgSHA1            CHAPAuthAlg = 0x06
	AlgCHAPwithSHA256  CHAPAuthAlg = 0x07
	AlgCHAPwithSHA3256 CHAPAuthAlg = 0x08
	AlgMSCHAP          CHAPAuthAlg = 0x80
	AlgMSCHAP2         CHAPAuthAlg = 0x81
)

func (alg CHAPAuthAlg) String() string {
	switch alg {
	case AlgNone:
		return ""
	case AlgCHAPwithMD5:
		return "AlgCHAPwithMD5"
	case AlgSHA1:
		return "AlgSHA1"
	case AlgCHAPwithSHA256:
		return "AlgCHAPwithSHA256"
	case AlgCHAPwithSHA3256:
		return "AlgCHAPwithSHA3256"
	case AlgMSCHAP:
		return "AlgMSCHAP"
	case AlgMSCHAP2:
		return "AlgMSCHAP2"
	default:
		return fmt.Sprintf("unknown (%d)", uint8(alg))
	}
}

// LayerNotifyEvent is the tlu/tld/tls/tlf event defined in RFC1661
type LayerNotifyEvent uint8

// List of LayerNotifyEvent
const (
	LayerNotifyUp LayerNotifyEvent = iota
	LayerNotifyDown
	LayerNotifyStarted
	LayerNotifyFinished
)

func (n LayerNotifyEvent) String() string {
	switch n {
	case LayerNotifyUp:
		return "up"
	case LayerNotifyDown:
		return "down"
	case LayerNotifyStarted:
		return "started"
	case LayerNotifyFinished:
		return "finished"
	default:
		return fmt.Sprintf("unknown (%d)", uint8(n))
	}
}

// IPCPOptionType is the option type for IPCP
type IPCPOptionType uint8

// List of IPCP option type
const (
	OpIPAddresses                IPCPOptionType = 0x01
	OpIPCompressionProtocol      IPCPOptionType = 0x02
	OpIPAddress                  IPCPOptionType = 0x03
	OpMobileIPv4                 IPCPOptionType = 0x04
	OpPrimaryDNSServerAddress    IPCPOptionType = 0x81
	OpPrimaryNBNSServerAddress   IPCPOptionType = 0x82
	OpSecondaryDNSServerAddress  IPCPOptionType = 0x83
	OpSecondaryNBNSServerAddress IPCPOptionType = 0x84
)

func (o IPCPOptionType) String() string {
	switch o {
	case OpIPAddresses:
		return "IPAddresses"
	case OpIPCompressionProtocol:
		return "IPCompressionProtocol"
	case OpIPAddress:
		return "IPAddress"
	case OpMobileIPv4:
		return "MobileIPv4"
	case OpPrimaryDNSServerAddress:
		return "PrimaryDNSServerAddress"
	case OpPrimaryNBNSServerAddress:
		return "PrimaryNBNSServerAddress"
	case OpSecondaryDNSServerAddress:
		return "SecondaryDNSServerAddress"
	case OpSecondaryNBNSServerAddress:
		return "SecondaryNBNSServerAddress"
	default:
		return fmt.Sprintf("unknown (%d)", uint8(o))
	}
}

// IPCP6OptionType is the option type for IPv6CP
type IPCP6OptionType uint8

// List of IPv6CP option type
const (
	IP6CPOpInterfaceIdentifier     IPCP6OptionType = 0x01
	IP6CPOpIPv6CompressionProtocol IPCP6OptionType = 0x02
)

func (code IPCP6OptionType) String() string {
	switch code {
	case IP6CPOpInterfaceIdentifier:
		return "InterfaceIdentifier"
	case IP6CPOpIPv6CompressionProtocol:
		return "IPv6CompressionProtocol"
	default:
		return fmt.Sprintf("unknown (%d)", uint8(code))
	}
}

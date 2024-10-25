package pppoe

import "fmt"

// Code is the PPPoE msg code
type Code uint8

// List of PPPoE msg code
const (
	CodeSession Code = 0x00
	CodePADO    Code = 0x07
	CodePADI    Code = 0x09
	CodePADR    Code = 0x19
	CodePADS    Code = 0x65
	CodePADT    Code = 0xA7
)

// String return a string representation of code
func (code Code) String() string {
	switch code {
	case CodeSession:
		return "session"
	case CodePADO:
		return "PADO"
	case CodePADI:
		return "PADI"
	case CodePADR:
		return "PADR"
	case CodePADS:
		return "PADS"
	case CodePADT:
		return "PADT"
	default:
		return fmt.Sprintf("unknown (%d)", code)
	}
}

// TagType is the PPPoE tag type
type TagType uint16

// a list of PPPoE tag type
const (
	TagTypeEndOfList         TagType = 0
	TagTypeServiceName       TagType = 257
	TagTypeACName            TagType = 258
	TagTypeHostUniq          TagType = 259
	TagTypeACCookie          TagType = 260
	TagTypeVendorSpecific    TagType = 261
	TagTypeCredits           TagType = 262
	TagTypeMetrics           TagType = 263
	TagTypeSequenceNumber    TagType = 264
	TagTypeCreditScaleFactor TagType = 265
	TagTypeRelaySessionID    TagType = 272
	TagTypeHURL              TagType = 273
	TagTypeMOTM              TagType = 274
	TagTypePPPMaxPayload     TagType = 288
	TagTypeIPRouteAdd        TagType = 289
	TagTypeServiceNameError  TagType = 513
	TagTypeACSystemError     TagType = 514
	TagTypeGenericError      TagType = 515
)

func (tag TagType) String() string {
	switch tag {
	case TagTypeEndOfList:
		return "EndofList"
	case TagTypeServiceName:
		return "SvcName"
	case TagTypeACName:
		return "ACName"
	case TagTypeHostUniq:
		return "HostUniq"
	case TagTypeACCookie:
		return "ACCookie"
	case TagTypeVendorSpecific:
		return "VendorSpecific"
	case TagTypeCredits:
		return "Credits"
	case TagTypeMetrics:
		return "Metrics"
	case TagTypeSequenceNumber:
		return "SequenceNumber"
	case TagTypeCreditScaleFactor:
		return "CreditScaleFactor"
	case TagTypeRelaySessionID:
		return "RelaySessionId"
	case TagTypeHURL:
		return "HURL"
	case TagTypeMOTM:
		return "MOTM"
	case TagTypePPPMaxPayload:
		return "PPPMaxPayload"
	case TagTypeIPRouteAdd:
		return "IPRouteAdd"
	case TagTypeServiceNameError:
		return "ServiceNameError"
	case TagTypeACSystemError:
		return "ACSystemError"
	case TagTypeGenericError:
		return "GenericError"
	default:
		return fmt.Sprintf("unknown (%d)", tag)
	}
}

// BBFSubTagNum is the BBF sub tag type
type BBFSubTagNum uint8

// a list of BBF sub tag type
const (
	BBFSubTagNumCircuitID                      BBFSubTagNum = 0x01
	BBFSubTagNumRemoteID                       BBFSubTagNum = 0x02
	BBFSubTagActualDataRateUpstream            BBFSubTagNum = 0x81
	BBFSubTagActualDataRateDownstream          BBFSubTagNum = 0x82
	BBFSubTagMinimumDataRateUpstream           BBFSubTagNum = 0x83
	BBFSubTagMinimumDataRateDownstream         BBFSubTagNum = 0x84
	BBFSubTagAttainableDataRateUpstream        BBFSubTagNum = 0x85
	BBFSubTagAttainableDataRateDownstream      BBFSubTagNum = 0x86
	BBFSubTagMaximumDataRateUpstream           BBFSubTagNum = 0x87
	BBFSubTagMaximumDataRateDownstream         BBFSubTagNum = 0x88
	BBFSubTagMinDataRateUpstreaminlow          BBFSubTagNum = 0x89
	BBFSubTagMinimumDataRateDownstreaminlow    BBFSubTagNum = 0x8A
	BBFSubTagMaxInterleavingDelay              BBFSubTagNum = 0x8B
	BBFSubTagActualInterleavingUpstreamDelay   BBFSubTagNum = 0x8C
	BBFSubTagMaximumInterleavingDelay          BBFSubTagNum = 0x8D
	BBFSubTagActualInterleavingDownstreamDelay BBFSubTagNum = 0x8E
	BBFSubTagDataLinkEncap                     BBFSubTagNum = 0x90
	BBFSubTagIWFSessionFlag                    BBFSubTagNum = 0xFE
)

// String returns a string representation of t
func (t BBFSubTagNum) String() string {
	switch t {
	case BBFSubTagNumCircuitID:
		return "CircuitID"
	case BBFSubTagNumRemoteID:
		return "RemoteID"
	case BBFSubTagActualDataRateUpstream:
		return "ActualDataRateUpstream"
	case BBFSubTagActualDataRateDownstream:
		return "ActualDataRateDownstream"
	case BBFSubTagMinimumDataRateUpstream:
		return "MinimumDataRateUpstream"
	case BBFSubTagMinimumDataRateDownstream:
		return "MinimumDataRateDownstream"
	case BBFSubTagAttainableDataRateUpstream:
		return "AttainableDataRateUpstream"
	case BBFSubTagAttainableDataRateDownstream:
		return "AttainableDataRateDownstream"
	case BBFSubTagMaximumDataRateUpstream:
		return "MaximumDataRateUpstream"
	case BBFSubTagMaximumDataRateDownstream:
		return "MaximumDataRateDownstream"
	case BBFSubTagMinDataRateUpstreaminlow:
		return "MinDataRateUpstreaminlow"
	case BBFSubTagMinimumDataRateDownstreaminlow:
		return "MinimumDataRateDownstreaminlow"
	case BBFSubTagMaxInterleavingDelay:
		return "MaxInterleavingDelay"
	case BBFSubTagActualInterleavingUpstreamDelay:
		return "ActualInterleavingUpstreamDelay"
	case BBFSubTagMaximumInterleavingDelay:
		return "MaximumInterleavingDelay"
	case BBFSubTagActualInterleavingDownstreamDelay:
		return "ActualInterleavingDownstreamDelay"
	case BBFSubTagDataLinkEncap:
		return "DataLinkEncap"
	case BBFSubTagIWFSessionFlag:
		return "IWFSessionFlag"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

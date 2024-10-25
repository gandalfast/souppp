package ppp

import "fmt"

// ProtocolNumber is the PPP protocol number
type ProtocolNumber uint16

// List of PPP protocol number
const (
	ProtoNone                                        ProtocolNumber = 0x00
	ProtoPAD                                         ProtocolNumber = 0x01
	ProtoIPv4                                        ProtocolNumber = 0x21
	ProtoIPv6                                        ProtocolNumber = 0x57
	ProtoLCP                                         ProtocolNumber = 0xc021
	ProtoPAP                                         ProtocolNumber = 0xc023
	ProtoCHAP                                        ProtocolNumber = 0xc223
	ProtoEAP                                         ProtocolNumber = 0xc227
	ProtoIPCP                                        ProtocolNumber = 0x8021
	ProtoIPv6CP                                      ProtocolNumber = 0x8057
	ProtoROHCsmallCID                                ProtocolNumber = 0x03
	ProtoROHClargeCID                                ProtocolNumber = 0x05
	ProtoOSINetworkLayer                             ProtocolNumber = 0x23
	ProtoXeroxNSIDP                                  ProtocolNumber = 0x25
	ProtoDECnetPhaseIV                               ProtocolNumber = 0x27
	ProtoAppletalk                                   ProtocolNumber = 0x29
	ProtoNovellIPX                                   ProtocolNumber = 0x002b
	ProtoVanJacobsonCompressedTCPIP                  ProtocolNumber = 0x002d
	ProtoVanJacobsonUncompressedTCPIP                ProtocolNumber = 0x002f
	ProtoBridgingPDU                                 ProtocolNumber = 0x31
	ProtoStreamProtocol                              ProtocolNumber = 0x33
	ProtoBanyanVines                                 ProtocolNumber = 0x35
	ProtoUnassigned                                  ProtocolNumber = 0x37
	ProtoAppleTalkEDDP                               ProtocolNumber = 0x39
	ProtoAppleTalkSmartBuffered                      ProtocolNumber = 0x003b
	ProtoMultiLink                                   ProtocolNumber = 0x003d
	ProtoNETBIOSFraming                              ProtocolNumber = 0x003f
	ProtoCiscoSystems                                ProtocolNumber = 0x41
	ProtoAscomTimeplex                               ProtocolNumber = 0x43
	ProtoFujitsuLinkBackupandLoadBalancing           ProtocolNumber = 0x45
	ProtoDCARemoteLan                                ProtocolNumber = 0x47
	ProtoSerialDataTransportProtocol                 ProtocolNumber = 0x49
	ProtoSNAover802                                  ProtocolNumber = 0x004b
	ProtoSNA                                         ProtocolNumber = 0x004d
	ProtoIPv6HeaderCompression                       ProtocolNumber = 0x004f
	ProtoKNXBridgingData                             ProtocolNumber = 0x51
	ProtoEncryption                                  ProtocolNumber = 0x53
	ProtoIndividualLinkEncryption                    ProtocolNumber = 0x55
	ProtoPPPMuxing                                   ProtocolNumber = 0x59
	ProtoVendorSpecificNetworkProtocol               ProtocolNumber = 0x005b
	ProtoTRILLNetworkProtocol                        ProtocolNumber = 0x005d
	ProtoRTPIPHCFullHeader                           ProtocolNumber = 0x61
	ProtoRTPIPHCCompressedTCP                        ProtocolNumber = 0x63
	ProtoRTPIPHCCompressedNonTCP                     ProtocolNumber = 0x65
	ProtoRTPIPHCCompressedUDP8                       ProtocolNumber = 0x67
	ProtoRTPIPHCCompressedRTP8                       ProtocolNumber = 0x69
	ProtoStampedeBridging                            ProtocolNumber = 0x006f
	ProtoMPPlus                                      ProtocolNumber = 0x73
	ProtoNTCITSIPI                                   ProtocolNumber = 0x00c1
	ProtoSinglelinkcompressioninmultilink            ProtocolNumber = 0x00fb
	ProtoCompresseddatagram                          ProtocolNumber = 0x00fd
	ProtoHelloPackets8021d                           ProtocolNumber = 0x201
	ProtoIBMSourceRoutingBPDU                        ProtocolNumber = 0x203
	ProtoDECLANBridge100SpanningTree                 ProtocolNumber = 0x205
	ProtoCiscoDiscoveryProtocol                      ProtocolNumber = 0x207
	ProtoNetcsTwinRouting                            ProtocolNumber = 0x209
	ProtoSTPScheduledTransferProtocol                ProtocolNumber = 0x020b
	ProtoEDPExtremeDiscoveryProtocol                 ProtocolNumber = 0x020d
	ProtoOpticalSupervisoryChannelProtocol           ProtocolNumber = 0x211
	ProtoOpticalSupervisoryChannelProtocolAlias      ProtocolNumber = 0x213
	ProtoLuxcom                                      ProtocolNumber = 0x231
	ProtoSigmaNetworkSystems                         ProtocolNumber = 0x233
	ProtoAppleClientServerProtocol                   ProtocolNumber = 0x235
	ProtoMPLSUnicast                                 ProtocolNumber = 0x281
	ProtoMPLSMulticast                               ProtocolNumber = 0x283
	ProtoIEEEp12844standarddatapackets               ProtocolNumber = 0x285
	ProtoETSITETRANetworkProtocolType1               ProtocolNumber = 0x287
	ProtoMultichannelFlowTreatmentProtocol           ProtocolNumber = 0x289
	ProtoRTPIPHCCompressedTCPNoDelta                 ProtocolNumber = 0x2063
	ProtoRTPIPHCContextState                         ProtocolNumber = 0x2065
	ProtoRTPIPHCCompressedUDP16                      ProtocolNumber = 0x2067
	ProtoRTPIPHCCompressedRTP16                      ProtocolNumber = 0x2069
	ProtoCrayCommunicationsControlProtocol           ProtocolNumber = 0x4001
	ProtoCDPDMobileNetworkRegistrationProtocol       ProtocolNumber = 0x4003
	ProtoExpandacceleratorprotocol                   ProtocolNumber = 0x4005
	ProtoODSICPNCP                                   ProtocolNumber = 0x4007
	ProtoDOCSISDLL                                   ProtocolNumber = 0x4009
	ProtoCetaceanNetworkDetectionProtocol            ProtocolNumber = 0x400B
	ProtoStackerLZS                                  ProtocolNumber = 0x4021
	ProtoRefTekProtocol                              ProtocolNumber = 0x4023
	ProtoFibreChannel                                ProtocolNumber = 0x4025
	ProtoOpenDOF                                     ProtocolNumber = 0x4027
	ProtoVendorSpecificProtocol                      ProtocolNumber = 0x405b
	ProtoTRILLLinkStateProtocol                      ProtocolNumber = 0x405d
	ProtoOSINetworkLayerControlProtocol              ProtocolNumber = 0x8023
	ProtoXeroxNSIDPControlProtocol                   ProtocolNumber = 0x8025
	ProtoDECnetPhaseIVControlProtocol                ProtocolNumber = 0x8027
	ProtoAppletalkControlProtocol                    ProtocolNumber = 0x8029
	ProtoNovellIPXControlProtocol                    ProtocolNumber = 0x802b
	ProtoBridgingNCP                                 ProtocolNumber = 0x8031
	ProtoStreamProtocolControlProtocol               ProtocolNumber = 0x8033
	ProtoBanyanVinesControlProtocol                  ProtocolNumber = 0x8035
	ProtoMultiLinkControlProtocol                    ProtocolNumber = 0x803d
	ProtoNETBIOSFramingControlProtocol               ProtocolNumber = 0x803f
	ProtoCiscoSystemsControlProtocol                 ProtocolNumber = 0x8041
	ProtoAscomTimeplexAlias                          ProtocolNumber = 0x8043
	ProtoFujitsuLBLBControlProtocol                  ProtocolNumber = 0x8045
	ProtoDCARemoteLanNetworkControlProtocol          ProtocolNumber = 0x8047
	ProtoSerialDataControlProtocol                   ProtocolNumber = 0x8049
	ProtoSNAover802Control                           ProtocolNumber = 0x804b
	ProtoSNAControlProtocol                          ProtocolNumber = 0x804d
	ProtoIP6HeaderCompressionControlProtocol         ProtocolNumber = 0x804f
	ProtoKNXBridgingControlProtocol                  ProtocolNumber = 0x8051
	ProtoEncryptionControlProtocol                   ProtocolNumber = 0x8053
	ProtoIndividualLinkEncryptionControlProtocol     ProtocolNumber = 0x8055
	ProtoPPPMuxingControlProtocol                    ProtocolNumber = 0x8059
	ProtoVendorSpecificNetworkControlProtocol        ProtocolNumber = 0x805b
	ProtoTRILLNetworkControlProtocol                 ProtocolNumber = 0x805d
	ProtoStampedeBridgingControlProtocol             ProtocolNumber = 0x806f
	ProtoMPPlusControlProtocol                       ProtocolNumber = 0x8073
	ProtoNTCITSIPIControlProtocol                    ProtocolNumber = 0x80c1
	Protosinglelinkcompressioninmultilinkcontrol     ProtocolNumber = 0x80fb
	ProtoCompressionControlProtocol                  ProtocolNumber = 0x80fd
	ProtoCiscoDiscoveryProtocolControl               ProtocolNumber = 0x8207
	ProtoNetcsTwinRoutingAlias                       ProtocolNumber = 0x8209
	ProtoSTPControlProtocol                          ProtocolNumber = 0x820b
	ProtoEDPCPExtremeDiscoveryProtocolCtrlPrtcl      ProtocolNumber = 0x820d
	ProtoAppleClientServerProtocolControl            ProtocolNumber = 0x8235
	ProtoMPLSCP                                      ProtocolNumber = 0x8281
	ProtoIEEEp12844standardProtocolControl           ProtocolNumber = 0x8285
	ProtoETSITETRATNP1ControlProtocol                ProtocolNumber = 0x8287
	ProtoMultichannelFlowTreatmentProtocolAlias      ProtocolNumber = 0x8289
	ProtoLinkQualityReport                           ProtocolNumber = 0xc025
	ProtoShivaPasswordAuthenticationProtocol         ProtocolNumber = 0xc027
	ProtoCallBackControlProtocol                     ProtocolNumber = 0xc029
	ProtoBACPBandwidthAllocationControlProtocolAlias ProtocolNumber = 0xc02b
	ProtoBAP                                         ProtocolNumber = 0xc02d
	ProtoVendorSpecificAuthenticationProtocol        ProtocolNumber = 0xc05b
	ProtoContainerControlProtocol                    ProtocolNumber = 0xc081
	ProtoRSAAuthenticationProtocol                   ProtocolNumber = 0xc225
	ProtoMitsubishiSecurityInfoExchPtcl              ProtocolNumber = 0xc229
	ProtoStampedeBridgingAuthorizationProtocol       ProtocolNumber = 0xc26f
	ProtoProprietaryAuthenticationProtocol           ProtocolNumber = 0xc281
	ProtoProprietaryAuthenticationProtocolAlias      ProtocolNumber = 0xc283
	ProtoProprietaryNodeIDAuthenticationProtocol     ProtocolNumber = 0xc481
)

func (val ProtocolNumber) String() string {
	switch val {
	case ProtoAppleClientServerProtocol:
		return "AppleClientServerProtocol"
	case ProtoAppleClientServerProtocolControl:
		return "AppleClientServerProtocolControl"
	case ProtoAppleTalkEDDP:
		return "AppleTalkEDDP"
	case ProtoAppleTalkSmartBuffered:
		return "AppleTalkSmartBuffered"
	case ProtoAppletalk:
		return "Appletalk"
	case ProtoAppletalkControlProtocol:
		return "AppletalkControlProtocol"
	case ProtoAscomTimeplex:
		return "AscomTimeplex"
	case ProtoAscomTimeplexAlias:
		return "AscomTimeplexAlias"
	case ProtoBACPBandwidthAllocationControlProtocolAlias:
		return "BACPBandwidthAllocationControlProtocolAlias"
	case ProtoBAP:
		return "BAP"
	case ProtoBanyanVines:
		return "BanyanVines"
	case ProtoBanyanVinesControlProtocol:
		return "BanyanVinesControlProtocol"
	case ProtoBridgingNCP:
		return "BridgingNCP"
	case ProtoBridgingPDU:
		return "BridgingPDU"
	case ProtoCDPDMobileNetworkRegistrationProtocol:
		return "CDPDMobileNetworkRegistrationProtocol"
	case ProtoCHAP:
		return "CHAP"
	case ProtoCallBackControlProtocol:
		return "CallBackControlProtocol"
	case ProtoCetaceanNetworkDetectionProtocol:
		return "CetaceanNetworkDetectionProtocol"
	case ProtoCiscoDiscoveryProtocol:
		return "CiscoDiscoveryProtocol"
	case ProtoCiscoDiscoveryProtocolControl:
		return "CiscoDiscoveryProtocolControl"
	case ProtoCiscoSystems:
		return "CiscoSystems"
	case ProtoCiscoSystemsControlProtocol:
		return "CiscoSystemsControlProtocol"
	case ProtoCompresseddatagram:
		return "Compresseddatagram"
	case ProtoCompressionControlProtocol:
		return "CompressionControlProtocol"
	case ProtoContainerControlProtocol:
		return "ContainerControlProtocol"
	case ProtoCrayCommunicationsControlProtocol:
		return "CrayCommunicationsControlProtocol"
	case ProtoDCARemoteLan:
		return "DCARemoteLan"
	case ProtoDCARemoteLanNetworkControlProtocol:
		return "DCARemoteLanNetworkControlProtocol"
	case ProtoDECLANBridge100SpanningTree:
		return "DECLANBridge100SpanningTree"
	case ProtoDECnetPhaseIV:
		return "DECnetPhaseIV"
	case ProtoDECnetPhaseIVControlProtocol:
		return "DECnetPhaseIVControlProtocol"
	case ProtoDOCSISDLL:
		return "DOCSISDLL"
	case ProtoEAP:
		return "EAP"
	case ProtoEDPCPExtremeDiscoveryProtocolCtrlPrtcl:
		return "EDPCPExtremeDiscoveryProtocolCtrlPrtcl"
	case ProtoEDPExtremeDiscoveryProtocol:
		return "EDPExtremeDiscoveryProtocol"
	case ProtoETSITETRANetworkProtocolType1:
		return "ETSITETRANetworkProtocolType1"
	case ProtoETSITETRATNP1ControlProtocol:
		return "ETSITETRATNP1ControlProtocol"
	case ProtoEncryption:
		return "Encryption"
	case ProtoEncryptionControlProtocol:
		return "EncryptionControlProtocol"
	case ProtoExpandacceleratorprotocol:
		return "Expandacceleratorprotocol"
	case ProtoFibreChannel:
		return "FibreChannel"
	case ProtoFujitsuLBLBControlProtocol:
		return "FujitsuLBLBControlProtocol"
	case ProtoFujitsuLinkBackupandLoadBalancing:
		return "FujitsuLinkBackupandLoadBalancing"
	case ProtoHelloPackets8021d:
		return "HelloPackets8021d"
	case ProtoIBMSourceRoutingBPDU:
		return "IBMSourceRoutingBPDU"
	case ProtoIEEEp12844standardProtocolControl:
		return "IEEEp12844standardProtocolControl"
	case ProtoIEEEp12844standarddatapackets:
		return "IEEEp12844standarddatapackets"
	case ProtoIP6HeaderCompressionControlProtocol:
		return "IP6HeaderCompressionControlProtocol"
	case ProtoIPCP:
		return "IPCP"
	case ProtoIPv4:
		return "IPv4"
	case ProtoIPv6:
		return "IPv6"
	case ProtoIPv6CP:
		return "IPv6CP"
	case ProtoIPv6HeaderCompression:
		return "IPv6HeaderCompression"
	case ProtoIndividualLinkEncryption:
		return "IndividualLinkEncryption"
	case ProtoIndividualLinkEncryptionControlProtocol:
		return "IndividualLinkEncryptionControlProtocol"
	case ProtoKNXBridgingControlProtocol:
		return "KNXBridgingControlProtocol"
	case ProtoKNXBridgingData:
		return "KNXBridgingData"
	case ProtoLCP:
		return "LCP"
	case ProtoLinkQualityReport:
		return "LinkQualityReport"
	case ProtoLuxcom:
		return "Luxcom"
	case ProtoMPLSCP:
		return "MPLSCP"
	case ProtoMPLSMulticast:
		return "MPLSMulticast"
	case ProtoMPLSUnicast:
		return "MPLSUnicast"
	case ProtoMPPlus:
		return "MPPlus"
	case ProtoMPPlusControlProtocol:
		return "MPPlusControlProtocol"
	case ProtoMitsubishiSecurityInfoExchPtcl:
		return "MitsubishiSecurityInfoExchPtcl"
	case ProtoMultiLink:
		return "MultiLink"
	case ProtoMultiLinkControlProtocol:
		return "MultiLinkControlProtocol"
	case ProtoMultichannelFlowTreatmentProtocol:
		return "MultichannelFlowTreatmentProtocol"
	case ProtoMultichannelFlowTreatmentProtocolAlias:
		return "MultichannelFlowTreatmentProtocolAlias"
	case ProtoNETBIOSFraming:
		return "NETBIOSFraming"
	case ProtoNETBIOSFramingControlProtocol:
		return "NETBIOSFramingControlProtocol"
	case ProtoNTCITSIPI:
		return "NTCITSIPI"
	case ProtoNTCITSIPIControlProtocol:
		return "NTCITSIPIControlProtocol"
	case ProtoNetcsTwinRouting:
		return "NetcsTwinRouting"
	case ProtoNetcsTwinRoutingAlias:
		return "NetcsTwinRoutingAlias"
	case ProtoNone:
		return "None"
	case ProtoNovellIPX:
		return "NovellIPX"
	case ProtoNovellIPXControlProtocol:
		return "NovellIPXControlProtocol"
	case ProtoODSICPNCP:
		return "ODSICPNCP"
	case ProtoOSINetworkLayer:
		return "OSINetworkLayer"
	case ProtoOSINetworkLayerControlProtocol:
		return "OSINetworkLayerControlProtocol"
	case ProtoOpenDOF:
		return "OpenDOF"
	case ProtoOpticalSupervisoryChannelProtocol:
		return "OpticalSupervisoryChannelProtocol"
	case ProtoOpticalSupervisoryChannelProtocolAlias:
		return "OpticalSupervisoryChannelProtocolAlias"
	case ProtoPAD:
		return "PAD"
	case ProtoPAP:
		return "PAP"
	case ProtoPPPMuxing:
		return "PPPMuxing"
	case ProtoPPPMuxingControlProtocol:
		return "PPPMuxingControlProtocol"
	case ProtoProprietaryAuthenticationProtocol:
		return "ProprietaryAuthenticationProtocol"
	case ProtoProprietaryAuthenticationProtocolAlias:
		return "ProprietaryAuthenticationProtocolAlias"
	case ProtoProprietaryNodeIDAuthenticationProtocol:
		return "ProprietaryNodeIDAuthenticationProtocol"
	case ProtoROHClargeCID:
		return "ROHClargeCID"
	case ProtoROHCsmallCID:
		return "ROHCsmallCID"
	case ProtoRSAAuthenticationProtocol:
		return "RSAAuthenticationProtocol"
	case ProtoRTPIPHCCompressedNonTCP:
		return "RTPIPHCCompressedNonTCP"
	case ProtoRTPIPHCCompressedRTP16:
		return "RTPIPHCCompressedRTP16"
	case ProtoRTPIPHCCompressedRTP8:
		return "RTPIPHCCompressedRTP8"
	case ProtoRTPIPHCCompressedTCP:
		return "RTPIPHCCompressedTCP"
	case ProtoRTPIPHCCompressedTCPNoDelta:
		return "RTPIPHCCompressedTCPNoDelta"
	case ProtoRTPIPHCCompressedUDP16:
		return "RTPIPHCCompressedUDP16"
	case ProtoRTPIPHCCompressedUDP8:
		return "RTPIPHCCompressedUDP8"
	case ProtoRTPIPHCContextState:
		return "RTPIPHCContextState"
	case ProtoRTPIPHCFullHeader:
		return "RTPIPHCFullHeader"
	case ProtoRefTekProtocol:
		return "RefTekProtocol"
	case ProtoSNA:
		return "SNA"
	case ProtoSNAControlProtocol:
		return "SNAControlProtocol"
	case ProtoSNAover802:
		return "SNAover802"
	case ProtoSNAover802Control:
		return "SNAover802Control"
	case ProtoSTPControlProtocol:
		return "STPControlProtocol"
	case ProtoSTPScheduledTransferProtocol:
		return "STPScheduledTransferProtocol"
	case ProtoSerialDataControlProtocol:
		return "SerialDataControlProtocol"
	case ProtoSerialDataTransportProtocol:
		return "SerialDataTransportProtocol"
	case ProtoShivaPasswordAuthenticationProtocol:
		return "ShivaPasswordAuthenticationProtocol"
	case ProtoSigmaNetworkSystems:
		return "SigmaNetworkSystems"
	case ProtoSinglelinkcompressioninmultilink:
		return "Singlelinkcompressioninmultilink"
	case ProtoStackerLZS:
		return "StackerLZS"
	case ProtoStampedeBridging:
		return "StampedeBridging"
	case ProtoStampedeBridgingAuthorizationProtocol:
		return "StampedeBridgingAuthorizationProtocol"
	case ProtoStampedeBridgingControlProtocol:
		return "StampedeBridgingControlProtocol"
	case ProtoStreamProtocol:
		return "StreamProtocol"
	case ProtoStreamProtocolControlProtocol:
		return "StreamProtocolControlProtocol"
	case ProtoTRILLLinkStateProtocol:
		return "TRILLLinkStateProtocol"
	case ProtoTRILLNetworkControlProtocol:
		return "TRILLNetworkControlProtocol"
	case ProtoTRILLNetworkProtocol:
		return "TRILLNetworkProtocol"
	case ProtoUnassigned:
		return "Unassigned"
	case ProtoVanJacobsonCompressedTCPIP:
		return "VanJacobsonCompressedTCPIP"
	case ProtoVanJacobsonUncompressedTCPIP:
		return "VanJacobsonUncompressedTCPIP"
	case ProtoVendorSpecificAuthenticationProtocol:
		return "VendorSpecificAuthenticationProtocol"
	case ProtoVendorSpecificNetworkControlProtocol:
		return "VendorSpecificNetworkControlProtocol"
	case ProtoVendorSpecificNetworkProtocol:
		return "VendorSpecificNetworkProtocol"
	case ProtoVendorSpecificProtocol:
		return "VendorSpecificProtocol"
	case ProtoXeroxNSIDP:
		return "XeroxNSIDP"
	case ProtoXeroxNSIDPControlProtocol:
		return "XeroxNSIDPControlProtocol"
	case Protosinglelinkcompressioninmultilinkcontrol:
		return "singlelinkcompressioninmultilinkcontrol"
	default:
		return fmt.Sprintf("unknown (%d)", uint16(val))
	}
}

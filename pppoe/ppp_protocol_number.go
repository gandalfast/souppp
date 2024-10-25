package pppoe

import "fmt"

// PPPProtocolNumber is the PPP protocol number
type PPPProtocolNumber uint16

// List of PPP protocol number
const (
	ProtoNone                                        PPPProtocolNumber = 0x00
	ProtoPAD                                         PPPProtocolNumber = 0x01
	ProtoIPv4                                        PPPProtocolNumber = 0x21
	ProtoIPv6                                        PPPProtocolNumber = 0x57
	ProtoLCP                                         PPPProtocolNumber = 0xc021
	ProtoPAP                                         PPPProtocolNumber = 0xc023
	ProtoCHAP                                        PPPProtocolNumber = 0xc223
	ProtoEAP                                         PPPProtocolNumber = 0xc227
	ProtoIPCP                                        PPPProtocolNumber = 0x8021
	ProtoIPv6CP                                      PPPProtocolNumber = 0x8057
	ProtoROHCsmallCID                                PPPProtocolNumber = 0x03
	ProtoROHClargeCID                                PPPProtocolNumber = 0x05
	ProtoOSINetworkLayer                             PPPProtocolNumber = 0x23
	ProtoXeroxNSIDP                                  PPPProtocolNumber = 0x25
	ProtoDECnetPhaseIV                               PPPProtocolNumber = 0x27
	ProtoAppletalk                                   PPPProtocolNumber = 0x29
	ProtoNovellIPX                                   PPPProtocolNumber = 0x002b
	ProtoVanJacobsonCompressedTCPIP                  PPPProtocolNumber = 0x002d
	ProtoVanJacobsonUncompressedTCPIP                PPPProtocolNumber = 0x002f
	ProtoBridgingPDU                                 PPPProtocolNumber = 0x31
	ProtoStreamProtocol                              PPPProtocolNumber = 0x33
	ProtoBanyanVines                                 PPPProtocolNumber = 0x35
	ProtoUnassigned                                  PPPProtocolNumber = 0x37
	ProtoAppleTalkEDDP                               PPPProtocolNumber = 0x39
	ProtoAppleTalkSmartBuffered                      PPPProtocolNumber = 0x003b
	ProtoMultiLink                                   PPPProtocolNumber = 0x003d
	ProtoNETBIOSFraming                              PPPProtocolNumber = 0x003f
	ProtoCiscoSystems                                PPPProtocolNumber = 0x41
	ProtoAscomTimeplex                               PPPProtocolNumber = 0x43
	ProtoFujitsuLinkBackupandLoadBalancing           PPPProtocolNumber = 0x45
	ProtoDCARemoteLan                                PPPProtocolNumber = 0x47
	ProtoSerialDataTransportProtocol                 PPPProtocolNumber = 0x49
	ProtoSNAover802                                  PPPProtocolNumber = 0x004b
	ProtoSNA                                         PPPProtocolNumber = 0x004d
	ProtoIPv6HeaderCompression                       PPPProtocolNumber = 0x004f
	ProtoKNXBridgingData                             PPPProtocolNumber = 0x51
	ProtoEncryption                                  PPPProtocolNumber = 0x53
	ProtoIndividualLinkEncryption                    PPPProtocolNumber = 0x55
	ProtoPPPMuxing                                   PPPProtocolNumber = 0x59
	ProtoVendorSpecificNetworkProtocol               PPPProtocolNumber = 0x005b
	ProtoTRILLNetworkProtocol                        PPPProtocolNumber = 0x005d
	ProtoRTPIPHCFullHeader                           PPPProtocolNumber = 0x61
	ProtoRTPIPHCCompressedTCP                        PPPProtocolNumber = 0x63
	ProtoRTPIPHCCompressedNonTCP                     PPPProtocolNumber = 0x65
	ProtoRTPIPHCCompressedUDP8                       PPPProtocolNumber = 0x67
	ProtoRTPIPHCCompressedRTP8                       PPPProtocolNumber = 0x69
	ProtoStampedeBridging                            PPPProtocolNumber = 0x006f
	ProtoMPPlus                                      PPPProtocolNumber = 0x73
	ProtoNTCITSIPI                                   PPPProtocolNumber = 0x00c1
	ProtoSinglelinkcompressioninmultilink            PPPProtocolNumber = 0x00fb
	ProtoCompresseddatagram                          PPPProtocolNumber = 0x00fd
	ProtoHelloPackets8021d                           PPPProtocolNumber = 0x201
	ProtoIBMSourceRoutingBPDU                        PPPProtocolNumber = 0x203
	ProtoDECLANBridge100SpanningTree                 PPPProtocolNumber = 0x205
	ProtoCiscoDiscoveryProtocol                      PPPProtocolNumber = 0x207
	ProtoNetcsTwinRouting                            PPPProtocolNumber = 0x209
	ProtoSTPScheduledTransferProtocol                PPPProtocolNumber = 0x020b
	ProtoEDPExtremeDiscoveryProtocol                 PPPProtocolNumber = 0x020d
	ProtoOpticalSupervisoryChannelProtocol           PPPProtocolNumber = 0x211
	ProtoOpticalSupervisoryChannelProtocolAlias      PPPProtocolNumber = 0x213
	ProtoLuxcom                                      PPPProtocolNumber = 0x231
	ProtoSigmaNetworkSystems                         PPPProtocolNumber = 0x233
	ProtoAppleClientServerProtocol                   PPPProtocolNumber = 0x235
	ProtoMPLSUnicast                                 PPPProtocolNumber = 0x281
	ProtoMPLSMulticast                               PPPProtocolNumber = 0x283
	ProtoIEEEp12844standarddatapackets               PPPProtocolNumber = 0x285
	ProtoETSITETRANetworkProtocolType1               PPPProtocolNumber = 0x287
	ProtoMultichannelFlowTreatmentProtocol           PPPProtocolNumber = 0x289
	ProtoRTPIPHCCompressedTCPNoDelta                 PPPProtocolNumber = 0x2063
	ProtoRTPIPHCContextState                         PPPProtocolNumber = 0x2065
	ProtoRTPIPHCCompressedUDP16                      PPPProtocolNumber = 0x2067
	ProtoRTPIPHCCompressedRTP16                      PPPProtocolNumber = 0x2069
	ProtoCrayCommunicationsControlProtocol           PPPProtocolNumber = 0x4001
	ProtoCDPDMobileNetworkRegistrationProtocol       PPPProtocolNumber = 0x4003
	ProtoExpandacceleratorprotocol                   PPPProtocolNumber = 0x4005
	ProtoODSICPNCP                                   PPPProtocolNumber = 0x4007
	ProtoDOCSISDLL                                   PPPProtocolNumber = 0x4009
	ProtoCetaceanNetworkDetectionProtocol            PPPProtocolNumber = 0x400B
	ProtoStackerLZS                                  PPPProtocolNumber = 0x4021
	ProtoRefTekProtocol                              PPPProtocolNumber = 0x4023
	ProtoFibreChannel                                PPPProtocolNumber = 0x4025
	ProtoOpenDOF                                     PPPProtocolNumber = 0x4027
	ProtoVendorSpecificProtocol                      PPPProtocolNumber = 0x405b
	ProtoTRILLLinkStateProtocol                      PPPProtocolNumber = 0x405d
	ProtoOSINetworkLayerControlProtocol              PPPProtocolNumber = 0x8023
	ProtoXeroxNSIDPControlProtocol                   PPPProtocolNumber = 0x8025
	ProtoDECnetPhaseIVControlProtocol                PPPProtocolNumber = 0x8027
	ProtoAppletalkControlProtocol                    PPPProtocolNumber = 0x8029
	ProtoNovellIPXControlProtocol                    PPPProtocolNumber = 0x802b
	ProtoBridgingNCP                                 PPPProtocolNumber = 0x8031
	ProtoStreamProtocolControlProtocol               PPPProtocolNumber = 0x8033
	ProtoBanyanVinesControlProtocol                  PPPProtocolNumber = 0x8035
	ProtoMultiLinkControlProtocol                    PPPProtocolNumber = 0x803d
	ProtoNETBIOSFramingControlProtocol               PPPProtocolNumber = 0x803f
	ProtoCiscoSystemsControlProtocol                 PPPProtocolNumber = 0x8041
	ProtoAscomTimeplexAlias                          PPPProtocolNumber = 0x8043
	ProtoFujitsuLBLBControlProtocol                  PPPProtocolNumber = 0x8045
	ProtoDCARemoteLanNetworkControlProtocol          PPPProtocolNumber = 0x8047
	ProtoSerialDataControlProtocol                   PPPProtocolNumber = 0x8049
	ProtoSNAover802Control                           PPPProtocolNumber = 0x804b
	ProtoSNAControlProtocol                          PPPProtocolNumber = 0x804d
	ProtoIP6HeaderCompressionControlProtocol         PPPProtocolNumber = 0x804f
	ProtoKNXBridgingControlProtocol                  PPPProtocolNumber = 0x8051
	ProtoEncryptionControlProtocol                   PPPProtocolNumber = 0x8053
	ProtoIndividualLinkEncryptionControlProtocol     PPPProtocolNumber = 0x8055
	ProtoPPPMuxingControlProtocol                    PPPProtocolNumber = 0x8059
	ProtoVendorSpecificNetworkControlProtocol        PPPProtocolNumber = 0x805b
	ProtoTRILLNetworkControlProtocol                 PPPProtocolNumber = 0x805d
	ProtoStampedeBridgingControlProtocol             PPPProtocolNumber = 0x806f
	ProtoMPPlusControlProtocol                       PPPProtocolNumber = 0x8073
	ProtoNTCITSIPIControlProtocol                    PPPProtocolNumber = 0x80c1
	Protosinglelinkcompressioninmultilinkcontrol     PPPProtocolNumber = 0x80fb
	ProtoCompressionControlProtocol                  PPPProtocolNumber = 0x80fd
	ProtoCiscoDiscoveryProtocolControl               PPPProtocolNumber = 0x8207
	ProtoNetcsTwinRoutingAlias                       PPPProtocolNumber = 0x8209
	ProtoSTPControlProtocol                          PPPProtocolNumber = 0x820b
	ProtoEDPCPExtremeDiscoveryProtocolCtrlPrtcl      PPPProtocolNumber = 0x820d
	ProtoAppleClientServerProtocolControl            PPPProtocolNumber = 0x8235
	ProtoMPLSCP                                      PPPProtocolNumber = 0x8281
	ProtoIEEEp12844standardProtocolControl           PPPProtocolNumber = 0x8285
	ProtoETSITETRATNP1ControlProtocol                PPPProtocolNumber = 0x8287
	ProtoMultichannelFlowTreatmentProtocolAlias      PPPProtocolNumber = 0x8289
	ProtoLinkQualityReport                           PPPProtocolNumber = 0xc025
	ProtoShivaPasswordAuthenticationProtocol         PPPProtocolNumber = 0xc027
	ProtoCallBackControlProtocol                     PPPProtocolNumber = 0xc029
	ProtoBACPBandwidthAllocationControlProtocolAlias PPPProtocolNumber = 0xc02b
	ProtoBAP                                         PPPProtocolNumber = 0xc02d
	ProtoVendorSpecificAuthenticationProtocol        PPPProtocolNumber = 0xc05b
	ProtoContainerControlProtocol                    PPPProtocolNumber = 0xc081
	ProtoRSAAuthenticationProtocol                   PPPProtocolNumber = 0xc225
	ProtoMitsubishiSecurityInfoExchPtcl              PPPProtocolNumber = 0xc229
	ProtoStampedeBridgingAuthorizationProtocol       PPPProtocolNumber = 0xc26f
	ProtoProprietaryAuthenticationProtocol           PPPProtocolNumber = 0xc281
	ProtoProprietaryAuthenticationProtocolAlias      PPPProtocolNumber = 0xc283
	ProtoProprietaryNodeIDAuthenticationProtocol     PPPProtocolNumber = 0xc481
)

func (val PPPProtocolNumber) String() string {
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

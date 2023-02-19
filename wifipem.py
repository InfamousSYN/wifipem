#!/usr/bin/python3
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

import argparse
from scapy.all import *
from scapy.layers.tls.record import *
from scapy.layers.tls.handshake import *
from scapy.layers.tls.extensions import *

parser = argparse.ArgumentParser(description='Automated tool for extract the public key presented by WPA2-Enterprise wireless networks')

parser.add_argument('-o', '--output', dest='output_file')
parser.add_argument('-t', '--timeout', dest='timeout', default=3, type=int)
parser.add_argument('--verbose', dest='verbose', action='store_true', default=False, help='enable verbosity')
parser.add_argument('--scan', dest='scan_enable', action='store_true', default=False, help='Scan for WLAN')
parser.add_argument('-r', '--retry', dest='retry', default=3, type=int, help='Control number of retry attempts at transmission and detection')
parser.add_argument('-d', '--delay', dest='pause', default=1, type=float, help='Control pause between starting sniffer thread and sending frame')
parser.add_argument('--version', action='version', version='%(prog)s 2.0.0')

sourceMode = parser.add_argument_group(description='Specify source for targeting information')
sourceMode.add_argument('-m', choices=[0,1], dest='mode', type=int, help='0 = live, 1 = pcap', required=True)

liveCaptureOptions = parser.add_argument_group(description='Specify targeting information for live extration. Used when -m 0 source mode is chosen')
liveCaptureOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')
liveCaptureOptions.add_argument('-sl', dest='ssid', help='select target SSID')
liveCaptureOptions.add_argument('-bl', dest='bssid', nargs='+', default=[], help='select BSSID')
liveCaptureOptions.add_argument('-bL', dest='bssid_file', default=None, help='provide file containing BSSIDs')

pcapCaptureOptions = parser.add_argument_group(description='Specify targeting information for pcap extration. Used when -m 1 source mode is chosen')
pcapCaptureOptions.add_argument('-p', '--pcap', dest='pcap_filename', help='extract .pem from a pcap')
pcapCaptureOptions.add_argument('-sp', dest='ssid', help='select target SSID')
pcapCaptureOptions.add_argument('-bp', dest='bssid', nargs='+', default=[''], help='select BSSID')
pcapCaptureOptions.add_argument('-bP', dest='bssid_file', default=None, help='provide file containing BSSIDs')


monitorOptions = parser.add_argument_group(description='Specify target source for extraction')
monitorOptions.add_argument('--enable-monitor', dest='monitor_status', action='store_true', default=False, help='set interface to use')
monitorOptions.add_argument('--monitor', dest='monitor', help='set interface to use')

eapOptions = parser.add_argument_group(description='EAP Settings')
eapOptions.add_argument('-I', '--identity', dest='eap_identity', default='InfamousSYN', type=str, help='Specify EAP identity')
eapOptions.add_argument('-T', '--eap-type', dest='default_eap_type', default=25, choices=[25, 13], type=int, help='Control default eap type')

args, leftover = parser.parse_known_args()
options = args.__dict__

class Dot11EltRates(Packet):
    name = '802.11 Rates Information Element'
    supported_rates = [ 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c, 0x82, 0x84, 0x8b, 0x96]
    fields_desc = [ByteField('ID', 1), ByteField('len', len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField('supported_rate{0}'.format(index+1), rate))

class wifipemClass(object):
    @classmethod
    def __init__(self, retry, pause, ssid, bssids, interface, monitor, monitor_status, scan_enable, timeout, verbose, eap_identity, default_eap_type):

        # Settings
        self.revert_interface_state = False
        self.retry = retry
        self.pause = pause
        self.bssids=bssids
        self.ssid=ssid
        self.verbose=verbose
        self.scan_enable=scan_enable
        self.timeout=timeout
        self.associatedState=False
        self.authenticationState=False
        self.eap_identity = eap_identity
        self.default_eap_type = default_eap_type
        self.client_tls_cipher_list = [ 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255]

        # Interfaces
        self.interface=interface
        self.monitor=monitor
        self.monitor_status=monitor_status
        self.senderAddress=self.getSenderAddress(interface=self.interface)

        # Packet Memory
        self.RadioTap_layer = RadioTap()
        self.probeResponsePacket = None
        self.authenticationRespPacket = None
        self.associationResponsePacket = None
        self.eapIdentityPacket = None
        self.real_capability = None
        self.real_bssid = None
        self.eap_version = None
        self.packet_probe_response_dot11elt_layer = None
        self.real_rates_id = None
        self.real_extended_rates_id = None
        self.real_rsn_id = None
        self.real_ht_capabilities_id = None
        self.real_rates = None
        self.real_extended_rates = None
        self.real_rsn = None
        self.real_ht_capabilities = None

    @staticmethod
    def sendFrame(pkt, interface, verbose=False, count=3, inter=1):
        if(verbose):
            print('[-]\tPacket Emission ({}):\r\n[-]\t\tcount: {}\r\n[-]\t\tPacket:\r\n[-]\t\t{}\r\n[-]'.format(interface, count, pkt.summary))
        junk = sendp(pkt, iface=interface, inter=inter, count=count)
        return

    @staticmethod
    def currentTime(boottime):
        import time
        return (time.time()-boottime*1000000)

    @staticmethod
    def ifaceUp(interface):
        import os
        os.system('ifconfig {} up'.format(interface))
        return

    @staticmethod
    def ifaceDown(interface):
        import os
        os.system('ifconfig {} down'.format(interface))
        return

    @staticmethod
    def testIfaceOpMode(interface):
        import os
        return os.popen('iwconfig {}'.format(interface)).read()

    @staticmethod
    def ifaceMonitor(interface):
        import os
        os.system('iwconfig {} mode monitor'.format(interface))
        return

    @staticmethod
    def ifaceManaged(interface):
        import os
        os.system('iwconfig {} mode managed'.format(interface))
        return

    @staticmethod
    def getSenderAddress(interface):
        import os
        try:
            return os.popen('cat /sys/class/net/{}/address'.format(interface)).read().strip('\n')
        except Exception as e:
            print('[!]\tInterface \'{}\' not found!'.format(interface))
            if(self.verbose):
                print('[!]\t\tError:\r\n\t\t\t{}'.format(e))

    @staticmethod
    def nmcliDisable(interface):
        import os
        try:
            os.system('nmcli device set {} managed no'.format(interface))
        except Exception as e:
            if(self.verbose):
                print('[!]\t\tError:\r\n\t\t\t{}'.format(e))
        return

    @staticmethod
    def nmcliEnable(interface):
        import os
        try:
            os.system('nmcli device set {} managed yes'.format(interface))
        except Exception as e:
            if(self.verbose):
                print('[!]\t\tError:\r\n\t\t\t{}'.format(e))
        return

    @staticmethod
    def testIfaceConMode(interface):
        import os
        return os.popen('nmcli device show {}'.format(interface)).read()

    @classmethod
    def disable_nmcli_interface(self, interface):
        if(self.verbose):
            print('[-]\tDisabling nmcli\'s management of interface: {}'.format(interface))
        self.nmcliDisable(interface=interface)

    @classmethod
    def enable_nmcli_interface(self, interface):
        if(self.verbose):
            print('[-]\tEnabling nmcli\'s management of interface: {}'.format(interface))
        self.nmcliEnable(interface=interface)

    @classmethod
    def check_interface_control_mode(self, interface, keyword='unmanaged'):
        res = self.testIfaceConMode(interface=interface)
        for line in res.splitlines():
            if( "GENERAL.STATE:" in line and "{}".format(keyword) not in line ):
                return True
            else:
                return False

    @classmethod
    def set_interface_monitor(self, interface):
        if(self.verbose):
            print('[-]\tInterface Mode Toggle: changing \'{}\' mode to \'monitor\''.format(interface))
        self.ifaceDown(interface=interface)
        self.ifaceMonitor(interface=interface)
        self.ifaceUp(interface=interface)

    @classmethod
    def set_interface_managed(self, interface):
        if(self.verbose):
            print('[-]\tInterface Mode Toggle: changing \'{}\' mode to \'managed\''.format(interface))
        self.ifaceDown(interface=interface)
        self.ifaceManaged(interface=interface)
        self.ifaceUp(interface=interface)

    @classmethod
    def check_interface_operational_mode(self, interface, keyword='Monitor'):
        res = self.testIfaceOpMode(interface=interface)
        return True if 'Mode:{}'.format(keyword) in res else False

    @classmethod
    def findProbeResponse(self, packet=None):
        if( (packet.haslayer(Dot11ProbeResp)) and (packet.info.decode('utf-8') == self.ssid) and (packet.addr1 == self.senderAddress) ):
            self.probeResponsePacket = packet
            self.target_bssid = packet.addr3

            self.RadioTap_layer = RadioTap(
                    #pad=packet.getlayer(RadioTap).pad,
                    #version=packet.getlayer(RadioTap).version,
                    #len=packet.getlayer(RadioTap).len,
                    #present=packet.getlayer(RadioTap).present,
                    #Flags=packet.getlayer(RadioTap).Flags,
                    #Rate=packet.getlayer(RadioTap).Rate,
                    #ChannelFrequency=packet.getlayer(RadioTap).ChannelFrequency,
                    #ChannelFlags=packet.getlayer(RadioTap).ChannelFlags,
                    #dBm_AntSignal=packet.getlayer(RadioTap).dBm_AntSignal,
                    #RXFlags=packet.getlayer(RadioTap).RXFlags
                    )

            return packet
        return None

    @classmethod
    def parserProbeResponse(self, packet=None):
        if(self.verbose):
            print("[-]\tParsing the Probe response")

        self.real_capability = int(self.probeResponsePacket.getlayer(Dot11ProbeResp).cap)
        self.real_bssid = (self.probeResponsePacket.getlayer(Dot11).addr3)
        packet = self.probeResponsePacket
        self.packet_probe_response_dot11elt_layer = packet.getlayer(Dot11Elt)


    @classmethod
    def findAuthenticationResponse(self, packet=None):
        if( (packet.haslayer(Dot11Auth)) and (packet.addr3 == self.target_bssid.lower()) and 
            (packet.addr1 == self.senderAddress.lower())):
            self.authenticationState = True
            self.authenticationRespPacket = packet
            return packet
        return None

    @classmethod
    def parserAuthenticationResponse(self, packet=None):
        pass

    @classmethod
    def findAssociationResponse(self, packet=None):
        if( (packet.haslayer(Dot11AssoResp)) and (packet.addr3 == self.target_bssid.lower()) and (packet.addr1 == self.senderAddress.lower()) ):
            self.associatedState = True
            self.associationResponsePacket = packet
            return packet
        elif( (self.associatedState) and (packet.haslayer(EAP)) and (packet.addr3 == self.target_bssid.lower()) and (packet.addr1 == self.senderAddress.lower()) ):
            self.eapIdentityPacket = packet
            return packet
        return None

    @classmethod
    def parserAssocationResponse(self, packet=None):
        pass

    @classmethod
    def sniffThread(self):
        if(self.verbose):
            print('[-]\tSniff Thread Started: Interface: \'{}\''.format(self.interface))

        if(self.state_machine_state == 'probe'):
            packets = sniff(iface=self.interface,timeout=self.timeout)
            for packet in packets:
                self.findProbeResponse(packet=packet)
            del packets

        if(self.state_machine_state == 'authenticate'):
            packets = sniff(iface=self.interface,timeout=self.timeout)
            for packet in packets:
                self.findAuthenticationResponse(packet=packet)
            del packets

        if(self.state_machine_state == 'associate'):
            packets = sniff(iface=self.interface,timeout=self.timeout)
            for packet in packets:
                self.findAssociationResponse(packet=packet)
            del packets

        if(self.state_machine_state == 'listen_for_eap_identity_request'):
            packets = sniff(iface=self.interface,timeout=self.timeout)
            for packet in packets:
                self.findEAPIdentityRequest(packet=packet)
            del packets

        if(self.state_machine_state == 'sent_eap_identity_response'):
            packets = sniff(iface=self.interface,timeout=self.timeout)
            for packet in packets:
                self.findEAPNegotiationRequest(packet=packet)
            del packets

        if(self.state_machine_state == 'sending_eap_method_negotiation_response'):
            packets = sniff(iface=self.interface,timeout=self.timeout)
            for packet in packets:
                self.findEAPNegotiationRequest(packet=packet)
            del packets
        if(self.verbose):
            print('[-]\tSniff Thread Ended: Interface: \'{}\''.format(self.interface))

    @classmethod
    def createProbeRequestFrame(self, addr1=None):
        from datetime import datetime
        import time
        boottime=time.time()
        loop = 1
        dst=bssid=self.target_bssid

        while loop <= self.retry:
            print('[-]\t802.11 Frame Crafting: Probe Request Attempt {}\r\n[-]\t\tssid: {}\r\n[-]\t\tSTA: {}\r\n[-]\t\tBSSID: {}\r\n[-]\t\tDST: {}'.format(
                loop, 
                self.ssid, 
                self.senderAddress.lower(), 
                bssid.lower(), 
                dst.lower()
            ))

            packet = self.RadioTap_layer/Dot11(type=0, subtype=4, addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11ProbeReq()/Dot11Elt(ID='SSID', info=self.ssid, len=len(self.ssid))/Dot11EltRates()
            packet.timestamp = self.currentTime(boottime)
            t = threading.Thread(target=self.sniffThread, daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
            t.join()
            if(self.probeResponsePacket is None and loop < self.retry):
                print('[!]\tProbe Request: No response detected!\r\n[-]')
                loop += 1
            elif(self.probeResponsePacket is None and loop == self.retry):
                print('[!]\tProbe Request: No response detected!\r\n[-]')
                self.deauthenticationFrame(addr1=self.target_bssid)
                return 1
            elif(self.probeResponsePacket is not None):
                print('[!]\tProbe Request: Probe response detected!\r\n[-]')
                break
            else:
                pass
        return 0

    @classmethod
    def createAuthenticationFrame(self, addr1=None):
        from datetime import datetime
        import time
        boottime=time.time()
        dst=bssid=self.target_bssid
        loop = 1 
        while loop <= self.retry:
            print('[-]\t802.11 Frame Crafting: Authentication Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(
                loop, 
                self.ssid, 
                self.senderAddress.lower(), 
                bssid.lower(), 
                dst.lower()
            ))

            packet = self.RadioTap_layer/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
            packet.timestamp = self.currentTime(boottime)
            t = threading.Thread(target=self.sniffThread, daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
            t.join()
            if(self.authenticationRespPacket is None and loop != self.retry):
                print('[!]\tAuthentication Request: No response detected!')
                loop += 1
            elif(self.authenticationRespPacket is None and loop == self.retry):
                print('[!]\tAuthentication Request: No response detected!')
                self.deauthenticationFrame(addr1=self.target_bssid)
                return 1
            elif(self.authenticationRespPacket is not None):
                print('[!]\tAuthentication Request: Authentication response detected!')
                break
            else:
                pass
        return 0

    @classmethod
    def createAssociationFrame(self, addr1=None):
        from datetime import datetime
        import time
        boottime=time.time()
        dst=bssid=self.target_bssid
        loop = 1 
        while loop <= self.retry:
            print('[-]\t802.11 Frame Crafting: Association Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(
                loop, 
                self.ssid, 
                self.senderAddress.lower(), 
                bssid.lower(), 
                dst.lower()
            ))

            packet = self.RadioTap_layer/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11AssoReq(cap=self.real_capability, listen_interval=0x0001)/self.packet_probe_response_dot11elt_layer
            packet.timestamp = self.currentTime(boottime)
            t = threading.Thread(target=self.sniffThread, daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
            t.join()
            if(self.associationResponsePacket is None and loop != self.retry):
                print('[!]\tAssocation Request: No response detected!')
                loop += 1
            elif(self.associationResponsePacket is None and loop == self.retry):
                print('[!]\tAssocation Response: No response detected!')
                self.deauthenticationFrame(addr1=self.target_bssid)
                return 1
            elif(self.associationResponsePacket is not None):
                print('[!]\tAssociation Request: Association response detected!')
                break
            else:
                pass
        return 0

    @classmethod
    def findEAPIdentityRequest(self, packet=None):
        if( (packet.haslayer(EAP)) and (packet.code == 1) and (packet.addr3 == self.target_bssid.lower()) and (packet.addr1 == self.senderAddress.lower()) ):
            print('[-]\tEAP Identity Request: Identity request detected!')
            self.state_machine_state == 'sending_eap_identity_response'
            return packet
        return None

    @classmethod
    def ParserEapRequest(self, packet=None):
        self.eap_dot11QoS_A_MSDU_Present = packet.getlayer(Dot11QoS).A_MSDU_Present
        self.eap_dot11QoS_Ack_Policy = packet.getlayer(Dot11QoS).Ack_Policy
        self.eap_dot11QoS_EOSP = packet.getlayer(Dot11QoS).EOSP
        self.eap_dot11QoS_TID = packet.getlayer(Dot11QoS).TID
        self.eap_dot11QoS_TXOP = packet.getlayer(Dot11QoS).TXOP
        self.eap_llc_crtl = packet.getlayer(LLC).ctrl
        self.eap_llc_dsap = packet.getlayer(LLC).dsap
        self.eap_llc_ssap = packet.getlayer(LLC).ssap
        self.eap_snap_code = packet.getlayer(SNAP).code
        self.eap_eapol_type = packet.getlayer(EAPOL).type
        self.eap_eapol_version = packet.getlayer(EAPOL).version


    @classmethod
    def findEAPChallengeResponse(self, packet):
        print('[-]\thit')

    @classmethod
    def findEAPNegotiationRequest(self, packet=None):
        import scapy.layers.tls.handshake
        import scapy.layers.tls.record
        import scapy.layers.tls.extensions
        import scapy.layers.tls


        if( (packet.haslayer(EAP)) and (int(packet.type) not in [1]) and (packet.addr3 == self.target_bssid.lower()) and (packet.addr1 == self.senderAddress.lower()) ):
            print('[-]\tBSSID \'{}\' is attempting to negotiate EAP method: {}'.format(self.target_bssid, packet.type))
            
            print('[-]\t\'{}\' Certifcate extraction commencing...'.format(self.target_bssid))
            print('[-]\t\'{}\' Sending \'Client Hello\''.format(self.target_bssid))
            dst=bssid=self.target_bssid

            tls_layer = TLS(
                #version=771, # 0x0303 = TLS 1.2
                #version=770, # 0x0302 = TLS 1.1
                version=769, # 0x0301 = TLS 1.0
                msg=[
                    TLSClientHello(
                        #version=771, # 0x0303 = TLS 1.2
                        #version=770, # 0x0302 = TLS 1.1
                        version=769, # 0x0301 = TLS 1.0
                        sid=bytes.fromhex("1EC02BC02FC02CC030CCA9CCA8C009C013C00AC014009C009D002F003500"),
                        ciphers=[
                            0xc02b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                            0xc02f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                            0xc02c,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                            0xc030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                            0xcca8,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                            0xcca9,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                            0xc009,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                            0xc013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                            0xc00a,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                            0xc014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                            0x009c,  # TLS_RSA_WITH_AES_128_GCM_SHA256
                            0x9d,    # TLS_RSA_WITH_AES_256_GCM_SHA384
                            0x002f,  # TLS_RSA_WITH_AES_128_CBC_SHA
                            0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
                            0x000a,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
                        ],
                        comp=[0],
                        ext=[
                            TLS_Ext_ExtendedMasterSecret(),
                            TLS_Ext_RenegotiationInfo(),
                            TLS_Ext_SupportedGroups(),
                            TLS_Ext_SupportedPointFormat(),
                            TLS_Ext_SignatureAlgorithms(),
                            #TLS_Ext_SupportedVersions(len=2),
                            #TLS_Ext_SupportedEllipticCurves(),
                            #TLSChangeCipherSpec(),
                        ])
            ])

            peap_layer = EAP_PEAP(code=2, id=14, len=None, L=1, M=0, S=0, reserved=0, version=0, type=25 ,tls_message_len=len(tls_layer))
            peap_layer = EAP_PEAP(code=2, id=14, L=1, M=0, S=0, reserved=0, version=0, type=25, len=len(peap_layer)+len(tls_layer), tls_message_len=len(tls_layer))/tls_layer
            eapol_layer = EAPOL(version=1, type=self.eap_eapol_type, len=len(peap_layer))
            llc_layer = LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code, OUI=0x0)
            dot11_layer = Dot11FCS(
                subtype=8, type=2, addr1=dst, addr2=self.senderAddress, addr3=bssid, proto=0, FCfield='to-DS', ID=1337, fcs=0xf146cc6a, SC=16
                )/Dot11QoS(A_MSDU_Present=0, Ack_Policy=0, EOSP=0, TID=6, TXOP=0)

            #need to send the client hello of a tls handshake
            eapChallengeResponse = self.RadioTap_layer/dot11_layer/llc_layer/eapol_layer/peap_layer

            self.state_machine_state == 'sending_eap_method_negotiation_response'
            t = threading.Thread(target=self.sniffThread, daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=eapChallengeResponse, interface=self.interface, verbose=self.verbose, count=1)
            t.join()

    @classmethod
    def findEAPResponse(self, packet):
        from scapy.layers.tls.handshake import TLSClientHello
        if((packet.haslayer(EAP)) and (packet.addr3 == self.target_bssid) and (packet.addr1 == self.senderAddress)):
            dst=bssid=packet.addr3
            print('\n[-]\tEAP Challenge Request Found!')
            if(self.verbose):
                print('[-]\t\tEAP Challenge Request: {}'.format(packet.summary))
            if((packet.getlayer(EAP).type == 25) or (packet.getlayer(EAP).type == 13)):
                t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11), self.findEAPChallengeResponse, self.timeout), daemon=True)
                t.start()
                time.sleep(self.pause)
                self.sendFrame(pkt=eapChallengeResponse, interface=self.interface, verbose=self.verbose, count=1)
                t.join()

            else:
                print('[-]\t\'{}\' sent EAP Challenge Type: {}'.format(self.target_bssid, packet.getlayer(EAP).type))
                print('[-]\tForcing PEAP challenge handshake to BSSID: {}'.format(self.target_bssid))
                eapChallengeResponse = self.RadioTap_layer/Dot11FCS(addr1=dst, addr2=self.senderAddress, addr3=bssid)/LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code)/EAPOL(version=self.eap_eapol_version, type=self.eap_eapol_type)/EAP(code=2, id=packet.getlayer(EAP).id, type=3, desired_auth_types=25)
                t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11), self.findEAPResponse, self.timeout), daemon=True)
                t.start()
                time.sleep(self.pause)
                self.sendFrame(pkt=eapChallengeResponse, interface=self.interface, verbose=self.verbose, count=1)
                t.join()


    @classmethod
    def eapHandler(self):

        if(self.eapIdentityPacket is None):
            print('[!] EAP Identity Request: Identity Request not already found!')
            #self.state_machine_state = 'listen_for_eap_identity_request'
            #t = threading.Thread(target=self.sniffThread, daemon=True)
            #t.start()
            #t.join()
            #self.findEAPIdentityRequest()
        else:
            print('[-]\tConnected to BSSID \'{}\', starting EAP handshake'.format(self.target_bssid))

            # Sending EAPOL Start
            #print('[-]\tSending EAPOL Start to \'{}\''.format(self.target_bssid, self.eap_identity))
#            dst=bssid=self.target_bssid
#            self.ParserEapRequest(packet=self.eapIdentityPacket)
#            self.eapIdentityPacket = None
#            eapEapolStart = RadioTap() / Dot11FCS(
                #subtype=8, type=2, addr1=dst, addr2=self.senderAddress, addr3=bssid, proto=0, FCfield='to-DS', ID=1337, fcs=0xf146cc6a, SC=16
                #)/Dot11QoS(A_MSDU_Present=0, Ack_Policy=0, EOSP=0, TID=6, TXOP=0) / LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code, OUI=0x0) / EAPOL(type=1)
#            self.state_machine_state = 'listen_for_eap_identity_request'
#            t = threading.Thread(target=self.sniffThread, daemon=True)
#            t.start()
#            time.sleep(self.pause)
            #self.sendFrame(pkt=eapEapolStart, interface=self.interface, verbose=self.verbose, count=1)
#            t.join()


            # Sending Identity Response
            dst=bssid=self.target_bssid
            self.ParserEapRequest(packet=self.eapIdentityPacket)
            eapIdentityResponse = self.RadioTap_layer/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code)/EAPOL(version=self.eap_eapol_version, type=self.eap_eapol_type)/EAP( code=2, id=self.eapIdentityPacket.getlayer(EAP).id, type=1, identity=self.eap_identity)
            
            print('[-]\tSending EAP Response to \'{}\' with identity \'{}\''.format(self.target_bssid, self.eap_identity))
            self.state_machine_state = 'sent_eap_identity_response'
            t = threading.Thread(target=self.sniffThread, daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=eapIdentityResponse, interface=self.interface, verbose=self.verbose, count=1)
            t.join()

    @classmethod
    def deauthenticationFrame(self, addr1):
        from datetime import datetime
        import time
        boottime=time.time()
        dst=bssid=self.target_bssid
        print('[-]\t802.11 Frame Crafting: Deauthentication\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(self.ssid, self.senderAddress.lower(), bssid.lower(), dst.lower()))
        packet = self.RadioTap_layer/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11Deauth(reason=7)
        packet.timestamp = self.currentTime(boottime)
        self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
        return 0

    @classmethod
    def __Operator__(self):
        try:
            if(self.verbose):
                print('[-]\tSetting \'{}\' to operational mode to monitor'.format(self.interface))
            if(not self.check_interface_operational_mode(interface=self.interface, keyword='unamanged')):
                self.disable_nmcli_interface(interface=self.interface)

            if(not self.check_interface_operational_mode(interface=self.interface, keyword='Monitor')):
                self.set_interface_monitor(interface=self.interface)

            print('[-]\tAttempting to extract the certificate for each BSSID in BSSID queue')
            if(self.verbose):
                print('[-]\tBSSID pool:\r\n[-]\t\t{}'.format(self.bssids))
            for bssid in self.bssids:
                self.target_bssid=bssid
                print('[-]\tExtracting certificate for BSSID: \'{}\''.format(self.target_bssid.lower()))
                self.state_machine_state = 'probe'
                if(self.createProbeRequestFrame(addr1=self.target_bssid) != 0):
                    raise
                else:
                    self.parserProbeResponse(packet=self.probeResponsePacket)

                self.state_machine_state = 'authenticate'
                if(self.createAuthenticationFrame(addr1=self.target_bssid) != 0):
                    raise
                else:
                    self.parserAuthenticationResponse(packet=self.authenticationRespPacket)

                self.state_machine_state = 'associate'
                if(self.createAssociationFrame(addr1=self.target_bssid) != 0):
                    raise
                else:
                    self.parserAssocationResponse(packet=self.associationResponsePacket)
                    if(self.eapIdentityPacket is not None):
                        print('[-]\tEAP Identity Request: Identity request already detected!')

                self.eapHandler()

                self.deauthenticationFrame(addr1=self.target_bssid)
        except Exception as e:
            print('[!] Error: {}'.format(e))
            self.deauthenticationFrame(addr1=self.target_bssid)
            if( self.revert_interface_state ):
                self.set_interface_managed(interface=self.interface)
                self.enable_nmcli_interface(interface=self.interface)

'''
        for bssid in self.bssids:
                return 1
            if(self.createAuthenticationFrame(addr1=self.target_bssid) != 0):
                self.deauthenticationFrame(addr1=self.target_bssid)
                return 1
            if(self.createAssociationFrame(addr1=self.target_bssid) != 0):
                if(self.authenticationState):
                    self.deauthenticationFrame(addr1=self.target_bssid)
                return 1
            if((self.authenticationState and self.associatedState) and (self.eapIdentityPacket is not None)):
                self.eapHandler(packet=self.eapIdentityPacket, addr1=self.target_bssid)
            elif((self.authenticationState and self.associatedState) and (self.eapIdentityPacket is None)):
                print('[!]\tEAP request frame not found!')
            else:
                pass
            if(self.authenticationState or self.associatedState):
                self.deauthenticationFrame(addr1=self.target_bssid)
        print('[-]\tResetting interfaces')
        if(not self.monitor_status):
            self.set_interface_managed(interface=self.interface)
            self.disable_nmcli_interface(interface=self.interface)
        if(self.monitor_status):
            self.set_interface_managed(interface=self.interface)
            self.set_interface_managed(interface=self.monitor)
            self.disable_nmcli_interface(interface=self.interface)
            self.disable_nmcli_interface(interface=self.monitor)
        return 0
'''

if __name__ == '__main__':
    import os

    if(not os.geteuid() == 0):
        print('You need to be root to run this tool')
        exit(0)
    else:
        if(options['mode'] == 0):
            print('[+] Entering \'live certificate extraction\' mode\r\n[-]')
            bssidList = list()
            if( (not options['bssid']) and (options['bssid_file'] is None) ):
                bssidList.append('ff:ff:ff:ff:ff:ff')
            else:
                if(options['bssid'] is not None):
                    for bssid in options['bssid']:
                        bssidList.append(bssid)
                elif(options['bssid_file'] is not None):
                    with open(options['bssid_file'], 'r') as f:
                        bssidList.append(f.readlines().strip('\n'))
                    f.close()
                else:
                    pass
            w = wifipemClass(
                retry=options['retry'],
                pause=options['pause'],
                ssid=options['ssid'],
                bssids=bssidList,
                interface=options['interface'],
                monitor=options['monitor'],
                monitor_status=options['monitor_status'],
                timeout=options['timeout'],
                verbose=options['verbose'],
                scan_enable=options['scan_enable'],
                eap_identity=options['eap_identity'],
                default_eap_type=options['default_eap_type']
            )
            w.__Operator__()
        elif(options['mode'] == 1):
            print('[+] Entering \'pcap certificate extraction\' mode\r\n[-]')
            pass
        else:
            print('[!] Error: Unknown mode selected')
            sys.exit(1)
    print('[-]\r\n[+] Finished!')
    sys.exit(0)

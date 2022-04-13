#!/usr/bin/python3

import argparse
from scapy.all import *

parser = argparse.ArgumentParser(description='Automated tool for extract the public key presented by WPA2-Enterprise wireless networks')

parser.add_argument('-o', '--output', dest='output_file')
parser.add_argument('-t', '--timeout', dest='timeout', default=3, type=int)
parser.add_argument('--verbose', dest='verbose', action='store_true', default=False, help='enable verbosity')
parser.add_argument('--scan', dest='scan_enable', action='store_true', default=False, help='Scan for WLAN')
parser.add_argument('-r', '--retry', dest='retry', default=3, type=int, help='Control number of retry attempts at transmission and detection')
parser.add_argument('-p', '--pause', dest='pause', default=1, type=float, help='Control pause between starting sniffer thread and sending frame')
parser.add_argument('--version', action='version', version='%(prog)s 2.0.0')

sourceOptions = parser.add_argument_group(description='Specify target source for extraction')
sourceOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')
sourceOptions.add_argument('-f', '--filename', dest='filename', help='extract .pem from a pcap')
sourceOptions.add_argument('-s', '--ssid', dest='ssid', help='select target SSID')
sourceOptions.add_argument('-b', '--bssid', dest='bssid', nargs='+', default=[''], help='select BSSID')
sourceOptions.add_argument('-B', '--bssids', dest='bssid_file', default=None, help='provide file containing BSSIDs')

monitorOptions = parser.add_argument_group(description='Specify target source for extraction')
monitorOptions.add_argument('-M', '--enable-monitor', dest='monitor_status', action='store_true', default=False, help='set interface to use')
monitorOptions.add_argument('-m', '--monitor', dest='monitor', help='set interface to use')

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
        self.probeResponsePacket = None
        self.authenticationPacket = None
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
        #self.eap_peap_tls_data = "\x16\x03\x03\x00\x9d\x01\x00\x00\x99\x03\x03bB\x85\xad\xcc\xbc\xea\xc6\xe4~\xb0l\x8cd\xa2\r+\x1et\xf0\x81A\xc0\xc4\xa8\xd95\xd1\xdaH\xa2\xa2\x00\x00*\xc0,\xc0+\xc00\xc0/\x00\x9f\x00\x9e\xc0$\xc0#\xc0(\xc0'\xc0\n\xc0\t\xc0\x14\xc0\x13\x00\x9d\x00\x9c\x00=\x00<\x005\x00/\x00\n\x01\x00\x00F\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\n\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\r\x00\x1a\x00\x18\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03\x00#\x00\x00\x00\x17\x00\x00\xff\x01\x00\x01\x00"
        #self.eap_peap_tls_data = b'160303009d010000990303624285adccbceac6e47eb06c8c64a20d2b1e74f08141c0c4a8d935d1da48a2a200002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a01000046000500050100000000000a00080006001d00170018000b00020100000d001a00180804080508060401050102010403050302030202060106030023000000170000ff01000100'
        #   self.eap_peap_tls_data = [0x16, 0x03, 0x03, 0x00, 0x9d, 0x01, 0x00, 0x00, 0x99, 0x03, 0x03, 0x62, 0x42, 0x85, 0xad, 0xcc, 0xbc, 0xea, 0xc6, 0xe4, 0x7e, 0xb0, 0x6c, 0x8c, 0x64, 0xa2, 0x0d, 0x2b, 0x1e, 0x74, 0xf0, 0x81, 0x41, 0xc0, 0xc4, 0xa8, 0xd9, 0x35, 0xd1, 0xda, 0x48, 0xa2, 0xa2, 0x00, 0x00, 0x2a, 0xc0, 0x2c, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x27, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x46, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x02, 0x02, 0x06, 0x01, 0x06, 0x03, 0x00, 0x23, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00]
        #self.eap_peap_tls_data ="\x16\x03\x03\x00\x9d\x01\x00\x00\x99\x03\x03\x62\x42\x85\xad\xcc\xbc\xea\xc6\xe4\x7e\xb0\x6c\x8c\x64\xa2\x0d\x2b\x1e\x74\xf0\x81\x41\xc0\xc4\xa8\xd9\x35\xd1\xda\x48\xa2\xa2\x00\x00\x2a\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f\x00\x9f\x00\x9e\xc0\x24\xc0\x23\xc0\x28\xc0\x27\xc0\x0a\xc0\x09\xc0\x14\xc0\x13\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\x0a\x01\x00\x00\x46\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x1a\x00\x18\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03\x00\x23\x00\x00\x00\x17\x00\x00\xff\x01\x00\x01\x00"
        #self.eap_peap_tls_data = b'160303009d0100009903036243e42bb620caaa67f421045ebcf76dbfa30d6862d59f9ea2e4a614c53e6bb000002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a01000046000500050100000000000a00080006001d00170018000b00020100000d001a001808040805080604'
        self.eap_peap_tls_data = "\x16\x03\x03\x00\x9d\x01\x00\x00\x99\x03\x03\x62\x42\x85\xad\xcc\xbc\xea\xc6\xe4\x7e\xb0\x6c\x8c\x64\xa2\x0d\x2b\x1e\x74\xf0\x81\x41\xc0\xc4\xa8\xd9\x35\xd1\xda\x48\xa2\xa2\x00\x00\x2a\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f\x00\x9f\x00\x9e\xc0\x24\xc0\x23\xc0\x28\xc0\x27\xc0\x0a\xc0\x09\xc0\x14\xc0\x13\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\x0a\x01\x00\x00\x46\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x1a\x00\x18\x08\x04\x08\x05\x08\x06\x04"
        self.eap_peap_tls_data = 0x160303009d0100009903036243e42bb620caaa67f421045ebcf76dbfa30d6862d59f9ea2e4a614c53e6bb000002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a01000046000500050100000000000a00080006001d00170018000b00020100000d001a001808040805080604

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
    def findProbeResponse(self, packet):
        if((packet.addr2 == self.target_bssid.lower()) and (packet.addr1 == self.senderAddress.lower())):
            self.probeResponsePacket = packet

    @classmethod
    def parserProbeResponse(self):
        if(self.verbose):
            print("[-]\tParsing the Probe response")
        self.real_capability = int(self.probeResponsePacket.getlayer(Dot11ProbeResp).cap)
        self.real_bssid = (self.probeResponsePacket.getlayer(Dot11).addr3)
        packet = self.probeResponsePacket
        self.packet_probe_response_dot11elt_layer = packet.getlayer(Dot11Elt)

    @classmethod
    def findAuthenticationResponse(self, packet):
        if((packet.addr3 == self.target_bssid.lower()) and (packet.addr2 == self.senderAddress.lower())):
            self.authenticationState = True
            self.authenticationPacket = packet

    @classmethod
    def parserAuthenticationResponse(self):
        pass

    @classmethod
    def findAssociationResponse(self, packet):
        if((packet.haslayer(Dot11AssoResp)) and (packet.addr3 == self.target_bssid.lower()) and (packet.addr1 == self.senderAddress.lower())):
            self.associatedState = True
            self.associationResponsePacket = packet
        elif((packet.haslayer(EAP)) and (packet.addr3 == self.target_bssid.lower()) and (packet.addr1 == self.senderAddress.lower()) and (self.associatedState and self.authenticationState) and (packet.getlayer(EAP).code == 1)):
            print('[-]\t\tEAP Identity Request Found!')
            self.eapIdentityPacket = packet
            return 0
        return 0

    @classmethod
    def parserAssocationResponse(self):
        pass

    @classmethod
    def sniffThread(self, monitor_interface, lfilter, stop_filter, timeout):
        if(self.verbose):
            print('[-]\tSniff Thread Started: Interface: \'{}\''.format(monitor_interface))
        sniff(iface=monitor_interface, lfilter=lfilter, stop_filter=stop_filter, timeout=timeout)
        if(self.verbose):
            print('[-]\tSniff Thread Ended: Interface: \'{}\''.format(monitor_interface))

    @classmethod
    def createProbeRequestFrame(self, addr1):
        from datetime import datetime
        import time
        boottime=time.time()
        loop = 1
        while loop <= self.retry:
            if(self.scan_enable):
                dst=bssid='ff:ff:ff:ff:ff:ff'
            else:
                dst=bssid=addr1
            print('[-]\t802.11 Frame Crafting: Probe Request Attempt {}\r\n[-]\t\tssid: {}\r\n[-]\t\tSTA: {}\r\n[-]\t\tBSSID: {}\r\n[-]\t\tDST: {}'.format(loop, self.ssid, self.senderAddress.lower(), bssid.lower(), dst.lower()))
            packet = RadioTap()/Dot11(type=0, subtype=4, addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11ProbeReq()/Dot11Elt(ID='SSID', info=self.ssid, len=len(self.ssid))/Dot11EltRates()
            packet.timestamp = self.currentTime(boottime)
            t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11ProbeResp), self.findProbeResponse, self.timeout), daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
            t.join()
            if(self.probeResponsePacket is not None):
                print('[!]\tProbe Request: Response detected!\r\n[-]')
                self.parserProbeResponse()
                if(self.verbose):
                    print('[-]\t\tResponse Packet:\r\n\t\t{}'.format(self.probeResponsePacket.summary))
                break
            elif(self.probeResponsePacket is None and loop < self.retry):
                print('[!]\tProbe Request: No response detected!\r\n[-]')
                loop += 1
            elif(self.probeResponsePacket is None and loop == self.retry):
                print('[!]\tProbe Request: No response detected!\r\n[-]')
                self.deauthenticationFrame(addr1=self.target_bssid)
                return 1
            else:
                print('[!]\tProbe Request: No response detected!\r\n[-]')
                self.deauthenticationFrame(addr1=self.target_bssid)
                return 1

        return 0

    @classmethod
    def createAuthenticationFrame(self, addr1):
        from datetime import datetime
        import time
        boottime=time.time()
        dst=bssid=addr1
        loop = 1 
        while loop <= self.retry:
            print('[-]\t802.11 Frame Crafting: Authentication Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(loop, self.ssid, self.senderAddress.lower(), bssid.lower(), dst.lower()))
            packet = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
            packet.timestamp = self.currentTime(boottime)
            t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11Auth), self.findAuthenticationResponse, self.timeout), daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
            t.join()
            if(self.authenticationPacket is not None):
                print('[!]\tAuthentication Request: Response detected!')
                self.parserAuthenticationResponse()
                if(self.verbose):
                    print('[-]\t\tResponse Packet:\r\n\t\t{}'.format(self.authenticationPacket.summary))
                break
            elif(self.authenticationPacket is None and loop != self.retry):
                print('[!]\tAuthentication Request: No response detected!')
                loop += 1
            elif(self.authenticationPacket is None and loop == self.retry):
                print('[!]\tAuthentication Request: No response detected!')
                return 1
            else:
                print('[!]\tAuthentication Request: No response detected!')
                return 1
        return 0

    @classmethod
    def createAssociationFrame(self, addr1):
        from datetime import datetime
        import time
        boottime=time.time()
        dst=bssid=addr1
        loop = 1 
        while loop <= self.retry:
            print('[-]\t802.11 Frame Crafting: Association Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(loop, self.ssid, self.senderAddress.lower(), bssid.lower(), dst.lower()))
            packet = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11AssoReq(cap=self.real_capability, listen_interval=0x0001)/self.packet_probe_response_dot11elt_layer
            packet.timestamp = self.currentTime(boottime)
            t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11), self.findAssociationResponse, self.timeout), daemon=True)
            t.start()
            time.sleep(self.pause)
            self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
            t.join()
            if(self.associationResponsePacket is not None):
                print('[!]\tAssocation Response: Response detected!')
                self.parserAssocationResponse()
                if(self.verbose):
                    print('[-]\t\tResponse Packet:\r\n\t\t{}'.format(self.associationResponsePacket.summary))
                break
            elif(self.associationResponsePacket is None and loop != self.retry):
                print('[!]\tAssocation Request: No response detected!')
                loop += 1
            elif(self.associationResponsePacket is None and loop == self.retry):
                print('[!]\tAssocation Response: No response detected!')
                return 1
            else:
                print('[!]\tAssocation Response: No response detected!')
                return 1
        return 0

    @classmethod
    def ParserEapRequest(self, packet):
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
    def findEAPResponse(self, packet):
        from scapy.layers.tls.handshake import TLSClientHello
        if((packet.haslayer(EAP)) and (packet.addr3 == self.target_bssid) and (packet.addr1 == self.senderAddress)):
            dst=bssid=packet.addr3
            print('\n[-]\tEAP Challenge Request Found!')
            if(self.verbose):
                print('[-]\t\tEAP Challenge Request: {}'.format(packet.summary))
            if((packet.getlayer(EAP).type == 25) or (packet.getlayer(EAP).type == 13)):
                print('[-]\t\'{}\' Certifcate extraction commencing...'.format(self.target_bssid))
                eapChallengeResponse = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code)/EAPOL(version=self.eap_eapol_version, type=self.eap_eapol_type)/EAP(code=2, id=packet.getlayer(EAP).id, type=self.default_eap_type)/EAP_PEAP(L=1, M=0, S=0, reserved=0, version=0, type=25, tls_message_len=len(self.eap_peap_tls_data), tls_data=self.eap_peap_tls_data)
                t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11), self.findEAPChallengeResponse, self.timeout), daemon=True)
                t.start()
                time.sleep(self.pause)
                self.sendFrame(pkt=eapChallengeResponse, interface=self.interface, verbose=self.verbose, count=1)
                t.join()

            else:
                print('[-]\t\'{}\' sent EAP Challenge Type: {}'.format(self.target_bssid, packet.getlayer(EAP).type))
                print('[-]\tForcing PEAP challenge handshake to BSSID: {}'.format(self.target_bssid))
                eapChallengeResponse = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code)/EAPOL(version=self.eap_eapol_version, type=self.eap_eapol_type)/EAP(code=2, id=packet.getlayer(EAP).id, type=3, desired_auth_types=25)
                t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11), self.findEAPResponse, self.timeout), daemon=True)
                t.start()
                time.sleep(self.pause)
                self.sendFrame(pkt=eapChallengeResponse, interface=self.interface, verbose=self.verbose, count=1)
                t.join()


    @classmethod
    def eapHandler(self, packet, addr1):
        dst=bssid=addr1
        print('[-]\tConnected to BSSID \'{}\', starting EAP handshake'.format(self.target_bssid))
        self.ParserEapRequest(packet=packet)
        eapresponse = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code)/EAPOL(version=self.eap_eapol_version, type=self.eap_eapol_type)/EAP(code=2, id=packet.getlayer(EAP).id, type=1, identity=self.eap_identity)
        print('[-]\tSending EAP Response to \'{}\' with identity \'{}\''.format(bssid, self.eap_identity))
        if(self.verbose):
            print('[-]\tEAP Response:\r\n\t\t{}'.format(eapresponse))
        t = threading.Thread(target=self.sniffThread, args=(self.monitor if self.monitor is not None else self.interface, lambda x: x.haslayer(Dot11), self.findEAPResponse, self.timeout), daemon=True)
        t.start()
        time.sleep(self.pause)
        self.sendFrame(pkt=eapresponse, interface=self.interface, verbose=self.verbose, count=1)
        t.join()
        return

    @classmethod
    def deauthenticationFrame(self, addr1):
        from datetime import datetime
        import time
        boottime=time.time()
        dst=bssid=addr1
        print('[-]\t802.11 Frame Crafting: Deauthentication\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(self.ssid, self.senderAddress.lower(), bssid.lower(), dst.lower()))
        packet = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11Deauth(reason=7)
        packet.timestamp = self.currentTime(boottime)
        self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
        return 0

    @classmethod
    def __Operator__(self):
        if(self.verbose):
            print('[-]\tSetting \'{}\' to operational mode to monitor'.format(self.interface))
        print('[-]\tConfiguring interfaces')
        if(not self.monitor_status):
            self.disable_nmcli_interface(interface=self.interface)
            self.set_interface_monitor(interface=self.interface)
        if(self.monitor_status):
            self.disable_nmcli_interface(interface=self.monitor)
            self.disable_nmcli_interface(interface=self.interface)
            self.set_interface_managed(interface=self.interface)
            self.set_interface_monitor(interface=self.monitor)
        if(self.verbose):
            print('[-]\tBSSID pool:\r\n[-]\t\t{}'.format(self.bssids))
        for bssid in self.bssids:
            self.target_bssid=bssid
            print('[-]\tExtracting certificate for BSSID: \'{}\''.format(self.target_bssid.lower()))
            if(self.createProbeRequestFrame(addr1=self.target_bssid) != 0):
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


if __name__ == '__main__':
    import os
    if((options['filename'] and options['interface'] is not None) or (options['filename'] and options['interface'] is None)):
        print('[!] Select one source of extraction')
        sys.exit(0)
    elif(options['filename']):
        print('[+] Entering \'pcap certificate extraction\' mode\r\n[-]')
        pass
    elif(options['monitor_status'] and ((options['interface'] is not None and options['monitor'] is None) or (options['interface'] is None and options['monitor'] is not None))):
        print('[!] Two interfaces are required!')
        sys.exit(0)
    elif((options['interface'] is None)):
        print('Provide WLAN adaptor')
        sys.exit(0)
    elif(options['ssid'] is None):
        print('Select SSID!')
        sys.exit(0)
    elif((options['bssid'] is None) and (options['bssid_file'] is None)):
        print('Provide BSSID target information')
        sys.exit(0)
    elif(not os.geteuid() == 0):
        print('You need to be root to run this tool')
        exit(0)
    else:
        print('[+] Entering \'live certificate extraction\' mode\r\n[-]')
        bssidList = list()
        try:
            if(options['bssid'] is not None):
                for bssid in options['bssid']:
                    bssidList.append(bssid)
            elif(options['bssid_file'] is not None):
                with open(options['bssid_file'], 'r') as f:
                    bssidList.append(f.readlines().strip('\n'))
                f.close()
            else:
                raise
        except Exception as e:
            print('[-]\tSet -b or -B arguments')
            exit(0)
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
        print('[-]\r\n[+] Finished!')

    sys.exit(0)

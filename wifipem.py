#!/usr/bin/python3

import argparse
from scapy.all import *

parser = argparse.ArgumentParser(description='Automated tool for extract the public key presented by WPA2-Enterprise wireless networks')

parser.add_argument('-s', '--ssid', dest='ssid', help='select target SSID')
parser.add_argument('-o', '--output', dest='output_file')
parser.add_argument('-t', '--timeout', dest='timeout', default=3, type=int)
parser.add_argument('--verbose', dest='verbose', action='store_true', default=False, help='enable verbosity')
parser.add_argument('--scan', dest='scan_enable', action='store_true', default=False, help='Scan for WLAN')
parser.add_argument('-r', '--retry', dest='retry', default=1, type=int, help='Control number of retry attempts at transmission and detection')
parser.add_argument('-p', '--pause', dest='pause', default=1, type=float, help='Control pause between starting sniffer thread and sending frame')
parser.add_argument('--version', action='version', version='%(prog)s 2.0.0')

sourceOptions = parser.add_argument_group(description='Specify target source for extraction')
sourceOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')
sourceOptions.add_argument('-f', '--filename', dest='filename', help='extract .pem from a pcap')
sourceOptions.add_argument('-b', '--bssid', dest='bssid', help='select BSSID')
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
        self.monitor=monitor
        self.scan_enable=scan_enable
        self.timeout=timeout
        self.associatedState=False
        self.authenticationState=False
        self.eap_identity = eap_identity
        self.default_eap_type = default_eap_type
        self.client_tls_cipher_list = [ 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255]

        # Interfaces
        self.interface=interface
        self.senderAddress=self.getSenderAddress(interface=self.interface)
        #self.set_interface_managed(interface=self.interface)
        #self.set_interface_monitor(interface=self.interface)
        if(monitor_status):
            self.set_interface_monitor(interface=self.monitor)

        # Packet Memory
        self.probeResponsePacket = None
        self.authenticationPacket = None
        self.associationResponsePacket = None
        self.eapIdentityPacket = None
        self.real_capability = None
        self.real_bssid = None
        self.eap_version = None
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
        if((packet.addr3 == self.target_bssid) and (packet.addr1 == self.senderAddress)):
            self.probeResponsePacket = packet

    @classmethod
    def parserProbeResponse(self):
        self.real_capability = int(self.probeResponsePacket.getlayer(Dot11ProbeResp).cap)
        self.real_bssid = (self.probeResponsePacket.getlayer(Dot11).addr3)
        packet = self.probeResponsePacket
        dot11elt = packet.getlayer(Dot11Elt)
        while dot11elt:
            if(dot11elt.ID == 1 and dot11elt.name == '802.11 Rates'):
                self.real_rates = dot11elt.info
            elif(dot11elt.ID == 50 and dot11elt.name == '802.11 Rates'):
                self.real_extended_rates = dot11elt.info
            elif(dot11elt.ID == 48 and dot11elt.name == '802.11 RSN information'):
                self.real_rsn = dot11elt.info
            elif(dot11elt.ID == 45 and dot11elt.name == '802.11 HT Capabilities'):
                self.real_ht_capabilities = dot11elt.info
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)

    @classmethod
    def findAuthenticationResponse(self, packet):
        if((packet.addr3 == self.target_bssid) and (packet.addr2 == self.senderAddress)):
            self.authenticationState = True
            self.authenticationPacket = packet

    @classmethod
    def parserAuthenticationResponse(self):
        pass

    @classmethod
    def findAssociationResponse(self, packet):
        if((packet.haslayer(Dot11AssoResp)) and (packet.addr3 == self.target_bssid) and (packet.addr1 == self.senderAddress)):
            self.associatedState = True
            self.associationResponsePacket = packet
        elif((packet.haslayer(EAP)) and (packet.addr3 == self.target_bssid) and (packet.addr1 == self.senderAddress) and (self.associatedState and self.authenticationState) and (packet.getlayer(EAP).code == 1)):
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
            print('[-]\t802.11 Frame Crafting: Probe Request Attempt {}\r\n[-]\t\tssid: {}\r\n[-]\t\tSTA: {}\r\n[-]\t\tBSSID: {}\r\n[-]\t\tDST: {}'.format(loop, self.ssid, self.senderAddress, bssid, dst))
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
            print('[-]\t802.11 Frame Crafting: Authentication Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(loop, self.ssid, self.senderAddress, bssid, dst))
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
            print('[-]\t802.11 Frame Crafting: Association Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(loop, self.ssid, self.senderAddress, bssid, dst))
            packet = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11AssoReq(cap=self.real_capability, listen_interval=0x0001)/Dot11Elt(ID=0, info=self.ssid)/Dot11Elt(ID=1, info=self.real_rates)/Dot11Elt(ID=45, info=self.real_ht_capabilities)/Dot11Elt(ID=48, info=self.real_rsn)/Dot11Elt(ID=50, info=self.real_extended_rates)
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
            print('[-]\tEAP Challenge Request Found!')
            if(self.verbose):
                print('[-]\t\tEAP Challenge Request: {}'.format(packet.summary))
            if((packet.getlayer(EAP).type == 25) or (packet.getlayer(EAP).type == 13)):
                print('[-]\t\'{}\' Certifcate extraction commencing...'.format(self.target_bssid))
                eapChallengeResponse = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/LLC(dsap=self.eap_llc_dsap, ssap=self.eap_llc_ssap, ctrl=self.eap_llc_crtl)/SNAP(code=self.eap_snap_code)/EAPOL(version=self.eap_eapol_version, type=self.eap_eapol_type)/EAP(code=2, id=packet.getlayer(EAP).id, type=self.default_eap_type)/EAP_PEAP(L=1, M=0, S=0, reserved=0, version=0, type=25, tls_data=TLSClientHello(version=0x00000301, ciphers=self.client_tls_cipher_list, cipherslen=len(self.client_tls_cipher_list), sidlen=0, msgtype=1))
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
        print('[-]\t802.11 Frame Crafting: Deauthentication\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(self.ssid, self.senderAddress, bssid, dst))
        packet = RadioTap()/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11Deauth(reason=7)
        packet.timestamp = self.currentTime(boottime)
        self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
        return 0

    @classmethod
    def __Operator__(self):
        if(self.verbose):
            print('[-]\tBSSID pool:\r\n[-]\t\t{}'.format(self.bssids))
        for bssid in self.bssids:
            self.target_bssid=bssid
            print('[-]\tExtracting certificate for BSSID: \'{}\''.format(self.target_bssid))
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
                bssidList.append(options['bssid'])
            elif(options['bssid'] is not None):
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

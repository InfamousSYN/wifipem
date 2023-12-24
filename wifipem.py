#!/usr/bin/python3
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

import argparse
from scapy.all import *

## Settings
__version__ = '2.0.0'
radius_certificate_extract_location = 'radius.der'
pcap_outfile_location = 'wifipem_certificate_capture.pcap'
wpa_supplicant_conf_file = 'wpa_supplicant.conf'
default_timeout = 15
default_identity = 'infamoussyn'
default_password = 'infamoussyn'

parser = argparse.ArgumentParser(description='Automated tool for extract the public key presented by WPA2-Enterprise wireless networks')

parser.add_argument('-o', '--output', dest='output_file')
parser.add_argument('-t', '--timeout', dest='timeout', default=3, type=int)
parser.add_argument('--verbose', dest='verbose', action='store_true', default=False, help='enable verbosity')
parser.add_argument('--scan', dest='scan_enable', action='store_true', default=False, help='Scan for WLAN')
parser.add_argument('-r', '--retry', dest='retry', default=3, type=int, help='Control number of retry attempts at transmission and detection')
parser.add_argument('-d', '--delay', dest='pause', default=1, type=float, help='Control pause between starting sniffer thread and sending frame')
parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))

sourceMode = parser.add_argument_group(description='Specify source for targeting information')
sourceMode.add_argument('-m', choices=[0,1], dest='mode', type=int, help='0 = live, 1 = pcap', required=True)

targetOptions = parser.add_argument_group(description='Specify targeting information')
targetOptions.add_argument('-s', dest='ssid', help='select target SSID')
targetOptions.add_argument('-b', dest='bssid', nargs='+', default=[], help='select BSSID')

liveCaptureOptions = parser.add_argument_group(description='Specify targeting information for live extration. Used when -m 0 source mode is chosen')
liveCaptureOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')
liveCaptureOptions.add_argument('-c', '--channel', dest='channel', help='set interface channel to use')
liveCaptureOptions.add_argument('-bL', dest='bssid_file', default=None, help='provide file containing BSSIDs')

pcapOptions = parser.add_argument_group(description='')
pcapOptions.add_argument('-f', '--input-file', dest='pcap_filename', help='Specify pcap file to extract certificate from')

args, leftover = parser.parse_known_args()
options = args.__dict__

class wpa_supplicant_without_bssid_conf(object):
    path = wpa_supplicant_conf_file
    template = '''
ctrl_interface=/var/run/wpa_supplicant
network={{
    ssid="{}"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="{}"
    password="{}"
}}
    '''
    @classmethod
    def configure(cls, ssid, hidden, identity, password):
        try:
            with open(cls.path, 'w') as fd:
                fd.write(cls.template.format(
                        ssid,
                        hidden,
                        identity,
                        password
                    ))
            return 0
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1

class wpa_supplicant_with_bssid_conf(object):
    path = wpa_supplicant_conf_file
    template = '''
    ctrl_interface=/var/run/wpa_supplicant
        network={{
        ssid="{}"
        scan_ssid={}
        bssid={}
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="{}"
        password="{}"
    }}
    '''
    @classmethod
    def configure(cls, ssid, hidden, bssid, identity, password):
        try:
            with open(cls.path, 'w') as fd:
                fd.write(cls.template.format(
                        ssid,
                        hidden,
                        bssid,
                        identity,
                        password
                    ))
            return 0
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1

def liveExtraction(interface, ssid, config, timeout):
    import subprocess, time, datetime, os, signal

    command = [
        'wpa_supplicant',
        '-i {}'.format(interface),
        '-c{}'.format(config),
        '-v'
    ]
    start = datetime.datetime.now()

    try:
        print('[-]  Connecting to wireless network "{}" using wpa_supplicant.conf file: {}'.format(ssid, config))
        ps = subprocess.Popen(command,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out,err = ps.communicate()
        print(out)
        while(ps.poll() is None):
            time.sleep(0.1)
            now = datetime.datetime.now()
            if((now-start).seconds > timeout):
                os.kill(ps.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
    except Exception as e:
        print('[!] Error: {}'.format(e))
    return 0

class wifipemClass(object):

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
    def ifaceChannel(interface, channel):
        import os
        os.system('iwconfig {} channel {}'.format(interface, channel))
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
    def __init__(self,ssid=None,interface=None,timeout=None,mode=None,pcap_filename=None,verbose=False):
        self.ssid=ssid
        self.interface=interface
        self.timeout=timeout
        self.mode=mode
        self.verbose=verbose
        self.hidden=None
        self.bssid=None
        self.identity=None
        self.password=None
        self.pcap_filename=pcap_filename
        self.list_of_bssid=[]
        self.ignore_bssid = [
        'ff:ff:ff:ff:ff:ff'
        ]

    @classmethod
    def handlerLive(self):
        import threading
        import time
        try:
            print('[-] Creating wpa_supplicant.conf file')
            if(self.bssid is not None):
                wpa_supplicant_with_bssid_conf.configure(
                    ssid=self.ssid,
                    hidden=self.hidden,
                    bssid=self.bssid,
                    identity=self.identity,
                    password=self.password
                )
            else:
                wpa_supplicant_without_bssid_conf.configure(
                    ssid=self.ssid,
                    hidden=self.hidden,
                    identity=self.identity,
                    password=self.password
                )
            t = threading.Thread(target=liveExtraction, kwargs={'interface':self.interface,'ssid':self.ssid, 'config':wpa_supplicant_conf_file, 'timeout':self.timeout}, daemon=True)
            t.start()
            time.sleep(3)
            t.join()
        except Exception as e:
            print(e)
            return 1
        return 0


    @classmethod
    def handlerPcap(self):
        print('[-]\tBuilding list of BSSID broadcasting \'{}\''.format(self.ssid))
        sniff(offline=self.pcap_filename, prn=self.__packet_parser_bssid__, store=0)
        print('[-]\tExtracting certificate')
        sniff(offline=self.pcap_filename, prn=self.__packet_parser_certificate__, store=0)
        return 0

    @classmethod
    def __packet_parser_bssid__(self,packet=None):
        if( (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)) and (packet.addr2 not in self.ignore_bssid) and (packet.info.decode('utf-8') == self.ssid) ):
            if(packet.addr2 not in self.list_of_bssid):
                if(self.verbose):
                    print('[-]\tFound new BSSID for {}, adding...'.format(self.ssid))
                self.list_of_bssid.append(packet.addr2)
            else:
                pass
        return None

    @classmethod
    def __packet_parser_certificate__(self,packet=None):
        if( (not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11ProbeResp)) and (packet.addr2 in self.list_of_bssid) and (packet.haslayer(EAPOL) and packet.getlayer(EAPOL).id == 76) ):
            print(packet.tls_data)
        else:
            pass
        return None

    @classmethod
    def __Operator__(self):

        if(self.mode=='live'):
            if(self.verbose):
                print('[-]\tSetting \'{}\' to operational mode to monitor'.format(self.interface))
            if(not self.check_interface_operational_mode(interface=self.interface, keyword='unamanged')):
                self.disable_nmcli_interface(interface=self.interface)
            if(not self.check_interface_operational_mode(interface=self.interface, keyword='Managed')):
                self.set_interface_managed(interface=self.interface)
            self.handlerLive()
        elif(self.mode=='pcap'):
            self.handlerPcap()
        else:
            raise

        if(self.mode=='live'):
            self.enable_nmcli_interface(interface=self.interface)

if __name__ == '__main__':
    import os
    if(not os.geteuid() == 0):
        print('You need to be root to run this tool')
        exit(1)
    else:
        pass

    if(options['mode'] is None):
        print('[!] Select one source of extraction')
        exit(1)
    elif(options['mode'] == 0):
        print('[+] Commencing live extration mode')
        wifipemClass(
            verbose=options['verbose'],
            ssid=options['ssid'],
            interface=options['interface'],
            timeout=options['timeout'],
            mode='live'
        ).__Operator__()
        
        pass
    elif(options['mode'] == 1):
        print('[+] Commencing PCAP extration mode')
        wifipemClass(
            verbose=options['verbose'],
            ssid=options['ssid'],
            pcap_filename=options['pcap_filename'],
            mode='pcap'
        ).__Operator__()
    else:
        exit(1)


    exit(0)

#!/usr/bin/python3

import argparse

## Settings
__version__ = '1.0'
radius_certificate_extract_location = 'radius.der'
pcap_outfile_location = 'wifipem_certificate_capture.pcap'
wpa_supplicant_conf_file = 'wpa_supplicant.conf'
default_timeout = 15
default_identity = 'infamoussyn'
default_password = 'infamoussyn'

parser = argparse.ArgumentParser(description='Automated tool for extract the public key presented by WPA2-Enterprise wireless networks')

parser.add_argument('--version', action='version', version=__version__)
parser.add_argument('-s', '--ssid', dest='ssid', help='select target SSID')
parser.add_argument('-o', '--output', dest='output_file', default=radius_certificate_extract_location, help='Specify the output file (Default: {})'.format(radius_certificate_extract_location))

sourceOptions = parser.add_argument_group(description='Specify target source for extraction')
sourceOptions.add_argument('-f', '--filename', dest='filename', help='extract .pem from a pcap')
sourceOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')
sourceOptions.add_argument('-B', dest='bssid_file', default=None, help='provide file containing BSSIDs')

liveExtractionOptions = parser.add_argument_group(description='Control settings for live extraction')
liveExtractionOptions.add_argument('-t', '--timeout', dest='timeout', type=int, default=default_timeout, help='specify the timeout for live capture window (Default: {})'.format(default_timeout))
liveExtractionOptions.add_argument('--identity', dest='identity', default=default_identity, help='specify the user identity to connect with (Default: {})'.format(default_identity))
liveExtractionOptions.add_argument('--password', dest='password', default=default_password, help='specify the user password to connect with (Default: {})'.format(default_password))
liveExtractionOptions.add_argument('-p', '--pcap-outfile', dest='pcap_outfile', default=pcap_outfile_location, help='specify the output location of the live capture (Default: {})'.format(pcap_outfile_location))
liveExtractionOptions.add_argument('--hidden', dest='hidden', type=int, default=0, choices=[0,1], help='Toggle for hidden network detection. Default: 0')

args, leftover = parser.parse_known_args()
options = args.__dict__

class wpa_supplicant_without_bssid_conf(object):
    path = wpa_supplicant_conf_file
    template = '''
    ctrl_interface=/var/run/wpa_supplicant
        network={{
        ssid="{}"
        scan_ssid={}
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

def pcapExtraction(filename, ssid, output_file):
    import pyshark
    import binascii
    packets = pyshark.FileCapture(filename)
    certificate = []
    count = 1
    for pkt in packets:
        if(('EAP' in pkt)):
            if((int(pkt['EAP'].code) == 1) and (hasattr(pkt['EAP'], 'tls_handshake_certificate'))):
                print('[-]  certificate frame found!')
                hex_array = [pkt['EAP'].tls_handshake_certificate.raw_value[i:i+2] for i in range(0, len(pkt['EAP'].tls_handshake_certificate.raw_value), 2)]
                file = '{}-{}.pem'.format(ssid, pkt['WLAN'].ta)
                print('[-]  extracting certificate to file: {}'.format(file))
                with open(file, 'wb') as f:
                    for ha in hex_array:
                        f.write(
                            binascii.unhexlify(ha)
                        )
                    f.close()
                print('[-]  open file with the following command:\r\n[-]    openssl x509 -inform der -in {} -text'.format(file))
                count += 1
    return 0

def liveExtraction(interface, ssid, config, timeout):
    import subprocess, time, datetime, os, signal

    command = [
        'wpa_supplicant',
        '-i{}'.format(interface),
        '-c{}'.format(config)
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
        while(ps.poll() is None):
            time.sleep(0.1)
            now = datetime.datetime.now()
            if((now-start).seconds > timeout):
                os.kill(ps.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
    except Exception as e:
        print('[!] Error: {}'.format(e))
    return 0

if __name__ == '__main__':
    if(options['filename'] and options['interface'] is not None):
        print('[!] Select one source of extraction')

    if(options['filename'] is not None):
        print('[+] Searching for RADIUS public certificate in file: {}'.format(options['filename']))
        pcapExtraction(
            filename=options['filename'],
            ssid=options['ssid'],
            output_file=options['output_file']
        )
    if(options['bssid_file'] is not None):
        bssids = []
        with open(options['bssid_file'], 'r') as file:
            for line in file:
                bssids.append(line.strip('\n'))
        file.close()
        for bssid in bssids:
            if(options['interface'] is not None):
                if(options['ssid'] is None):
                    print('[!] You need to specify the target SSID!')
                    exit(0)
                print('[+] Creating wpa_supplicant.conf file')
                wpa_supplicant_with_bssid_conf.configure(
                    ssid=options['ssid'],
                    hidden=options['hidden'],
                    bssid=bssid,
                    identity=options['identity'],
                    password=options['password']
                )
                print('[+] Performing a live extraction attempt of SSID: {} / BSSID: {}'.format(options['ssid'], bssid))

                import threading
                from kamene.all import *
                thread = threading.Thread(target=liveExtraction, args=( options['interface'], options['ssid'], wpa_supplicant_conf_file, options['timeout'], ))
                thread.demon = True
                thread.start()
                print('[-]  Capturing wireless handshake')
                packets = sniff(iface=options['interface'], timeout=(options['timeout']+10))
                print('[-]  Writing captured wireless frames to file: {}'.format(options['pcap_outfile']))
                wrpcap(options['pcap_outfile'], packets)
                pcapExtraction(
                    filename=options['pcap_outfile'],
                    ssid=options['ssid'],
                    output_file=options['output_file']
                )
    else:
        if(options['interface'] is not None):
            if(options['ssid'] is None):
                print('[!] You need to specify the target SSID!')
                exit(0)
            print('[+] Creating wpa_supplicant.conf file')
            wpa_supplicant_without_bssid_conf.configure(
                ssid=options['ssid'],
                hidden=options['hidden'],
                identity=options['identity'],
                password=options['password']
            )
            print('[+] Performing a live extraction attempt of SSID: {}'.format(options['ssid']))
    
            import threading
            from kamene.all import *
            thread = threading.Thread(target=liveExtraction, args=( options['interface'], options['ssid'], wpa_supplicant_conf_file, options['timeout'], ))
            thread.demon = True
            thread.start()
            print('[-]  Capturing wireless handshake')
            packets = sniff(iface=options['interface'], timeout=(options['timeout']+10))
            print('[-]  Writing captured wireless frames to file: {}'.format(options['pcap_outfile']))
            wrpcap(options['pcap_outfile'], packets)
            pcapExtraction(
                filename=options['pcap_outfile'],
                ssid=options['ssid'],
                output_file=options['output_file']
            )
    exit(0)

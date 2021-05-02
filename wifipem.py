#!/usr/bin/python3

import argparse

## Settings
__version__ = '0.0'
radius_certificate_extract_location = 'radius.der'

parser = argparse.ArgumentParser(description='Automated tool for extract the public key presented by WPA2-Enterprise wireless networks')

parser.add_argument('--version', action='version', version=__version__)
parser.add_argument('-s', '--ssid', dest='ssid', help='select target SSID')
parser.add_argument('-o', '--output', dest='output_file', default=radius_certificate_extract_location, help='Specify the output file (Default: {})'.format(radius_certificate_extract_location))

sourceOptions = parser.add_argument_group(description='Specify target source for extraction')
sourceOptions.add_argument('-f', '--filename', dest='filename', help='extract .pem from a pcap')
sourceOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')

args, leftover = parser.parse_known_args()
options = args.__dict__

def pcapExtraction(filename, output_file):
    import pyshark
    import binascii
    packets = pyshark.FileCapture(filename)
    certificate = []
    for pkt in packets:
        if(hasattr(pkt['EAP'], 'tls_handshake_certificate')):
            print('[-]  certificate frame found!')
            hex_array = [pkt.eap.tls_handshake_certificate.raw_value[i:i+2] for i in range(0, len(pkt.eap.tls_handshake_certificate.raw_value), 2)]
            print('[-]  extracting certificate to file: {}'.format(output_file))
            with open(output_file, 'wb') as f:
                for ha in hex_array:
                    f.write(
                        binascii.unhexlify(ha)
                    )
                f.close()
    return 0

def liveExtraction(interface, ssid, output_file):
    return 0

if __name__ == '__main__':
    if(options['filename'] and options['interface'] is not None):
        print('[!] Select one source of extraction')

    if(options['filename'] is not None):
        print('[+] Searching for RADIUS public certificate in file: {}'.format(options['filename']))
        pcapExtraction(
            filename=options['filename'],
            output_file=options['output_file']
        )
    if(options['interface'] is not None):
        print('[+] Performing a live extraction attempt of SSID: {}'.format(options['ssid']))
        liveExtraction(
            interface=options['interface'],
            ssid=options['ssid'],
            output_file=options['output_file']
        )
    exit(0)

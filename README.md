# wifipem
wifipem is an automated tool for extracting RADIUS public certificates from pcap files and live captures.

## Usage
wifipem.py is capable of parsing Dot11 pcap captures which include RadioTap abstraction layer or captures without the layer, in addition the ability to conduct a live capture via an EAP-PEAP authentication attempt.

### Examples

#### Extracting RADIUS public certificates from pcaps

```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wifipem]
└─$ ls -lh                                         
total 100K
-rw-r--r-- 1 vagrant vagrant  166 May  2 10:27 README.md
-rw-r--r-- 1 vagrant vagrant   92 May  2 22:45 settings.py
-rw-r--r-- 1 vagrant vagrant 2.1K May  2 22:45 wifipem.py
                                                                                                                                                                                                                                             
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wifipem]
└─$ python3 wifipem.py -f wifipem_certificate_capture.pcap
[+] Searching for RADIUS public certificate in file: wifipem_certificate_capture.pcap
[-]  certificate frame found!
[-]  extracting certificate to file: radius.der.1
[-]  open file with the following command:
[-]    openssl x509 -inform der -in radius.der.1 -text
                                                                                                                    
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wifipem]
└─$ openssl x509 -inform der -in radius.der.1 -text       
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = AU, ST = NSW, L = Sydney, O = rogue, emailAddress = rogue@rogue.rogue, CN = rogue
        Validity
            Not Before: Apr  4 02:48:52 2021 GMT
            Not After : Apr  4 02:48:52 2022 GMT
        Subject: C = AU, ST = NSW, O = rogue, CN = rogue, emailAddress = rogue@rogue.rogue
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:e6:ec:54:12:25:fa:9e:37:9b:26:c8:29:c3:14:
                    e7:ff:14:4f:28:ca:94:6e:09:65:33:12:3a:7e:23:
                    43:24:e0:42:2e:c9:c7:bd:a4:7f:bd:21:f9:05:ce:
                    f4:1b:92:41:e7:b2:a4:62:1b:00:1e:77:4f:8d:bf:
                    64:b5:f3:b6:42:49:4b:17:d4:12:29:09:d5:3c:55:
                    d9:50:40:6c:f6:ea:92:87:26:39:88:91:e2:09:21:
                    53:45:c7:0b:41:c6:d6:ae:f9:44:31:33:bf:01:fa:
                    6f:a4:40:5f:7f:bd:47:0d:5e:78:ba:6e:4e:6d:4c:
                    cf:dd:3f:94:4f:64:db:c9:b8:d3:c0:29:69:1c:b3:
                    d1:8b:32:02:a9:ce:a2:3b:c2:52:fd:f7:c8:68:53:
                    e0:bc:44:c8:14:f7:a3:42:a5:b1:0a:65:ac:11:21:
                    ea:91:b9:db:9e:ff:2e:5d:af:0d:e9:83:ee:62:5f:
                    94:e0:79:60:9a:d9:ae:eb:82:32:35:2f:1a:4e:91:
                    a5:5e:22:b8:f2:fa:02:82:9e:18:28:24:a2:24:90:
                    0d:3e:1b:73:2e:2a:49:9b:04:d7:9e:3c:76:d1:97:
                    b3:d5:9e:75:db:58:bc:eb:a3:f8:6d:ae:bc:bc:69:
                    2b:20:96:cd:71:19:8a:4a:f4:7f:41:61:97:c4:d1:
                    6c:89
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
    Signature Algorithm: sha256WithRSAEncryption
         53:1a:30:ae:08:0e:77:d8:f4:a7:ee:ed:ea:73:6e:a9:ad:9f:
         5d:51:27:80:3e:f9:da:13:23:d4:c2:9d:2c:13:7c:fe:49:8c:
         a7:7a:74:e3:f6:09:0e:40:da:e6:74:60:3f:d7:96:9d:01:41:
         4a:d7:69:e9:59:1d:a5:ad:7c:d5:af:88:b1:01:55:e9:7f:46:
         5b:b4:13:e1:e3:6b:fb:04:7e:7c:f2:fb:93:43:b5:9e:fd:c2:
         dd:a9:ff:1d:b9:b1:38:c0:0f:19:63:a3:53:d5:fa:f6:f7:36:
         b4:1e:02:d2:ed:99:00:04:e3:16:25:bf:44:9b:65:02:33:34:
         11:00:15:9e:97:57:11:ea:c4:c0:da:84:01:8e:cf:6a:0f:43:
         ec:ca:e5:23:e6:7f:5b:24:10:2e:52:02:dc:9a:a5:d7:16:48:
         b0:0c:b8:86:dd:61:2b:0e:56:9e:24:ec:c8:7b:d7:19:db:d5:
         51:fa:cc:67:59:12:11:69:47:c0:96:48:f7:74:24:1a:e3:d2:
         00:39:c3:cd:00:f9:ee:0c:3a:15:3e:e4:64:42:32:25:e2:1a:
         75:11:3e:d1:56:7f:c6:0f:a1:fc:d7:26:52:37:7d:08:41:5e:
         a4:ef:1a:ab:20:95:da:2f:81:da:5e:e3:8f:43:c8:7f:80:74:
         c9:33:e5:72
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIBATANBgkqhkiG9w0BAQsFADBuMQswCQYDVQQGEwJBVTEM
MAoGA1UECAwDTlNXMQ8wDQYDVQQHDAZTeWRuZXkxDjAMBgNVBAoMBXJvZ3VlMSAw
HgYJKoZIhvcNAQkBFhFyb2d1ZUByb2d1ZS5yb2d1ZTEOMAwGA1UEAwwFcm9ndWUw
HhcNMjEwNDA0MDI0ODUyWhcNMjIwNDA0MDI0ODUyWjBdMQswCQYDVQQGEwJBVTEM
MAoGA1UECAwDTlNXMQ4wDAYDVQQKDAVyb2d1ZTEOMAwGA1UEAwwFcm9ndWUxIDAe
BgkqhkiG9w0BCQEWEXJvZ3VlQHJvZ3VlLnJvZ3VlMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA5uxUEiX6njebJsgpwxTn/xRPKMqUbgllMxI6fiNDJOBC
LsnHvaR/vSH5Bc70G5JB57KkYhsAHndPjb9ktfO2QklLF9QSKQnVPFXZUEBs9uqS
hyY5iJHiCSFTRccLQcbWrvlEMTO/AfpvpEBff71HDV54um5ObUzP3T+UT2TbybjT
wClpHLPRizICqc6iO8JS/ffIaFPgvETIFPejQqWxCmWsESHqkbnbnv8uXa8N6YPu
Yl+U4Hlgmtmu64IyNS8aTpGlXiK48voCgp4YKCSiJJANPhtzLipJmwTXnjx20Zez
1Z5121i866P4ba68vGkrIJbNcRmKSvR/QWGXxNFsiQIDAQABoxcwFTATBgNVHSUE
DDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAUxowrggOd9j0p+7t6nNu
qa2fXVEngD752hMj1MKdLBN8/kmMp3p04/YJDkDa5nRgP9eWnQFBStdp6Vkdpa18
1a+IsQFV6X9GW7QT4eNr+wR+fPL7k0O1nv3C3an/HbmxOMAPGWOjU9X69vc2tB4C
0u2ZAATjFiW/RJtlAjM0EQAVnpdXEerEwNqEAY7Pag9D7MrlI+Z/WyQQLlIC3Jql
1xZIsAy4ht1hKw5WniTsyHvXGdvVUfrMZ1kSEWlHwJZI93QkGuPSADnDzQD57gw6
FT7kZEIyJeIadRE+0VZ/xg+h/NcmUjd9CEFepO8aqyCV2i+B2l7jj0PIf4B0yTPl
cg==
-----END CERTIFICATE-----

┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wifipem]
└─$
```

#### Extracting RADIUS public certificates from pcaps
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wifipem]
└─$ sudo python3 wifipem.py -s rogue -i wlan1                                         
[+] Creating wpa_supplicant.conf file
[+] Performing a live extraction attempt of SSID: rogue
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
WARNING: can't import layer ipsec: cannot import name 'gcd' from 'fractions' (/usr/lib/python3.9/fractions.py)
[-]  Connecting to wireless network "rogue" using wpa_supplicant.conf file: wpa_supplicant.conf
[-]  Capturing wireless handshake
[-]  Writing captured wireless frames to file: wifipem_certificate_capture.pcap
[-]  certificate frame found!
[-]  extracting certificate to file: radius.der.1
[-]  open file with the following command:
[-]    openssl x509 -inform der -in radius.der.1 -text
                                                                                                                                                                                                                                             
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wifipem]
└─$
```

## Dependencies
1. `pyshark`
2. `tshark`

### Install
#### pyshark
`python3 -m pip install pyshark`

#### tshark
```
sudo apt update
sudo apt install tshark
```

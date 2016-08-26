import pytest
from dane_checker import *

def test_get_certificate_chain():
    nist_www = get_service_certificate_chain("132.163.4.162","www.nist.gov",443,'https')
    www_certs = split_certs(nist_www[0].data)
    assert len(www_certs)>0

def test_smtp_works():
    sys4_smtp = get_service_certificate_chain("sys4.de","mail.sys4.de",25,'smtp')
    print(sys4_smtp)

    
def test_get_tlsa():
    n = get_dns_tlsa("www.had-pilot.com",443)
    assert tlsa_str(n[0].rdata).upper() == "1 0 1 E5024FB9FBF366850138836E22EAD22728F2E7950ACFE75971D0099571C5E4D0"

def test_get_dns_ip():
    n = get_dns_ip("www.had-pilot.com.")
    assert n[0].data=="129.6.100.200"

def test_cname():
    n = get_dns_cname("a.nitroba.org.")
    assert n[0].data=="b.nitroba.org."

def test_mx():
    n = get_dns_mx("nist.gov")
    assert n[0].data=="nist-gov.mail.protection.outlook.com."


#
# Test the Google Certificates
#
google_chain="""
CONNECTED(00000003)
---
Certificate chain
 0 s:/C=US/ST=California/L=Mountain View/O=Google Inc/CN=www.google.com
   i:/C=US/O=Google Inc/CN=Google Internet Authority G2
-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIID9m4lZvTOKQwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTUwNjAzMTA0MzA0WhcNMTUwOTAxMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQ3kVa
YKv6b+2eExHAQqsmNtZ/y/7WsUYgfBEgFSS4BTEm1Y4WEodlMX1syW8P9WgaYWqt
LiRMw2aVDfnX2sjw0Hft8sJfzC9A88sbofRuqpevgpRJrzyJxYQJF+seZQ+pczN7
2+MTJrDpyFWpqkPKD94UoKwHMPaEpGbc0JN2mAvIZg7Q0T7hsL46dO2WUKRRE6jy
fqisEVFvCi8GKNkVfn+8fB9iYr0JUBSS1Zzj20yI9IF//SbQjiwfJVEOZDC8e0ux
V6Iav3+fp27i7ivYwAQ9U6Ojf0cRnJSCP6wLU/UR57cJg6UX+SidA1ND5TUEaSWK
XOKdVqtn/o31ozwVAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBRP8cWn5oxqVL+IgpkPR48C9AcvtTAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQBcjxltuc2eSiSIwMA5yVjWB1gj3i3w
wBP4oDgGj+lFVVve1fk3BDqws/PzIjswJHtII7uPyAgOrhE8LoXT1BT4RkNbsfxB
VLDWovwt7RoJADbTvmo5IhT7BJx4hxLFRJMyuPKYUYpekjwZ+LyxidJabNnT3eA+
rv5en5eBTS0/oCD4tyrkYtJnu+LfQY0HuIOISbtCGLMqAufvZHnfB4E8+6DCDdzc
KRHKyzHpY2TYLWP+WSGWrBwsZcJYUzlhWxAEwiTMWKdCFeoLtluPQZuLHBBCc+IM
fwpahGRLxGROlxvV+FUbbIJgO6ALMMN50Ky4bR88uZWjRjKETPfPALmP
-----END CERTIFICATE-----
 1 s:/C=US/O=Google Inc/CN=Google Internet Authority G2
   i:/C=US/O=GeoTrust Inc./CN=GeoTrust Global CA
-----BEGIN CERTIFICATE-----
MIID8DCCAtigAwIBAgIDAjp2MA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwNQYDVR0fBC4wLDAqoCig
JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMC4GCCsGAQUF
BwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL2cuc3ltY2QuY29tMBcGA1UdIAQQ
MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQUFAAOCAQEAJ4zP6cc7vsBv6JaE
+5xcXZDkd9uLMmCbZdiFJrW6nx7eZE4fxsggWwmfq6ngCTRFomUlNz1/Wm8gzPn6
8R2PEAwCOsTJAXaWvpv5Fdg50cUDR3a4iowx1mDV5I/b+jzG1Zgo+ByPF5E0y8tS
etH7OiDk4Yax2BgPvtaHZI3FCiVCUe+yOLjgHdDh/Ob0r0a678C/xbQF9ZR1DP6i
vgK66oZb+TWzZvXFjYWhGiN3GhkXVBNgnwvhtJwoKvmuAjRtJZOcgqgXe/GFsNMP
WOH7sf6coaPo/ck/9Ndx3L2MpBngISMjVROPpBYCCX65r+7bU2S9cS+5Oc4wt7S8
VOBHBw==
-----END CERTIFICATE-----
 2 s:/C=US/O=GeoTrust Inc./CN=GeoTrust Global CA
   i:/C=US/O=Equifax/OU=Equifax Secure Certificate Authority
-----BEGIN CERTIFICATE-----
MIIDfTCCAuagAwIBAgIDErvmMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVT
MRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0
aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDIwNTIxMDQwMDAwWhcNMTgwODIxMDQwMDAw
WjBCMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UE
AxMSR2VvVHJ1c3QgR2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA2swYYzD99BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9m
OSm9BXiLnTjoBbdqfnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIu
T8rxh0PBFpVXLVDviS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6c
JmTM386DGXHKTubU1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmR
Cw7+OC7RHQWa9k0+bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5asz
PeE4uwc2hGKceeoWMPRfwCvocWvk+QIDAQABo4HwMIHtMB8GA1UdIwQYMBaAFEjm
aPkr0rKV10fYIyAQTzOYkJ/UMB0GA1UdDgQWBBTAephojYn7qwVkDBF9qn1luMrM
TjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjA6BgNVHR8EMzAxMC+g
LaArhilodHRwOi8vY3JsLmdlb3RydXN0LmNvbS9jcmxzL3NlY3VyZWNhLmNybDBO
BgNVHSAERzBFMEMGBFUdIAAwOzA5BggrBgEFBQcCARYtaHR0cHM6Ly93d3cuZ2Vv
dHJ1c3QuY29tL3Jlc291cmNlcy9yZXBvc2l0b3J5MA0GCSqGSIb3DQEBBQUAA4GB
AHbhEm5OSxYShjAGsoEIz/AIx8dxfmbuwu3UOx//8PDITtZDOLC5MH0Y0FWDomrL
NhGc6Ehmo21/uBPUR/6LWlxz/K7ZGzIZOKuXNBSqltLroxwUCEm2u+WR74M26x1W
b8ravHNjkOR/ez4iyz0H7V84dJzjA1BOoa+Y7mHyhD8S
-----END CERTIFICATE-----
---
Server certificate
subject=/C=US/ST=California/L=Mountain View/O=Google Inc/CN=www.google.com
issuer=/C=US/O=Google Inc/CN=Google Internet Authority G2
---
No client certificate CA names sent
Server Temp Key: ECDH, prime256v1, 256 bits
---
SSL handshake has read 3719 bytes and written 373 bytes
---
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Session-ID: 4BE135308BE7BA75A0E5F3C58C3CEDCC4DEDD4CC39C3AE474C4735B2B0B22151
    Session-ID-ctx: 
    Master-Key: 79457D1F1ED4C68BA57E8627FDEAF6A026133AB3811A1FAEEB160C49289146C4CB35945CDD7F530A80258D3822F54EFC
    Key-Arg   : None
    Krb5 Principal: None
    PSK identity: None
    PSK identity hint: None
    TLS session ticket lifetime hint: 100800 (seconds)
    TLS session ticket:
    0000 - 67 52 e0 88 b6 49 c4 f7-7d f4 03 a6 59 f2 20 29   gR...I..}...Y. )
    0010 - 11 1d 0c bf 2f e8 ba fb-2b 6e 50 ea 79 9b 78 60   ..../...+nP.y.x`
    0020 - 99 6e c4 67 d3 e6 95 08-ee d8 f9 4b 72 bd d3 6a   .n.g.......Kr..j
    0030 - 43 e3 36 8b 33 55 74 ce-0a 63 7b 58 3e cb aa cd   C.6.3Ut..c{X>...
    0040 - ae fd e5 30 bb ad f2 01-7f 81 df 92 8e 19 eb b8   ...0............
    0050 - 08 ed 1a 09 60 37 c5 44-d5 c7 17 76 ad 11 c2 1f   ....`7.D...v....
    0060 - 63 1d a5 f4 57 09 8b e1-a4 ec 89 7e b5 07 98 b6   c...W......~....
    0070 - 59 d0 0a 28 b4 af 51 a5-2e c2 da ee 7f 39 f0 86   Y..(..Q......9..
    0080 - cb a2 b8 4d cd 0d 40 28-5b ea be f3 ba 38 e9 45   ...M..@([....8.E
    0090 - 66 9a 93 ee 3e 4f 81 e6-1e 95 ce 23 c7 5b bd aa   f...>O.....#.[..
    00a0 - 92 ad a6 af                                       ....

    Start Time: 1433963046
    Timeout   : 300 (sec)
    Verify return code: 20 (unable to get local issuer certificate)
---
"""

google_cert="""
-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIB1Qnfj/zM4IwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTUwNjAzMDkyNjAxWhcNMTUwOTAxMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChruJu
4vl1I+x9Ypzejv0NsDYfAChaaOH4jjjv33IhuYkJsh8yyjCKBj6I2z2eCBwctzoT
Wcv73rUwGI+nyevtksAWemIbWssurCfwg9su/8TIg4i61T7R7RefnrVzbNcTiVsD
73wcItdJdJHSef9rjmISeEUOVl8Bf0jJ9FcJ7fOAvZ1FI5QBCKZqaThqw/Yueseh
ZJVjK//XYZJXNJzx3u+Esjctqk/+qyOiPkAWdpr/hkIfO6+94lfWqNTu1tnscPXt
hUtFJI0g5O3IY3iQKZArfP9Z4CnJewBR4YZWh5ON5Kl8f3qz/MZkluxcpPXNi81C
5VIGfIQX24iiISihAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBQbxIwppiAAgZarS9XPgPHhburQJDAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQBcNNydftmGqg/r2wtLrvGJMG9fkLAT
Fl0SaUFAPzdbUrOF+TEmub8TA8RJVcZC7qrpyHOIbi92Fku1IFTzbMoWicxTxriY
JRyz7genbKaNjUY/2eiGS41zuVB+LDNg5k9UBKrPtJtI8g3myg/aq6N+e348RAfD
wrpt/cYJw1oli1Qr93Wdqnb7sG8jk1f2W8TFK/0D2/5mQsr8SExDR9vLehC6kf4u
TleWRVLvKFFcCPd/mhnlD7zTl6p77q/+7kpOJiEYigBiv0Yax769MG6r6YuEPjlB
GEOKUhNxGbmLSVRrmfedg3RpYQFoZmN2ML8YANX3JWwE7lDpWSCRVo0z
-----END CERTIFICATE-----
"""


def test_pem_verify():
    certs = split_certs(google_chain)
    assert pem_verify(certs[-1],google_chain,google_cert)==True

def test_good_dane_verisignlabs_com():
    ret = tlsa_https_verify("good.dane.verisignlabs.com")
    assert ret.passed == True

def test_bad_sig_dane_verisignlabs_com():
    ret = tlsa_https_verify("bad-sig.dane.verisignlabs.com")
    assert ret.passed == False


if __name__=="__main__":
    test_smtp_works()


import pytest
from dane_checker import *

def test_get_certificate_chain():
    nist_www = get_service_certificate_chain("132.163.4.162","www.nist.gov",443,'https')
    assert len(nist_www)==3

    nist_smtp = get_service_certificate_chain("207.46.163.138","nist-gov.mail.protection.outlook.com",25,'smtp')
    assert len(nist_smtp)==3
    assert "CN=mail.protection.outlook.com" in nist_smtp[0]

    
def test_get_tlsa():
    n = get_tlsa("www.had-pilot.com",443)
    assert tlsa_str(n[0].data) == "1 0 1 E5024FB9FBF366850138836E22EAD22728F2E7950ACFE75971D0099571C5E4D0"

def test_get_dns_ip():
    n = get_dns_ip("www.had-pilot.com.")
    assert n[0].data=="129.6.100.200"

def test_cname():
    n = get_dns_cname("a.nitroba.org.")
    assert n[0].data=="b.nitroba.org."


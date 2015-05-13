import pytest
import dns


def test_mx():
    assert dns.query('nist.gov','mx').mx()==['0 nist-gov.mail.protection.outlook.com.']

def test_addr():
    assert dns.query('www.had-pilot.com').addr()==['129.6.100.200']

def test_addr6():    
    assert dns.query('www.had-pilot.com').addr6()==['2610:20:6005:100::200']

def test_dnssec():
    assert dns.query('www.dnssec-failed.org').dnssec == 'bogus'



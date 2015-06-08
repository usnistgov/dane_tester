import pytest
import getdns


def test_addr():
    ctx = getdns.Context()
    r = ctx.address(name='www.had-pilot.com')
    assert results.status == getdns.getdns.RESPSTATUS_GOOD
    count = 0
    for addr in results.just_address_answers:
        if addr['address_type']=='IPv4':
            assert addr['address_data']=='129.6.100.200'
            count += 1
    assert count==1

def test_addr6():
    ctx = getdns.Context()
    r = ctx.address(name='www.had-pilot.com')
    assert results.status == getdns.getdns.RESPSTATUS_GOOD
    count = 0
    for addr in results.just_address_answers:
        if addr['address_type']=='IPv6':
            assert addr['address_data']=='2610:20:6005:100::200'
            count += 1
    assert count==1


def test_mx():
    assert dns.query('nist.gov','mx').mx()==['0 nist-gov.mail.protection.outlook.com.']

def test_addr6():    
    assert dns.query('www.had-pilot.com').addr6()==['2610:20:6005:100::200']

def test_dnssec():
    ctx = getdns.Context()
    extensions = { 'dnssec_return_status' : getdns.EXTENSION_TRUE }
    r = ctx.address(name='www.dnssec-failed.org',extensions=extensions)
    #print("r=",r)
    print(r.just_address_answers)
    print(r.replies_full['status'])
    print(len(r.replies_tree))
    print(r.replies_tree[0]['dnssec_status'])
    #assert dns.query('www.dnssec-failed.org').dnssec == 'bogus'

if __name__=="__main__":
    test_dnssec()




import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

import sys

# get nameservers for target domain
nsaddr='8.8.8.8'

for hostname in ['nist.gov','mit.edu','simson.net','google.com','dane-test.had.dnsops.gov',
                 'dhs.gov','www.dhs.gov', 'dualstack.mc-12555-1019789594.us-east-1.elb.amazonaws.com']:
    print("========================= {} ===================".format(hostname))
    print("===A test===")
    request = dns.message.make_query(hostname, dns.rdatatype.A, want_dnssec=True)
    response = dns.query.udp(request,nsaddr)
    print("From wire:")
    print("{} response AD flag:{}".format(hostname,response.flags & dns.flags.AD))
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.A:
                print(rr.address)

    response = dns.message.from_text(response.to_text())
    print("From text:")
    print("{} response AD flag:{}".format(hostname,response.flags & dns.flags.AD))
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.A:
                print(rr.address)



    print("===MX test===")
    request = dns.message.make_query(hostname, dns.rdatatype.MX, want_dnssec=True)
    response = dns.query.udp(request,nsaddr)
    print("From wire:")
    print("{} MX response AD flag:{}".format(hostname,response.flags & dns.flags.AD))
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.MX:
                print(rr.preference,rr.exchange)
    
    response = dns.message.from_text(response.to_text())
    print("From text record:")
    print("{} MX response AD flag:{}".format(hostname,response.flags & dns.flags.AD))
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.MX:
                print(rr.preference,rr.exchange)
    

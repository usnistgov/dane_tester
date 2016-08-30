import pytest
import getdns
import sys

CNAME_MAX = 20

def v(bin_addr):
    return '.'.join(map(str, map(ord, bin_addr)))

extensions = {"return_both_v4_and_v6":getdns.EXTENSION_TRUE,
                       "dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}


dnssec_status = {getdns.DNSSEC_SECURE:"SECURE",
                 getdns.DNSSEC_INDETERMINATE:"INDETERMINATE",
                 getdns.DNSSEC_INSECURE:"INSECURE",
                 getdns.DNSSEC_BOGUS:"BOGUS",
                 None:"NONE"}


def walk_host(host):
    try:
        results = ctx.address(name=host, extensions=extensions)
    except getdns.error as e:
        print(str(e))
        sys.exit(1)

    if results.status == getdns.RESPSTATUS_GOOD:
        #for r in results.replies_tree:
        #    print(r)
        #print(results.just_address_answers)
        for reply in results.replies_tree:
            for a in reply['answer']:
                if a['type']==getdns.RRTYPE_A:
                    ty = a['type']
                    ipv4 = v(a['rdata']['ipv4_address'])
                    dstat = dnssec_status[reply.get('dnssec_status',None)]
                    print("  type={} data={} dnssec_status={}".format(ty,ipv4,dstat))
                if a['type']==getdns.RRTYPE_AAAA:
                    ty = a['type']
                    ipv6 = v(a['rdata']['ipv6_address'])
                    dstat = dnssec_status[reply.get('dnssec_status',None)]
                    print("  type={} v6data={} dnssec_status={}".format(ty,ipv6,dstat))
    

def walk_host_cname(host):
    cname_count = 0
    while cname_count < CNAME_MAX:
        try:
            results = ctx.general(name=host, request_type=getdns.RRTYPE_CNAME, extensions=extensions)
        except getdns.error, e:
            print(str(e))
            sys.exit(1)
        found_cname = False
        if results.status == getdns.RESPSTATUS_GOOD:
            for reply in results.replies_tree:
                answers = reply['answer']
                for answer in answers:
                    if answer['type'] == getdns.RRTYPE_CNAME:
                        dstat = dnssec_status[reply.get('dnssec_status',None)]
                        print("CNAME {} -> {}  {}".format(host,answer['rdata']['cname'],dstat))
                        host = answer['rdata']['cname']
                        cname_count += 1
                        found_cname = True
                        break
        if not found_cname:
            return walk_host(host)
    print("CNAME DEPTH REACHED")
    return None
            
def get_tlsa(host,port):
    try:
        rhost = "_{}._tcp.{}".format(port,host)
        results = ctx.general(name=rhost,
                              request_type = getdns.RRTYPE_TLSA,
                              extensions=extensions)
    except getdns.error, e:
        print(str(e))
        sys.exit(1)
    
    def tohex(rdata):
        def hexnum(v): return "%02X" % ord(v)
        return ''.join(map(hexnum, rdata))

    if results.status == getdns.RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            answers = reply['answer']
            for answer in answers:
                if answer['type'] == getdns.RRTYPE_TLSA:
                    dstat = dnssec_status[reply.get('dnssec_status',None)]
                    rdata = answer['rdata']
                    print("{} TLSA usage:{}  selector:{} matching_type:{}  data:{} DNSSEC:{}".format(
                            rhost,
                            rdata['certificate_usage'],
                            rdata['selector'],
                            rdata['matching_type'],
                            tohex(rdata['certificate_association_data']),
                            dstat))
                    print(rdata.selector)
                    break
    



if __name__=="__main__":
    host = sys.argv[1]
    ctx = getdns.Context()

    get_tlsa("good.dane.verisignlabs.com",443)

    try:
        results = ctx.general(name=host, request_type=getdns.RRTYPE_MX, extensions=extensions)
    except getdns.error, e:
        print(str(e))
        sys.exit(1)
    status = results.status
    count = 0
    if status == getdns.RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            answers = reply['answer']
            for answer in answers:
                if answer['type'] == getdns.RRTYPE_MX:
                    dstat = dnssec_status[reply.get('dnssec_status',None)]
                    print("MX Preference: {}  {}".format(answer['rdata']['preference'],dstat))
                    walk_host_cname(answer['rdata']['exchange'])
                    count += 1
    elif status == getdns.RESPSTATUS_NO_NAME:
        print "%s, %s: no such name" % (host, qtype)
    elif status == getdns.RESPSTATUS_ALL_TIMEOUT:
        print "%s, %s: query timed out" % (host, qtype)
    else:
        print "%s, %s: unknown return code: %d" % results["status"]
        

    if count==0:
        # Search on the host without MX
        walk_host_cname(host)

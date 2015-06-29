import getdns
extensions = {"dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}
dnssec_status = {getdns.DNSSEC_SECURE:"SECURE",
                 getdns.DNSSEC_INDETERMINATE:"INDETERMINATE",
                 getdns.DNSSEC_INSECURE:"INSECURE",
                 getdns.DNSSEC_BOGUS:"BOGUS",
                 None:""}

#extensions = {}
if __name__=="__main__":
    ctx = getdns.Context()
    hostname ="dougbarton.us"
    request_type = getdns.RRTYPE_MX
    results = ctx.general(name=hostname,request_type=request_type,extensions=extensions)
    for reply in results.replies_tree:
        print("dnssec_status:",dnssec_status[reply.get("dnssec_status")])
        for a in reply['answer']:
            if a['type'] == request_type:
                print a
    print "====================="



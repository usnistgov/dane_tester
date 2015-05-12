# Module for dig parsing

from subprocess import PIPE,Popen

SERVFAIL="SERVFAIL"
FAILED="FAILED"
ANSWER="ANSWER"
CNAME="CNAME"
A="A"
MX="MX"
CNAME_MAX_DEPTH=20
TLSA="TLSA"
from collections import namedtuple

import re

rr_re = re.compile("(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)")

RR = namedtuple('RR',['owner','ttl','addr_class','type','data'])
def RRMake(s):
    vals = rr_re.search(s)
    return RR(vals.group(1),vals.group(2),vals.group(3),vals.group(4),vals.group(5))

class DigQueryResult:
    def __init__(self,host,cdflag=False):
        self.flags = set()
        self.answers= []
        self.rrs    = []
        self.host   = host
        self.cdflag = cdflag
    def __repr__(self):
        return "flags: {}  answer: {}".format(self.flags,self.answer)
    def compute_rrs(self):
        self.rrs    = [RRMake(x) for x in self.answers]
        self.rrs    = list(filter(lambda r:r.owner == self.host,self.rrs))
    def get_rrs(self,qtype):
        return filter(lambda a:a.type==qtype,self.rrs)
    def cname(self):
        try:
            return list(self.get_rrs(CNAME))[0].data
        except IndexError:
            return None
    def addr(self):
        return [rr.data for rr in self.get_rrs(A)]
    def mx(self):
        return [rr.data for rr in self.get_rrs(MX)]
    def tlsa(self):
        return [rr.data for rr in self.get_rrs(TLSA)]
        
        

status_re  = re.compile(";; ...HEADER....*status: ([A-Z]+)")
section_re = re.compile(";; ([A-Z]+) SECTION:")
flags_re   = re.compile(";; flags: ([a-z ]+);")

def dig(host,qtype=None,cdflag=False):
    if not host.endswith("."):
        host+="."
    ret = DigQueryResult(host,cdflag=cdflag)

    cmd = ['dig','+dnssec','@8.8.8.8',host]
    if qtype: cmd.append(qtype)
    if cdflag: cmd.append("+cdflag")
    res = Popen(cmd,stdout=PIPE).communicate()[0].decode('utf-8')
    section = None
    for line in res.split("\n"):
        if not line: continue
        m = status_re.search(line)
        if m:
            ret.status = m.group(1)
            continue
        m = section_re.search(line)
        if m:
            section = m.group(1)
            continue
        m=flags_re.search(line)
        if m:
            ret.flags = m.group(1).split(" ")
            continue
        if line[0]==';':
            section = None
            continue
        if section==ANSWER:
            if not line[0].isspace():
                ret.answers.append(line.strip()) # new line
            else:
                ret.answers[-1] += line.strip() # continuation line
    ret.compute_rrs()
    return ret

def query(host,qtype=None):
    originalHost = host
    cname_count = 0;
    while cname_count < CNAME_MAX_DEPTH:
        ret = dig(host,qtype=qtype)
        ret.dnssec = "ad" in ret.flags
        if ret.status==SERVFAIL:
            ret = dig(host,qtype=qtype,cdflag=True)
            ret.dnssec = 'bogus'
        if ret.cname():
            host = ret.cname()
            continue
        ret.originalHost = originalHost
        return ret
            
if __name__=="__main__":
    hosts = [ "www.had-pilot.com",
              "www.mit.edu",
              "mit.edu",
             "www.cnn.com",
             "_443._tcp.102host.dns.good.test.had-pilot.biz",
             "www.dnssec-failed.org"]
    for h in hosts:
        r = query(h)
        mx = query(h,MX)
        v = query(h,TLSA)
        print("{}:  host:{} originalHost:{} addr:{} mx:{}  dnssec:{}  tlsa:{}\n".format(
                h,r.host,r.originalHost,r.addr(),mx.mx(),r.dnssec,v.tlsa()))
    

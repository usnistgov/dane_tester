#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
import cgitb;cgitb.enable()
from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi
import sys

assert sys.version > '3'

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

#
# Create a GPG public key record
# See https://tools.ietf.org/html/rfc7929

gpg_exe = '/usr/bin/gpg'

def hexdump(s, separator=''):
    if type(s)==str:
        return separator.join("{:02X}".format(ord(x)) for x in s)
    if type(s)==bytes:
        return separator.join("{:02X}".format(x) for x in s)
    if type(s)==memoryview:
        return separator.join("{:02X}".format(x) for x in bytes(s))
    raise RuntimeError("Unknown type for hexdump: {}".format(type(s)))

def gen_pgp_key(email,pgpKey):
   from subprocess import Popen,PIPE,STDOUT
   import re,base64,hashlib
   #
   # Import the key
   #
   (stdout,stderr) = Popen([gpg_exe, '--import'],stdin=PIPE,stdout=PIPE,stderr=PIPE).communicate(pgpKey.encode('utf-8'))
   keyfind = re.compile("key ([0-9A-F]{8})")
   stderr_out = stderr.decode('utf-8')
   m = keyfind.search(stderr.decode('utf-8'))
   if not m:
      return "Error: Key Format Invalid"
   if email not in stderr_out:
      return "Error: Key '{}' not in public key".format(email)

   #
   # Export the key according to the spec
   # See https://tools.ietf.org/html/rfc7929
   #
   (stdout,stderr) = Popen([gpg_exe, '--export','--export-options','export-minimal,no-export-attributes',email],
                           stdin=PIPE,stdout=PIPE,stderr=PIPE).communicate()
   keyblob_base64 = base64.b64encode(stdout)
   if stderr:
      return "Error: Export failed"

   (emailpart,domainpart) = email.split('@')
   hasher = hashlib.sha256()
   hasher.update(emailpart.encode('ascii'))
   hexpart = hasher.hexdigest()[0:28]
   return "{}._openpgpkey.{}. IN OPENPGPKEY {}\n".format(hexpart,domainpart,keyblob_base64.decode('ascii')) + \
      "{}._openpgpkey.{}. IN TYPE61 \# {} {}".format(hexpart,domainpart,len(keyblob_base64),hexdump(keyblob_base64))
   

if __name__=="__main__":
   import os

   if "SCRIPT_FILENAME" not in os.environ:
      print("*** LOCAL TESTING MODE ***")
      print("Enter email:"); sys.stdout.flush()
      email = sys.stdin.readline()
      print("Enter PGP key:"); sys.stdout.flush()
      pgpKey = ""
      while True:
         line = sys.stdin.readline()
         if not line: break
         pgpKey += line
      email = email.strip()
      pgpKey = pgpKey.strip() + "\n"
      print(gen_pgp_key(email,pgpKey))
      exit(0)

   import cgitb; cgitb.enable()
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   form = cgi.FieldStorage()

   if 'email' not in form:
      print("Please provide an email address")
      exit(0)

   if 'pgpKey' not in form:
      print("Please provide a Pgp Public Key address")
      exit(0)

   T = Tester()
   args = {}
   email = form['email'].value.strip()
   pgpKey  = form['pgpKey'].value.strip() + "\n"

   #print("<pre>\n",pgpKey,"\n</pre>\n");exit(0);

   res = gen_pgp_key(email,pgpKey)
   
   if not res.startswith("Error"):
      print("<p><i>Add one of these records to your DNS:</i></p>")
   for line in res.split("\n"):
      print("<pre>\n{}\n</pre>\n".format(line))
   exit(0)



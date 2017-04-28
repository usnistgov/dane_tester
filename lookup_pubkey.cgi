#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
# lookup_pubkey.cgi:
# Return the public keys used by this system
#
import cgitb;cgitb.enable()
#from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi
import sys

ANONYMOUS_USER="anonymous"
ANONYMOUS_HASH="iuabfuXHVpg="

assert sys.version > '3'

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

from subprocess import call,Popen,PIPE
import smimea
import openpgpkey

#catch HTML escape chars to prevent XSS attacks
html_escape_table = {
   "&": "&amp;",
   '"': "&quot;",
   "'": "&apos;",
   ">": "&gt;",
   "<": "&lt;",
   }
   
def def html_escape(text):
   """Produce entities within text."""
   return "".join(html_escape_table.get(c,c) for c in text)

if __name__=="__main__":

   form = cgi.FieldStorage()
   try:
      email = form['email'].value
      if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",email):
         email = ""
   except KeyError as e:
      email = ""

   from tester import Tester
   T = Tester()
   T.login(ANONYMOUS_USER,ANONYMOUS_HASH)
   T.newtest(testname="dig")

   print("Content-Type: text/plain")    # HTML is following
   print()
   print(openpgpkey.my_gpg_public_key_block())
   T.commit()

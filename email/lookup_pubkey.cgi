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

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

from subprocess import call,Popen,PIPE
import smimea
import openpgpkey

if __name__=="__main__":

   form = cgi.FieldStorage()
   try:
      email = form['email'].value
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

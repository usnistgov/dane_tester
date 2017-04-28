#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
# Perform an email lookup
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

ANONYMOUS_USER="anonymous"
ANONYMOUS_HASH="iuabfuXHVpg="

def testid_html(testid,hash):
   return "<a href='lookup_test.cgi?testid={}&hash={}' target='_blank'>{}</a>".format(testid,hash,testid)

if __name__=="__main__":

   form = cgi.FieldStorage()
   try:
      email = html_escape(form['email'].value)
      if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",email):
         email = ""
   except KeyError as e:
      email = ""

   from tester import Tester
   T = Tester()
   T.login(ANONYMOUS_USER,ANONYMOUS_HASH)
   T.newtest(testname="dig")

   print("Content-Type: text/html")    # HTML is following
   print()
   print("""<html><body>""")
   print("<p><i>Test {}</i></p>".format(testid_html(T.testid,ANONYMOUS_HASH)))
   print("<h3>SMIMEA Lookup for <tt>{}</tt></h3>".format(email))

   data = smimea.smimea_to_txt(T,email)
   if data:
      print("<pre>{}</pre>".format(data))
   else:
      print("<p>No SMIMEA record for {}</p>".format(email))

   print("<h3>OPENPGPA Lookup for <tt>{}</tt></h3>".format(email))
   data = openpgpkey.openpgpkey_to_txt(T,email)
   if data:
      print("<pre>{}</pre>".format(data))
   else:
      print("<p>No OPENPGPA record for {}</p>".format(email))

   
   print("<h3>Tester Status</h3>")
   if dbmaint.user_hash(T.conn,email=email):
      print("<p><tt>{}</tt> is a registered user of this system.</p>".format(email))
   else:
      print("<p><tt>{}</tt> is not a registered user of this system.</p>".format(email))

   print("</body></html>")
   T.commit()

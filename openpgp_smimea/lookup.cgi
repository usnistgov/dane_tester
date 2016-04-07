#!/usr/bin/env python3
# -*- mode: python; -*-
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

from subprocess import call,Popen,PIPE

if __name__=="__main__":

   form = cgi.FieldStorage()
   try:
      email = form['email'].value
   except KeyError as e:
      email = ""
      
   print("Content-Type: text/html")    # HTML is following
   print()
   print("""<html><body>""")
   print("<h3>SMIMEA Lookup for <tt>{}</tt></h3>".format(email))
   sys.stdout.flush()
   data = Popen(["python3","smimea.py","--print",email],stdout=PIPE).communicate()[0]
   if data:
      print("<pre>{}</pre>".format(data))
   else:
      print("<p>No SMIMEA record for {}</p>".format(email))

   print("<h3>OPENPGPA Lookup for <tt>{}</tt></h3>".format(email))
   data = Popen(["python3","openpgpkey.py","--print",email],stdout=PIPE).communicate()[0]
   sys.stdout.flush()
   if data:
      print("<pre>{}</pre>".format(data))
   else:
      print("<p>No OPENPGPA record for {}</p>".format(email))

   
   print("<h3>Tester Status</h3>")
   import tester,dbmaint
   T = Tester()
   if dbmaint.user_hash(T.conn,email=email):
      print("<p><tt>{}</tt> is a registered user of this system.</p>".format(email))
   else:
      print("<p><tt>{}</tt> is not a registered user of this system.</p>".format(email))

   print("</body></html>")

#!/usr/bin/env python3
# -*- mode: python; -*-
#
import cgitb;cgitb.enable()
from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi
import sys

from subprocess import call

if __name__=="__main__":

   form = cgi.FieldStorage()
   try:
      email = form['email'].value
   except KeyError as e:
      email = ""
      
   print("Content-Type: text/html")    # HTML is following
   print()
   print("""<html><body>""")
   print("<h3>S/MIME Lookup</h3>")
   print("<pre>")
   sys.stdout.flush()
   call(["python3","smimea.py","--print",email])
   print("</pre>")
   print("<h3>OPENPGPA Lookup</h3>")
   print("<pre>")
   sys.stdout.flush()
   call(["python3","openpgpkey.py","--print",email])
   print("</pre>")
   print("</body></html")

#!/usr/bin/env python3
# -*- mode: python; -*-
#
# Perform a history
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
   print("Content-Type: text/html")    # HTML is following
   print()

   form = cgi.FieldStorage()
   try:
      hash = form['email'].value
   except KeyError as e:
      print("<h3>No hash provided</h3>")
      exit(0)
      
   print("<h3>History for hash <tt>{}</tt></h3>".format(hash))
   import tester,dbmaint
   T = Tester()
   print("</body></html>")

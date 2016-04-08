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
      hash = form['hash'].value
   except KeyError as e:
      print("<h3>No hash provided</h3>")
      exit(0)

   print("<h3>History for hash <tt>{}</tt></h3>".format(hash))
   import tester,dbmaint
   T = Tester()
   userid = dbmaint.user_lookup(T.conn,hash=hash)
   print("<p>Userid: {}</p>".format(userid))

   c = T.conn.cursor()
   c.execute("select testid,testtype,modified from tests where userid=%s",(userid,))
   print("<table class='table'>")
   print("<thead><tr><th>TestID</td><th>Test Type</th><th>Modified</th></tr></thead>")
   for (testid,testtype,modified) in c.fetchall():
      print("<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(testid,testtype,modified))
   print("</table>")

   print("</body></html>")


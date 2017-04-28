#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
# Perform a history
#
import cgitb;cgitb.enable()
from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi
import sys,io,codecs
import html

assert sys.version > '3'

from subprocess import call,Popen,PIPE

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

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

# Outputs a table with the ability to have disclosure triangles.

def testid_html(testid,hash):
   return "<a href='lookup_test.cgi?testid={}&hash={}' target='_blank'>{}</a>".format(testid,hash,testid)

if __name__=="__main__":
   sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
   print("Content-Type: text/html")    # HTML is following
   print()

   form = cgi.FieldStorage()
   try:
      hash = html_escape(form['hash'].value)
   except KeyError as e:
      print("<h3>No hash provided</h3>")
      exit(0)

   # The nb class disables the border on top of the element


   print("<h3>History for hash <tt>{}</tt></h3>".format(hash))
   import tester,dbmaint
   T = Tester()
   c = T.conn.cursor()
   userid = dbmaint.user_lookup(T.conn,hash=hash)
   c.execute("select testid,testtypes.name,tests.modified from tests left join testtypes on "+
             "tests.testtype=testtypes.testtype where userid=%s",(userid,))
   data = c.fetchall()


   print("<p>Userid: {} {}</p>".format(userid,len(data)))

   tclosed="▶︎"
   topened="▼"


   #print("""<style> .nb {   border-top: none !important; }</style>""")


   print("<table class='table'>")
   print("<thead><tr><th>TestID</td><th>Test Type</th><th>Modified</th></tr></thead>")
   oid = 1
   for (testid,testtype,modified) in data:
      # The disclosure triangle.
      # It's not working now.
      disclosure="<span class='disclosure' id={}'>{}{}</span>".\
         format(oid,tclosed,testid_html(testid,hash))
      print("<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(disclosure,testtype,modified))
      # print("<tr><td colspan=3 class='disclosure_text nb' id={}>More data goes here. It can be very big.</td></tr>".format(oid))
      oid += 1
   print("</table>")

   print("""
<script>
$(document).ready(function(){
   $('[data-toggle
</script>
""")

   print("</body></html>")


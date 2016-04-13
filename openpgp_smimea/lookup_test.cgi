#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
# Perform a testid lookup
#
import cgitb;cgitb.enable()
from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi
import sys

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

from subprocess import call,Popen,PIPE

if __name__=="__main__":

   form = cgi.FieldStorage()
   try:
      testid = form['testid'].value
      hash   = form['hash'].value
   except KeyError as e:
      email = ""
      hash  = ""
      
   print("Content-Type: text/html")    # HTML is following
   print()
   print("""<html><body>""")

   # Make sure that this testid has this hash
   T = Tester()
   c = T.cursor()
   c.execute("select userid from tests where testid=%s",(testid,))
   userid = c.fetchone()[0]
   if dbmaint.user_hash(T.conn,userid=userid) != hash:
      print("<h3>Invalid hash for user userid={}</h3>".format(userid))
      exit(0)
   
   sys.stdout.flush()

   # Make navigation links
   navigation = ''

   # Find the text test for this userid
   c.execute("select max(testid) from tests where userid=%s and testid<%s",(userid,testid))
   n = c.fetchone()
   if n[0]:
      navigation += "<a href='lookup_test.cgi?testid={}&hash={}'>&lt;--{}--</a>".format(n[0],hash,n[0])
      
   c.execute("select min(testid) from tests where userid=%s and testid>%s",(userid,testid))
   n = c.fetchone()
   if n[0]:
      if navigation:
         navigation += "&nbsp;"*5;
      navigation += "<a href='lookup_test.cgi?testid={}&hash={}'>--{}--&gt;</a>".format(n[0],hash,n[0])
      
   print(navigation)

   c.execute("select queryname,queryrr,answer,modified from dns where testid=%s order by modified",(testid,))
   print("<h3>DNS lookup for TestID <tt>{}</tt></h3>".format(testid))
   data = c.fetchall()
   if data:
      print("<table>")
      print("<thead><tr><th>NAME</td><th>RR</th><th>Answer</th><th>Modified</th></tr></thead>")

      for (queryname,queryrr,answer,modified) in data:
         print("<tr><td>{}</td><td>{}</td><td><pre>\n{}\n</pre></td><td></td></tr>".format(
            queryname,queryrr,answer,modified))
         print("</table>")
   else:
      print("<i>No DNS queries were issued</i>")


   c.execute("select body,received,sent,toaddr,fromaddr,modified,smtp_log from messages where testid=%s order by modified",(testid,))
   print("<h3>Messages for TestID <tt>{}</tt></h3>".format(testid))
   data = c.fetchall()
   if data:
      for (body,received,sent,toaddr,fromaddr,modified,smtp_log) in data:
         print("<table>")
         def mm(a,b):
            print("<tr><th>{}</th><td>{}</td></tr>".format(a,b))
         mm("to:",toaddr)
         mm("from:",fromaddr)
         mm("date:",modified)
         mm("received:",received)
         mm("sent:",sent)
         print("</table>")
         print("<p>message:</p>")
         print("<pre>\n{}\n</pre>".format(body))
         print("<p>SMTP Log:</p>")
         print("<pre>\n{}\n</pre>".format(smtp_log))
         print("<hr/>")
   else:
      print("<i>No Messages were sent or received</i>")
   print(navigation)


   print("</body></html>")


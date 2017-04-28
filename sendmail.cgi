#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
#
# sendmail.cgi: Can queue both S/MIME and OpenPGP messages.
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
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   form = cgi.FieldStorage()
   
   if 'email' not in form:
      print("<p>Please provide an email address</p>")
      
   if 'hash' not in form:
      print("<p>Please provide your hash. If you do not have one, "\
            "you must <a href='mailto:register@dane-test.had.dnsops.gov?subject=register&body=Thanks!'>register</a></p>")

   if 'email' in form and 'hash' in form:
      T = Tester()
      args = {}
      email = html_escape(form['email'].value)
      
      import re
      if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",email):
         print("Please provide a valid email address");
         exit(0)

      hash  = form['hash'].value

      T.login(email,hash)

      result = ""
      for sigmode in ["none","pgp","smime"]:
         try:
            checked = form[sigmode].value
         except KeyError:
            checked = False
         
         if checked:
            args['to']      = email
            args['subject'] = "Email from proj-had TestID {}".format(T.testid)
            args['testid']  = T.testid
            args['body']    = "This message was sent with signature mode '{}'.\n\nTestID {}.\n".format(sigmode,T.testid)
            args['sigmode'] = sigmode
            T.newtest(testname="sendplain")
            T.insert_task(tester.TASK_COMPOSE_SIMPLE_MESSAGE, args)
            T.commit()
            result += "<p>Message #{} mode '{}' queued.<p/>\n".format(T.testid,sigmode)
      print(result)             # send to caller
      exit(0)
   print("<p>No email message will be sent.</p>")
   exit(0)

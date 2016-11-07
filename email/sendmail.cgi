#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
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

if __name__=="__main__":
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   form = cgi.FieldStorage()


   if 'email' in form and 'hash' in form:
      T = Tester()
      args = {}
      email = form['email'].value
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
   print("required args not provided")
   exit(0)

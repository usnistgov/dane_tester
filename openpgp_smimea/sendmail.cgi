#!/usr/bin/env python3
# -*- mode: python; -*-
#
import cgitb;cgitb.enable()
from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi

if __name__=="__main__":
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   form = cgi.FieldStorage()


   if 'email' in form and 'hash' in form:
      T = Tester(testname="sendplain")
      args = {}
      email = form['email'].value
      hash  = form['hash'].value
      if hash != dbmaint.user_hash(T.conn,email=email):
         print("Invalid hash for {}".format(email))
         exit(0)

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
            T.insert_task(tester.TASK_COMPOSE_SIMPLE_MESSAGE, args)
            T.commit()
            T.newtest()
            result += "<p>Message #{} mode '{}' queued.<p/>\n".format(T.testid,sigmode)
      print(result)             # send to caller
      exit(0)
   print("required args not provided")
   exit(0)

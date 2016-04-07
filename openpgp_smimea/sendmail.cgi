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
      try:
         sigmode = form['sigmode'].value
      except KeyError:
         sigmode = '--'
      if hash != dbmaint.user_hash(T.conn,email=email):
         print("Invalid hash for {}".format(email))
         exit(0)
         
      args['to']      = email
      args['subject'] = "A subject"
      args['testid']  = T.testid
      args['body']    = "A body"
      args['sigmode'] = form['sigmode'].value
      T.insert_task(tester.TASK_COMPOSE_SIMPLE_MESSAGE, args)
      T.commit()
      print('Your {} email to {} is queued.'.format(sigmode,email))
      exit(0)

   print("required args not provided")

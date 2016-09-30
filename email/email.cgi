#!/usr/bin/env python3
# -*- mode: python; -*-
#
# CGI module to queue an email mesasge 
import cgitb;cgitb.enable()
from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

if __name__=="__main__":
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   form = cgi.FieldStorage()
   host = None


   if 'email' in form and 'hash' in form:
      T = Tester(testname="sendplain")
      t = Template(filename="sendmail.html")
      args = {}
      email = form['email'].value
      hash  = form['hash'].value
      if hash == dbmaint.user_hash(T.conn,email=email):
         args['to']      = email
         args['subject'] = "A subject"
         args['testid']  = T.testid
         args['body']    = "A body"
         args['sigmode'] = form['sigmode'].value
         T.insert_task(tester.TASK_COMPOSE_SIMPLE_MESSAGE, args)
         T.commit()
         args['message'] = 'Your email to {} is queued.'.format(email)
      else:
         args['message'] = 'Email/Hash missmatch. {} != {}'.format(hash,dbmaint.user_hash(T.conn,email=email))
      print(t.render(**args))

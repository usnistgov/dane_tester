#!/usr/bin/env python3
# -*- mode: python; -*-
#
from mako.template import Template
import cgitb
cgitb.enable()

if __name__=="__main__":
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   form = cgi.FieldStorage()
   host = None

   if 'email' in form and 'hash' in form:
   

   t = Template(filename="sendmail.html")
   print(t.render(**data))

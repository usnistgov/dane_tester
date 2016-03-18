#!/usr/bin/env python3
#
from mako.template import Template
import cgitb
cgitb.enable()

if __name__=="__main__":
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   t = Template(filename="hello.html")
   data = {"data":"world"}
   print(t.render(**data))


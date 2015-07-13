#!/usr/bin/env python2.7
# -*- mode: python; -*-

import cgi,cgitb,subprocess,sys
import dane_checker

times = 0

if __name__=="__main__":
   print "Content-type: text/html\r\n\r\n"
   print "<html><title>Okay</title>"

   cgitb.enable()
   form = cgi.FieldStorage()
   if "host" in form:
      host = form['host'].value
      print "Checking <b>{0}</b>::<br>".format(host)
      sys.stdout.flush()
      dane_checker.process(host,format='html')
      sys.stdout.flush()



   print "<form>"
   print "<input type='text' name='host'><br>"
   print "<input type='submit' value='Submit'>"
   print "</form>"
   print "Or try some of these test points:<br>"
   def murl(x):
      return "<a href='dane_check.cgi?host={}'>{}</a><br>".format(x,x)
   print murl("unixadm.org"),"<br>"
   print murl("https://www.freebsd.org/"),"<br>"
   print "</html>"

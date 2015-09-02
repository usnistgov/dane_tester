#!/usr/bin/env python2.7
# -*- mode: python; -*-

import cgi,cgitb,subprocess,sys,os,re
import dane_checker

times = 0

if __name__=="__main__":
   print "Content-type: text/html\r\n\r\n"
   print "<html><title>Okay</title>"

   cgitb.enable()
   form = cgi.FieldStorage()
   host = None
   if "host" in form:
      host = form['host'].value
      
   m = re.search(".*/smtp/(.*)$",os.environ["REQUEST_URI"])
   if m:
      host = m.group(1)

   m = re.search(".*/https?/(.*)$",os.environ["REQUEST_URI"])
   if m:
      host = "https://" + m.group(1) + "/"

   if host:
      host = host.strip()
      sys.stdout.flush()
      print "Checking ok <b>{0}</b>:<br>".format(host)
      dane_checker.process(host,format='html')
      print "<p>"
      print "Compare with <a href='https://dane.sys4.de/smtp/{}'>dane.sys4.de</a>".format(host)
   sys.stdout.flush()

   print "<p>"
   print "<form>"
   print "<input type='text' name='host'><br>"
   print "<input type='submit' value='Submit'>"
   print "</form>"
   print "Or try some of these test points:<br>"
   def murl(x):
      return "<a href='{}?host={}'>{}</a><br>".format(os.environ["SCRIPT_NAME"],x,x)
   print murl("unixadm.org"),"<br>"
   print murl("https://www.freebsd.org/"),"<br>"
   print "<p>Other DANE SMTP checkers:"
   print "<ul>"
   print "<li><a href='https://dane.sys4.de/'>https://dane.sys4.de/</a> (SMTP only)"
   print "<li><a href='https://www.had-pilot.com/dane/danelaw.html'>https://www.had-pilot.com/dane/danelaw.html</a> (HTTPS only)."
   print "</ul>"
   print "</html>"
   

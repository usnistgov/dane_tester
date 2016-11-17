#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
# NIST-developed software is provided by NIST as a public service. You
# may use, copy and distribute copies of the software in any medium,
# provided that you keep intact this entire notice. You may improve,
# modify and create derivative works of the software or any portion of
# the software, and you may copy and distribute such modifications or
# works. Modified works should carry a notice stating that you changed
# the software and should note the date and nature of any such
# change. Please explicitly acknowledge the National
# Institute of Standards and Technology as the source of the software.

# NIST-developed software is expressly provided “AS IS.” NIST MAKES NO
# WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY
# OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
# NON-INFRINGEMENT AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR
# WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR
# ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT
# WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE
# SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE
# CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

# You are solely responsible for determining the appropriateness of
# using and distributing the software and you assume all risks
# associated with its use, including but not limited to the risks and
# costs of program errors, compliance with applicable laws, damage to
# or loss of data, programs or equipment, and the unavailability or
# interruption of operation. This software is not intended to be used
# in any situation where a failure could cause risk of injury or
# damage to property. The software developed by NIST employees is not
# subject to copyright protection within the United States.

import cgi,cgitb,subprocess,sys,os,re
import dane_checker
assert sys.version > '3'

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

times = 0

if __name__=="__main__":
   cgitb.enable()
   template = open("dane_check_template.html","r",encoding='utf8').read()
   (top,bottom) = template.split("%%INSERT%%")
   print("Content-type: text/html\r\n\r\n")
   print(top)

   if not dane_checker.verify_package():
      print("<p>Required <tt>dane_checker executable</tt>(s) not installed.</p>")
      print("<p>Run <tt>make</tt> in installation directory.</p>")
      print(bottom)
      exit(0)

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
      print("Checking <b>{0}</b>:<br>".format(host))
      sys.stdout.flush()
      dane_checker.process(host,format='html')
      sys.stdout.flush()
      print("<p>")
      print("Compare with <a href='https://dane.sys4.de/smtp/{}'>dane.sys4.de</a>".format(host))

   print("<p>")
   print("Enter a DOMAIN to test an SMTP server.<br/> Enter a URL to test HTTPS server.<br/>")
   print("<form>")
   print("<input type='text' name='host'><br>")
   print("<input type='submit' value='Submit'>")
   print("</form>")
   print("Or try some of these test points:<br>")
   def murl(x):
      return "<a href='{}?host={}'>{}</a>".format(os.environ["SCRIPT_NAME"],x,x)
   print("<ul>")
   print("<li>",murl("unixadm.org"),"<i>Email tester</i></li>")
   print("<li>",murl("https://www.freebsd.org/"),"<i>https tester</i></li>")
   print("</ul>")
   print("<p>Other DANE SMTP checkers:")
   print("<ul>")
   print("<li><a href='https://dane.sys4.de/'>https://dane.sys4.de/</a> (SMTP only)")
   print("<li><a href='https://www.had-pilot.com/dane/danelaw.html'>https://www.had-pilot.com/dane/danelaw.html</a> (HTTPS only).")
   print("</ul>")
   print(bottom)

   

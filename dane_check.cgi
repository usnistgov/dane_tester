#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
# -*- mode: python; -*-

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
import dane_check

if __name__=="__main__":
    print "Content-type: text/html\r\n\r\n"

    try:
        script = os.environ["SCRIPT_NAME"]
    except KeyError:
        script = ""
    cgitb.enable()
    form = cgi.FieldStorage()
    host = ''
    proto = 'smtp'
    if "host" in form:
        host = form['host'].value
        
    m = re.search(".*/smtp/(.*)$",os.environ["REQUEST_URI"])
    if m:
        host = m.group(1)
        proto = 'smtp'

    m = re.search(".*/https?/(.*)$",os.environ["REQUEST_URI"])
    if m:
        host = "https://" + m.group(1) + "/"
        proto = 'https'

    if host:
        hostname=host.replace("https:","").replace("/","")
        print "<html><title>{} | DANE Checker</title>".format(hostname)
        host = host.strip()
        print "Checking <b>{}</b> for DANE {}:<br>".format(host,proto)
        sys.stdout.flush()
        dane_check.process(host,format='html')
        sys.stdout.flush()
        print "<p>"
        print "<ul>"
        if proto=='smtp':
            print "<li><a href='{}/https/{}'>Check https://{} for HTTPS DANE</a>".format(script,hostname,hostname)
            print "<li>Compare with <a href='https://dane.sys4.de/smtp/{}'>dane.sys4.de</a>".format(hostname)
        if proto=='https':
            print "<li><a href='{}/smtp/{}'>Check <b>{}</b> for SMTP DANE</a>".format(script,hostname,hostname)
        print "</ul>"
        
    else:
        print "<html><title>DANE Checker</title>"

    print "<p>"
    print "<hr>"
    print "Test another host:<p>"
    print "<form>"
    print "<input type='text' name='host'><br>"
    print "<input type='submit' value='Submit'>"
    print "</form>"
    print "Or try some of these test points:<br>"
    def murl(x):
        return "<a href='{}?host={}'>{}</a>".format(script,x,x)
    print "<ul>"
    print "<li>",murl("unixadm.org")," (SMTP)"
    print "<li>",murl("https://www.freebsd.org/")," (HTTP)"
    print "</ul>"
    print "<p>Other DANE Checkers:"
    print "<ul>"
    print "<li><a href='https://dane.sys4.de/'>https://dane.sys4.de/</a> (SMTP only)"
    print "<li><a href='https://www.had-pilot.com/dane/danelaw.html'>https://www.had-pilot.com/dane/danelaw.html</a> (HTTPS only)."
    print "</ul>"
    print "</html>"
    

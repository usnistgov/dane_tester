#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
import cgi,cgitb
cgitb.enable()

import sys,os,os.path
sys.path.append(os.path.expanduser("~/gits/dane_tester/email"))

tform="""
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="icon" href="favicon.ico">
    <title>Email Tester</title>

    <!-- Bootstrap core CSS -->
    <link href="dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <link href="assets/css/ie10-viewport-bug-workaround.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="jumbotron.css" rel="stylesheet">

    <!-- Just for debugging purposes. Don't actually copy these 2 lines! -->
    <!--[if lt IE 9]><script src="assets/js/ie8-responsive-file-warning.js"></script><![endif]-->
    <script src="assets/js/ie-emulation-modes-warning.js"></script>

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>
<body>
<div class="jumbotron">
<div class="container">
<h1>Email Tester</h1>
<form action="webcontrol.cgi" method="get">
  <fieldset>
  <label> Your email address: </label>
  <input id="email" type="text" name="email"/>
  </fieldset>
  <fieldset>
  <label> The hash you were provided with when you registered:</label>
  <input id="hash" type="text" name="hash"/>
  </fieldset>
  <input type="submit" value="OK">
  </fieldset>
</form>
</div>
</div>
</body>
"""


if __name__=="__main__":
   print("Content-Type: text/html")    # HTML is following
   print()                             # blank line, end of headers
   form = cgi.FieldStorage()
   if "hash" not in form or "email" not in form:
      print(tform)
   else:
      from tester import Tester
      import dbmaint,tester
      T = Tester(testname="sendplain")
      email = form.getfirst("email","")
      if dbmaint.user_hash(T.conn,email=email)==form.getfirst("hash","BADVALUE"):
         print("Correct hash. Sending mail.")
         T.insert_task(tester.TASK_COMPOSE_SIMPLE_MESSAGE,{"to":email,
                                                           "subject":"Your response from HAD",
                                                           "body":"This is the plain message you requested"})
         T.commit()
      else:
         print("Incorrect hash. Not sending mail.")
         
      


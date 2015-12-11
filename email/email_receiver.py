#!/usr/bin/env python3
#
# the email receiver ingests email messages and stores them in the database

import tester                   # get my routine
import logging
import sys
import email

if __name__=="__main__":
    # Get the test type for our invocation
    con = tester.mysql_connect()
    cmd = sys.argv[1]
    c = con.cursor()
    c.execute("select testtype from testtypes where name=%s",(cmd,))
    try:
        testtype = c.fetchone()[0]
    except TypeError:
        raise RuntimeError("No test type '{}'".format(cmd))
        
    print("testtype={}".format(testtype))

    # Get the email message
    body = sys.stdin.read()
    msg  = email.message_from_string(body)

    # Save it in the database
    c.execute("insert into tests (testtype) values (%s)",(testtype,))
    testid = c.lastrowid
    c.execute("insert into messages(testid,toaddr,fromaddr,body,received) values(%s,%s,%s,%s,now())",(testid,msg['to'],msg['from'],body))
    messageid = c.lastrowid
    con.commit()


    # First get a database handle
    logging.error("Logged Message {}".format(messageid))

    # Now save the message in the database
    # 

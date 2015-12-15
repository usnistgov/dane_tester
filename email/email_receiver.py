#!/usr/bin/env python3
#
# email_receiver.py:
# ingests email messages and stores them in the database
# Usage:  email_receiver.py [testqueue] <message
#


import tester                   # get my routine
import logging
import sys
import email
import json

logging.basicConfig(level=logging.DEBUG)

if __name__=="__main__":
    # Get the test type for our invocation
    conn = tester.mysql_connect()
    cmd = sys.argv[1]
    c = conn.cursor()
    c.execute("select testtype from testtypes where name=%s",(cmd,))
    try:
        testtype = c.fetchone()[0]
    except TypeError:
        raise RuntimeError("No test type '{}'".format(cmd))
        
    print("testtype={}".format(testtype))

    # Get the email message
    body = sys.stdin.read()

    # Save it in the database
    c.execute("insert into tests (testtype) values (%s)",(testtype,))
    testid = c.lastrowid
    messageid = tester.insert_email_message(conn,testid,tester.EMAIL_TAG_USER_SENT,body)

    # Finally, a workqueue requirement to compose the response
    args = {"messageid":messageid}
    tester.insert_task(conn,testid,tester.TASK_COMPOSE_SIMPLE_RESPONSE,args)
    conn.commit()

    # First get a database handle
    logging.info("Logged Message {}".format(messageid))

    # Now save the message in the database
    # 

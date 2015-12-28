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
    cmd = sys.argv[1]
    T = tester(cmd)

    # Get the email message
    body = sys.stdin.read()

    # Save it in the database
    c.execute("insert into tests (testtype) values (%s)",(testtype,))
    messageid = T.insert_email_message(T.testid,tester.EMAIL_TAG_USER_SENT,body)

    # Finally, a workqueue requirement to compose the response
    args = {"messageid":messageid}
    T.insert_task(testid,tester.TASK_COMPOSE_SIMPLE_RESPONSE,args)
    T.commit()

    # Log the results
    logging.info("Logged Message {}".format(messageid))


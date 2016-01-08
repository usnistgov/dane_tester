#!/usr/bin/env python3
#
# email_receiver.py:
# ingests email messages and stores them in the database
# Usage:  email_receiver.py [testqueue] <message
#


from tester import Tester                   # get my routine
import tester
import logging
import sys
import email
import json

logging.basicConfig(level=logging.DEBUG)

if __name__=="__main__":
    # Get the test type for our invocation
    cmd = sys.argv[1]
    T = Tester(testname=cmd)

    # Get the email message. Beware of possible unicode problems.
    msg = email.message_from_file(sys.stdin)

    # Save it in the database
    messageid = T.insert_email_message(tester.EMAIL_TAG_USER_SENT,str(msg))

    # Finally, a workqueue requirement to compose the response
    args = {"messageid":messageid}
    T.insert_task(tester.TASK_COMPOSE_SIMPLE_RESPONSE,args)
    T.commit()

    # Log the results
    logging.info("Logged Message {}".format(messageid))


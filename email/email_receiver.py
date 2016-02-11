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

def email_receiver(cmd,msg):
    T = Tester(testname=cmd)

    # Save it in the database
    messageid = T.insert_email_message(tester.EMAIL_TAG_USER_SENT,str(msg))
    args = {"messageid":messageid,"cmd":cmd}

    # Depending on the command, institute the next step...
    if cmd=="bouncer":
        T.insert_task(tester.TASK_COMPOSE_SIMPLE_RESPONSE, args)
        T.commit()
        
    elif cmd=="register":
        T.insert_task(tester.TASK_REGISTER_FROM_EMAIL, args)
        T.commit()

    else:
         # Log invalid command
         logging.info("Invalid command: {}  Message {}".format(cmd,messageid))

    

if __name__=="__main__":
    # Get the test type for our invocation
    cmd = sys.argv[1]
    msg = email.message_from_file(sys.stdin)

    email_receiver(cmd,msg)

#!/usr/bin/env python3
#
# email_receiver.py:
# ingests email messages and stores them in the database
# Usage:  email_receiver.py [testqueue] <message
#


from tester import Tester                   # get my routine
import argparse
import tester
import logging
import sys
import email
import json

logging.basicConfig(level=logging.DEBUG)

def email_receiver(cmd,msg):
    T = Tester()
    T.newtest(testname=cmd)

    # Save the received email mesasge in the database
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
    cmd = None
    parser = argparse.ArgumentParser(description="Designed to be called from a PIPE in /etc/aliases.")
    parser.add_argument("--register",help="Simulate register by email with a predefined message. REGISTER is from: address")
    parser.add_argument("command",nargs="?",help="Specifies queue to use. [bouncer|register]. Email message should be provided on STDIN")
    args = parser.parse_args()

    if args.register:
        print("Fake registration email:\n\n")
        msg_str = "To: email_receiver.py\nFrom: {}\nSubject: register\n\nRegister me\n".format(args.register)
        print(msg_str)
        cmd = "register"
        msg = email.message_from_string(msg_str)

    # Get the test type for our invocation
    if not cmd:
        cmd = sys.argv[1]
        msg = email.message_from_file(sys.stdin)

    email_receiver(cmd,msg)

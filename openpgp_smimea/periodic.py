#!/usr/bin/env python3
#
# periodic queue runner
# currently includes the test implementations as well.
# periodic.py - the program that is for development

import tester
import pymysql.cursors
import logging,json
import email
import dbmaint
import smtp


logging.basicConfig(level=logging.DEBUG)

from_address = "pythentic@had-ub1.had-pilot.com"
template0 = \
"""To: %TO%
From: %FROM%
Subject: %SUBJECT%

%BODY%
"""

template1 = \
"""To: %TO%
From: %FROM%
Subject: Your response from testid %TESTID%

Here is the message you sent:

%MESSAGE%
"""

template2 = \
"""To: %TO%
From: %FROM%
Subject: Re:register

Thank you for registering on the had-pilot.biz test system.
Here is your hash. Please enter it in the Paste-in-Hash field of the test form,
with your address in the MailTo field.

The test system is rate limited to one message per minute, to curb spamming through our server.
Mailto = %MAILTO%
Paste-in-Hash = %HASH%
If you register again you will get the same hash as a reminder.
"""



# Get the message from the database, create a response, and put it back in the database with new work to do.
def compose_simple_message(T,args):
    c = T.conn.cursor()
    msg = template0.replace("%TO%",args['to']) \
                            .replace("%FROM%",from_address) \
                            .replace("%SUBJECT%",args['subject']) \
                            .replace("%TESTID%",str(T.testid)) \
                            .replace("%BODY%",args['body'])
    messageid = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,msg)
    T.insert_task(tester.TASK_SEND_MESSAGE,{"messageid":messageid})
    T.commit()
    return True

def compose_simple_response(T,args):
    c = T.conn.cursor()
    c.execute("select body from messages where messageid=%s",(args['messageid'],))
    for (body,) in c.fetchall():
        msg = email.message_from_string(body)
        response = template1.replace("%TO%",msg['from']) \
                            .replace("%FROM%",from_address) \
                            .replace("%TESTID%",str(T.testid)) \
                            .replace("%MESSAGE%",body)
        messageid = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,response)
        T.insert_task(tester.TASK_SEND_MESSAGE,{"messageid":messageid})
        T.commit()
        return True



# Like compse_simple_response, but also creates a hash
def register_from_email(T,args):
    c = T.conn.cursor()
    c.execute("select body from messages where messageid=%s",(args['messageid'],))
    for (body,) in c.fetchall():
        msg = email.message_from_string(body)
        sender = msg['from']
        response = template2.replace("%TO%",sender) \
                            .replace("%FROM%",from_address) \
                            .replace("%MAILTO%",sender) \
                            .replace("%HASH%",dbmaint.user_hash(T.conn,userid=dbmaint.user_register(T.conn,sender)))
        messageid = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,response)
        T.insert_task(tester.TASK_SEND_MESSAGE,{"messageid":messageid})
        T.commit()
        return True

# Send a message that is pending in the database
def send_message(T,args):
    c = T.conn.cursor()
    messageid = args['messageid']
    c.execute("select body from messages where messageid=%s",(messageid,))
    for (body,) in c.fetchall():
        import smtplib
        msg = email.message_from_string(body)
        from_header = msg['From']
        to_headers = []
        if msg.get_all('To'): to_headers += msg.get_all('To')
        if msg.get_all('Cc'): to_headers += msg.get_all('Cc')
        smtp_log = smtp.sendmailWithTranscript(tester.SMTP_HOST,tester.SMTP_PORT,from_header,to_headers,body)
        if smtp_log:
            T.set_smtp_log(messageid,smtp_log)
            T.commit()
        return True
    
def run(testid,task,args):
    logging.info("testid={} task={} args={}".format(testid,task,args))

    if task==tester.TASK_COMPOSE_SIMPLE_RESPONSE:
        return compose_simple_response(testid,args)

    if task==tester.TASK_SEND_MESSAGE:
        return send_message(testid,args)

    if task==tester.TASK_REGISTER_FROM_EMAIL:
        return register_from_email(testid,args)

    if task==tester.TASK_COMPOSE_SIMPLE_MESSAGE:
        return compose_simple_message(testid,args)

    raise RuntimeError("testid: {}  unknown worker: {}".format(testid,worker))


def periodic():
    from tester import Tester


    import argparse
    parser = argparse.ArgumentParser(description="database maintenance")
    parser.add_argument("--list",help="List all of the tasks",action="store_true")
    args = parser.parse_args()
    
    W = Tester()                # get a database connection
    c = W.conn.cursor()

    if args.list:
        c.execute("select workqueueid,testid,created,completed from workqueue")
        for line in c:
            print(line)
        exit(0)

    c.execute("select workqueueid,testid,task,args from workqueue where isnull(completed)")
    for (workqueueid,testid,task,args_str) in c.fetchall():
        T = Tester(testid=testid)
        args = json.loads(args_str)
        print("args_str=",args_str,"args=",args)
        args['state'] = 'WORKING'
        if run(T,task,args):
            c.execute("update workqueue set completed=now() where workqueueid=%s",(workqueueid,))
            W.commit()
        

if __name__=="__main__":
    periodic()
        


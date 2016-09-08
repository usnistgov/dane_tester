#!/usr/bin/env python3
# -*- mode: python; -*-
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
import smimea
import openpgpkey

debug = True
logging.basicConfig(level=logging.DEBUG)

FROM_ADDRESS = "dane-tester@dane-test.had.dnsops.gov"
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

Your have successfully registered your email address "%TO%" with the 
DANE test system operating at dane-test.had.dnsops.gov.

Your "hash" is below. You will use this hash to initiate tests on the DANE TEST website.

URL:	http://dane-test.had.dnsops.gov/dane_tester/email/
EMAIL:	%MAILTO%
Hash:	%HASH%

The test system is rate limited to one message per minute, to curb spamming through our server.

If you register again you will get the same hash as a reminder.
"""


# Get the message from the database, create a response, and put it back in the database with new work to do.
def compose_simple_message(T,args):
    c = T.conn.cursor()
    msg = template0.replace("%TO%",args['to']) \
                            .replace("%FROM%",FROM_ADDRESS) \
                            .replace("%SUBJECT%",args['subject']) \
                            .replace("%TESTID%",str(T.testid)) \
                            .replace("%BODY%",args['body'])
    args['messageid'] = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,msg)
    T.insert_task(tester.TASK_CRYPTO_MESSAGE,args)
    T.commit()
    return True

def compose_simple_response(T,args):
    c = T.conn.cursor()
    c.execute("select body from messages where messageid=%s",(args['messageid'],))
    for (body,) in c.fetchall():
        msg = email.message_from_string(body)
        response = template1.replace("%TO%",msg['from']) \
                            .replace("%FROM%",FROM_ADDRESS) \
                            .replace("%TESTID%",str(T.testid)) \
                            .replace("%MESSAGE%",body)
        args['messageid'] = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,response)
        T.insert_task(tester.TASK_CRYPTO_MESSAGE,args)
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
                            .replace("%FROM%",FROM_ADDRESS) \
                            .replace("%MAILTO%",sender) \
                            .replace("%HASH%",dbmaint.user_hash(T.conn,userid=dbmaint.user_register(T.conn,sender)))
        args['messageid'] = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,response)
        T.insert_task(tester.TASK_CRYPTO_MESSAGE,args)
        T.commit()
        return True

# crypto a message
# currently only does signing.
def crypto_message(T,args):
    c = T.conn.cursor()
    c.execute("select body,messageid from messages where messageid=%s",(args['messageid'],))
    for (body,messageid) in c.fetchall():
        sigmode = args.get('sigmode',"none")
        encmode = args.get('encmode',"none")
        newbody = None
        if sigmode=="none" and encmode=="none":
            # No processing; use the old message
            pass
        elif sigmode=='smime' or encmode=='smime':
            # Perform an SMIME signature and/or encryption
            signing_cert = None
            signing_key  = None
            if sigmode=='smime':
                signing_cert = smimea.get_file(smimea.SIGNING_KEY_FILE )
                signing_key  = smimea.get_file(smimea.SIGNING_CERT_FILE)
            newbody = smimea.smime_crypto(body,signing_key=signing_key,signing_cert=signing_cert)
        elif sigmode=='pgp' or encmode=='pgp':
            # Perform a PGP signature and/or encryption
            newbody = openpgpkey.pgp_process(body,signing_key_file=openpgpkey.SIGNING_KEY_FILE)
        else:
            newbody = body + "\n\nInvalid signature mode: {}\n".format(sigmode)

        # If a new message was created, insert the new message into
        # the database and get the new messageID
        if newbody:
            args['messageid'] = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,newbody) 
        T.insert_task(tester.TASK_SEND_MESSAGE,args)
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
    

def periodic():
    from tester import Tester


    import argparse
    parser = argparse.ArgumentParser(description="database maintenance")
    parser.add_argument("--debug",action="store_true")
    parser.add_argument("--list",help="List all of the tasks",action="store_true")
    args = parser.parse_args()
    
    W = Tester()                # get a database connection
    c = W.conn.cursor()

    if args.list:
        c.execute("select workqueueid,testid,created,completed from workqueue")
        for line in c:
            print(line)
        exit(0)

    # Run the queue until there is nothing left to run
    while True:
        c.execute("select workqueueid,testid,task,args from workqueue where isnull(completed)")
        count = 0
        for (workqueueid,testid,task,task_args_str) in c.fetchall():
            count += 1 
            T = Tester(testid=testid)
            task_args = json.loads(task_args_str)
            if args.debug or debug:
                print("task_args=",task_args)
                task_args['state'] = 'WORKING'
            logging.info("testid={} task={} task_args={}".format(testid,task,task_args))
            if eval(task+"(T,task_args)"):
                c.execute("update workqueue set completed=now() where workqueueid=%s",(workqueueid,))
                W.commit()
        if count==0:
            break
    


if __name__=="__main__":
    periodic()
        


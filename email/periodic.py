#!/usr/bin/env python3
#
# periodic queue runner

import tester
import pymysql.cursors
import logging,json

logging.basicConfig(level=logging.DEBUG)

from_address = "no-reply@no-domain.com"

def compose_simple_response(T,args):
    import email

    # Get the message from the database, create a response, and put it back in the database with new work to do.
    c = T.conn.cursor()
    c.execute("select body from messages where messageid=%s",(args['messageid'],))
    for (body,) in c.fetchall():
        msg = email.message_from_string(body)
        response = "To: {}\nFrom: {}\nSubject: Your response from testid {}\n\nHere is the message you sent:\n\n{}".format(
            msg['from'],
            from_address,
            T.testid,
            body)
        messageid = T.insert_email_message(tester.EMAIL_TAG_AUTOMATED_RESPONSE,response)
        T.insert_task(tester.TASK_SEND_MESSAGE,{"messageid":messageid})
        T.commit()
        return True

# Send a message that is pending in the database
def send_message(T,args):
    import email,smtp
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
        T.set_smtp_log(messageid,smtp_log)
        T.commit()
        return True
    
def run(testid,task,args):
    logging.info("testid={} task={} args={}".format(testid,task,args))
    if task==tester.TASK_COMPOSE_SIMPLE_RESPONSE:
        return compose_simple_response(testid,args)
    if task==tester.TASK_SEND_MESSAGE:
        return send_message(testid,args)
    raise RuntimeError("testid: {}  unknown worker: {}".format(testid,worker))


if __name__=="__main__":
    import argparse
    from tester import Tester

    W = Tester()                # get a database connection
    c = W.conn.cursor()
    c.execute("select workqueueid,testid,task,args from workqueue where isnull(completed)")
    for (workqueueid,testid,task,args_str) in c.fetchall():
        T = Tester(testid=testid)
        args = json.loads(args_str)
        print("args_str=",args_str,"args=",args)
        args['state'] = 'WORKING'
        if run(T,task,args):
            c.execute("update workqueue set completed=now() where workqueueid=%s",(workqueueid,))
            W.commit()
        
                     
        


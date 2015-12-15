#!/usr/bin/env python3
#
# periodic queue runner

import tester
import pymysql.cursors
import logging,json

logging.basicConfig(level=logging.DEBUG)

from_address = "no-reply@no-domain.com"

conn = tester.mysql_connect()



def compose_simple_response(testid,args):
    import email

    # Get the message from the database, create a response, and put it back in the database with new work to do.
    c = conn.cursor()
    c.execute("select body from messages where messageid=%s",(args['messageid'],))
    for (body,) in c.fetchall():
        print("body=",body)
        msg = email.message_from_string(body)
        response = "To: {}\nFrom: {}\nSubject: Your response from testid {}\n\nHere is the message you sent:\n\n{}".format(
            msg['from'],
            from_address,
            testid,
            body)
        messageid = tester.insert_email_message(conn,testid,tester.EMAIL_TAG_AUTOMATED_RESPONSE,response)
        tester.insert_task(conn,testid,tester.TASK_SEND_MESSAGE,{"messageid":messageid})
        conn.commit()
        return True

def send_message(testid,args):
    import email
    # Send the message that is pending
    c = conn.cursor()
    c.execute("select body from messages where messageid=%s",(args['messageid'],))
    for (body,) in c.fetchall():
        import smtplib
        msg = email.message_from_string(body)
        from_header = msg['From']
        to_headers = []
        if msg.get_all('To'): to_headers += msg.get_all('To')
        if msg.get_all('Cc'): to_headers += msg.get_all('Cc')
        print("from_header=",from_header)
        print("to_header=",to_headers)
        smtpObj = smtplib.SMTP(tester.SMTP_HOST,tester.SMTP_PORT)
        smtpObj.sendmail(from_header,to_headers,body)
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

    c = conn.cursor()
    c.execute("select workqueueid,testid,task,args from workqueue where isnull(completed)")
    for (workqueueid,testid,task,args_str) in c.fetchall():
        args = json.loads(args_str)
        print("args_str=",args_str,"args=",args)
        args['state'] = 'WORKING'
        if run(testid,task,args):
            c.execute("update workqueue set completed=now() where workqueueid=%s",(workqueueid,))
            conn.commit()
        
                     
        


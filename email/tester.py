#!/usr/bin/env python3
#
# common routines for NIST email tester
# Requires PyMySQL

import os,os.path
import pymysql.cursors

SMTP_HOST = "localhost"
SMTP_PORT = 25


DB_HOST = "localhost"
DB_NAME = "emaildb"
DEFAULT_HOME = "/home/slg"

home = os.getenv("HOME") if os.getenv("HOME") else DEFAULT_HOME
cfg_file = os.path.join(home,"email.cfg")

# Work jobs
TASK_COMPOSE_SIMPLE_RESPONSE="COMPOSE SIMPLE RESPONSE"
TASK_SEND_MESSAGE="SEND MESSAGE"

# Email message tags
EMAIL_TAG_USER_SENT="USER SENT" # sent by a user
EMAIL_TAG_AUTOMATED_RESPONSE="AUTOMATED RESPONSE" # created by our script

import tester                   # import myself
import pytest,json

def mysql_connect():
    import configparser,sys
    cfg = configparser.ConfigParser()
    cfg.read(cfg_file)
    sec = cfg["mysql"]
    return pymysql.connect(host=sec.get("host",DB_HOST),
                           user=sec.get("username"),
                           password=sec.get("password"),
                           charset='utf8',
                           db=sec.get("emaildb",DB_NAME))
                           
def insert_email_message(conn,testid,tag,body):
    """Insert an email message into the database using a given connection; return the messageid"""
    import email
    msg  = email.message_from_string(body)
    c = conn.cursor()
    c.execute("insert into messages(testid,tag,toaddr,fromaddr,body,received) values(%s,%s,%s,%s,%s,now())",(
        testid,tag,msg['to'],msg['from'],body))
    return c.lastrowid
    
def insert_task(conn,testid,task,args):
    c = conn.cursor()
    c.execute("insert into workqueue (testid,task,args,created) values (%s,%s,%s,NOW())",(testid,task,json.dumps(args)))
    return c.lastrowid


                           
if __name__=="__main__":
    import tester               # I can import myself!
    print("Current databases:")
    db = tester.mysql_connect()
    c = db.cursor()
    c.execute("show tables")
    for t in c:
        print(t[0])
    

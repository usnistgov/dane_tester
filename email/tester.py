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

class tester:
    def __init__(self,testname=None,testid=None,rw=True):
        import configparser,sys
        cfg = configparser.ConfigParser()
        cfg.read(cfg_file)
        sec = cfg["mysql"]
        self.conn = pymysql.connect(host=sec.get("host",DB_HOST),
                                    user=sec.get("username"),
                                    password=sec.get("password"),
                                    charset='utf8',
                                    db=sec.get("emaildb",DB_NAME))

        # if testname is specified, create a new test
        self.rw = rw
        if testid:
            self.rw = False
            self.testid = testid
        if testname and self.rw:
            testtype = self.get_test_type(testname)
            c = self.conn.cursor()
            c.execute("insert into tests (testtype) values (%s)",(testtype,))
            self.testid = c.lastrowid

    def get_test_type(self,name):
        c = self.conn.cursor()
        c.execute("select testtype from testtypes where name=%s",(name,))
        try:
            return c.fetchone()[0]
        except TypeError:
            raise RuntimeError("No test type '{}'".format(cmd))

    def insert_email_message(self,testid,tag,body):
        """Insert an email message into the database using a given connection; return the messageid"""
        assert self.rw
        import email
        msg  = email.message_from_string(body)
        c = self.conn.cursor()
        c.execute("insert into messages(testid,tag,toaddr,fromaddr,body,received) values(%s,%s,%s,%s,%s,now())",(
            testid,tag,msg['to'],msg['from'],body))
        return c.lastrowid

    def insert_task(self,testid,task,args):
        assert self.rw
        c = self.conn.cursor()
        c.execute("insert into workqueue (testid,task,args,created) values (%s,%s,%s,NOW())",(testid,task,json.dumps(args)))
        return c.lastrowid

    def commit(self):
        if self.rw:
            self.conn.commit()


                           
if __name__=="__main__":
    import tester               # I can import myself!
    print("Current databases:")
    db = tester.mysql_connect()
    c = db.cursor()
    c.execute("show tables")
    for t in c:
        print(t[0])
    

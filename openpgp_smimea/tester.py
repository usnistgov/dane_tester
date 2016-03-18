#!/usr/bin/env python3
#
# common routines for NIST email tester
# Requires PyMySQL

import os,os.path
import pymysql.cursors

SMTP_HOST = "mail.nist.gov"
SMTP_PORT = 25

# Hack to handle internal email.
# implemented in smtp.py
SMTP_INTERNAL_HOST = "localhost"
SMTP_INTERNAL_DOMAIN = ".had-pilot.com"


DB_HOST = "localhost"
DB_NAME = "emaildb"
DEFAULT_HOME = "/home/slg"

home = os.getenv("HOME") if os.getenv("HOME") else DEFAULT_HOME
cfg_file = os.path.join(home,"email.cfg")
cfg_file = "/home/slg/email.cfg"

# Work jobs
TASK_COMPOSE_SIMPLE_RESPONSE="COMPOSE SIMPLE RESPONSE"
TASK_SEND_MESSAGE="SEND MESSAGE"
TASK_REGISTER_FROM_EMAIL="REGISTER FROM EMAIL"
TASK_COMPOSE_SIMPLE_MESSAGE="COMPOSE SIMPLE MESSAGE"

# Email message tags
EMAIL_TAG_USER_SENT="USER SENT" # sent by a user
EMAIL_TAG_AUTOMATED_RESPONSE="AUTOMATED RESPONSE" # created by our script

import tester                   # import myself
import pytest,json,os,os.path,sys

class Tester:
    def __init__(self,testname=None,testid=None,rw=True):
        self.rw = rw            # .rw means we are writing
        self.testid = testid
        self.conn = None        # make sure it's set
        assert os.path.exists(cfg_file)
        import configparser,sys
        cfg = configparser.ConfigParser()
        cfg.read(cfg_file)
        sec = cfg["mysql"]
        try:
            self.conn = pymysql.connect(host=sec.get("host",DB_HOST),
                                    user=sec.get("username"),
                                    password=sec.get("password"),
                                    charset='utf8',
                                    db=sec.get("emaildb",DB_NAME))
        except pymysql.err.OperationalError as e:
            sys.stderr.write("********************************\n")
            sys.stderr.write("*** MYSQL SERVER NOT RUNNING ***\n")
            sys.stderr.write("********************************\n")
            raise e

        # if testname is specified, create a new test
        if testid:
            self.testid = testid
        if testname and self.rw:
            testtype = self.get_test_type(testname)
            c = self.conn.cursor()
            c.execute("insert into tests (testtype) values (%s)",(testtype,))
            self.testid = c.lastrowid

    def cursor(self):
        return self.conn.cursor()

    def get_test_type(self,name):
        c = self.conn.cursor()
        c.execute("select testtype from testtypes where name=%s",(name,))
        try:
            return c.fetchone()[0]
        except TypeError:
            raise RuntimeError("No test type '{}'".format(cmd))

    def insert_email_message(self,tag,body):
        """Insert an email message into the database using a given connection; return the messageid"""
        assert self.rw
        assert self.testid>0
        import email
        msg  = email.message_from_string(body)
        c = self.conn.cursor()
        c.execute("insert into messages(testid,tag,toaddr,fromaddr,body,received) values(%s,%s,%s,%s,%s,now())",(
            self.testid,tag,msg['to'],msg['from'],body))
        return c.lastrowid

    def set_smtp_log(self,messageid,smtp_log):
        c = self.conn.cursor()
        c.execute("select smtp_log from messages where messageid=%s",(messageid,))
        r = c.fetchall()
        # Make sure that there is precisely one row with messageid=messageid and that it has no log
        assert len(r)==1
        assert r[0][0]==None
        c.execute("update messages set smtp_log=%s,sent=now() where messageid=%s",(smtp_log,messageid))

    def insert_task(self,task,args):
        assert self.rw
        c = self.conn.cursor()
        c.execute("insert into workqueue (testid,task,args,created) values (%s,%s,%s,NOW())",(self.testid,task,json.dumps(args)))
        return c.lastrowid

    def commit(self):
        if self.rw and self.conn:
            self.conn.commit()

    # this has caused many problems
    #def __del__(self):
    #    self.commit()           # if we need to commit, do it!

                           
if __name__=="__main__":
    import tester               # I can import myself!
    print("Current databases:")
    db = tester.mysql_connect()
    c = db.cursor()
    c.execute("show tables")
    for t in c:
        print(t[0])
    

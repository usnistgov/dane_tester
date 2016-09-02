#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
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
TASK_COMPOSE_SIMPLE_RESPONSE="compose_simple_response"
TASK_COMPOSE_SIMPLE_MESSAGE="compose_simple_message"
TASK_CRYPTO_MESSAGE="crypto_message"
TASK_SEND_MESSAGE="send_message"
TASK_REGISTER_FROM_EMAIL="register_from_email"

# Email message tags
EMAIL_TAG_USER_SENT="USER SENT" # sent by a user
EMAIL_TAG_AUTOMATED_RESPONSE="AUTOMATED RESPONSE" # created by our script

import pytest,json,os,os.path,sys
import dbmaint

class Tester:
    def __init__(self,testid=None,rw=True):
        """Create a new Tester object. Specify either testname or testid"""
        self.rw     = rw          # .rw means we are writing
        self.testid = testid
        self.conn   = None        # make sure it's set
        self.userid = 0           # not logged in

        # Make sure that the cfg_file exists and that it is not world or group readable
        if not os.path.exists(cfg_file):
            raise RuntimeError("{} does not exist".format(cfg_file))
        if (os.stat(cfg_file).st_mode & 0o0070) != 0:
            raise RuntimeError("{} should not be group-readable or group-writable".format(cfg_file))
        if (os.stat(cfg_file).st_mode & 0o0007) != 0:
            raise RuntimeError("{} should not be world-readable or world-writable".format(cfg_file))
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

    def login(self,email,userhash):
        if userhash != dbmaint.user_hash(self.conn,email=email):
            print("Invalid hash for {}".format(email))
            exit(0)
        self.email  = email
        self.userid = dbmaint.user_lookup(self.conn,email)

    def newtest(self,testname=None):
        """Get a new testid."""
        self.testtype = self.get_test_type(testname)
        c = self.conn.cursor()
        fields = ["testtype"]
        fds    = ["%s"]
        vals   = [self.testtype]
        if self.userid:
            fields.append("userid")
            fds.append("%s")
            vals.append(self.userid)

        c.execute("insert into tests (" + ",".join(fields) + ") values (" + ",".join(fds) +")",vals)
        self.testid = c.lastrowid

    def cursor(self):
        return self.conn.cursor()

    def dictcursor(self):
        return self.conn.cursor(pymysql.cursors.DictCursor)

    def get_test_type(self,name):
        c = self.conn.cursor()
        c.execute("select testtype from testtypes where name=%s",(name,))
        try:
            return c.fetchone()[0]
        except TypeError:
            raise RuntimeError("No test type '{}'".format(name))

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
        c.execute("insert into workqueue (testid,task,args,created) values (%s,%s,%s,NOW())",
                  (self.testid,task,json.dumps(args)))
        return c.lastrowid

    def commit(self):
        if self.rw and self.conn:
            self.conn.commit()

    # this has caused many problems
    #def __del__(self):
    #    self.commit()           # if we need to commit, do it!

                           
if __name__=="__main__":
    import tester               # I can import myself; useful for demo code
    print("Current databases:")
    db = tester.mysql_connect()
    c = db.cursor()
    c.execute("show tables")
    for t in c:
        print(t[0])
    

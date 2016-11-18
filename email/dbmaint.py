#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
# programs for maintaining the database

import tester                   # get my routine
import logging
import sys
import pymysql.err
from tabulate import tabulate
import periodic

assert sys.version > '3'

def make_hash(email):
    "These are called hashes, but they are actually random nonces."
    import os,base64
    return base64.b64encode(os.urandom(8))


def user_register(conn,email):
    """Regsiter an email address. conn is the MySQL database connection.
    Returns the userid."""
    c = conn.cursor()
    try:
        c.execute("insert into users (email,hash) values (%s,%s)",(email,make_hash(email)))
        conn.commit()
        return c.lastrowid
    except pymysql.err.IntegrityError as e:
        pass                    # user already exists
    c.execute("select userid from users where email=%s",(email,))
    for (userid,) in c.fetchall():
        return userid
    return none
        
def user_lookup(conn,email=None,hash=None):
    """Return the userID given a hash or email"""
    c = conn.cursor()
    if email:
        c.execute("select userid from users where email=%s",(email,))
    if hash:
        c.execute("select userid from users where hash=%s",(hash,))
    for (userid,) in c.fetchall():
        return userid
    return None
    

def user_hash(conn,userid=None,email=None):
    """Return the hash for a specific user or email address"""
    assert(userid!=None or email!=None)
    c = conn.cursor()
    if userid:
        c.execute("select hash from users where userid=%s",(userid,))
    if email:
        c.execute("select hash from users where email=%s",(email,))
    for (hash,) in c.fetchall():
        return hash
    return None
        

if __name__=="__main__":
    import argparse
    from tester import Tester

    parser = argparse.ArgumentParser(description="database maintenance")
    parser.add_argument("--createtest",help="Create a new test")
    parser.add_argument("--list",help="List something [tests, users, messages, workqueue]")
    parser.add_argument("--dump",help="Dump database",action="store_true")
    parser.add_argument("--dumpsmtp",help="Dump an SMTP transaction")
    parser.add_argument("--register",help="Register an email address as a user")
    parser.add_argument("--registerByMail",help="Fake registration from email address")
    parser.add_argument("--resend",help="Resend an email message")
    parser.add_argument("--message",help="Display mesasge #",type=int)
    
    if len(sys.argv)==1:
        parser.print_help()
        exit(0)

    args = parser.parse_args()

    T = Tester()
    c = T.cursor()
    

    if args.createtest:
        try:
            c.execute("insert into testtypes (name) values (%s)",(args.createtest,))
            T.commit()
            print("test {} created".format(args.createtest))
        except pymysql.err.IntegrityError as e:
            print("test {} already exists".format(args.createtest))


    if args.list:
        if args.list.startswith("test"):
            cmd = "select testtype,name from testtypes"
        if args.list.startswith("user"):
            cmd = "select * from users"
        if args.list.startswith("m"):
            cmd = "select messageid,fromaddr,toaddr,received,sent,length(smtp_log) from messages"
        if args.list.startswith("w"):
            cmd = "select * from workqueue"
        print("Tests:")
        c.execute(cmd)
        headers = [t[0] for t in c.description]
        print(tabulate(c,headers))

    if args.register:
        userid = user_register(T.conn,args.register)
        print("Hash for {}: {}".format(args.register,user_hash(T.conn,userid=userid)))
            
    if args.registerByMail:
        import email_receiver,email
        msg = email.message_from_string("To: {}\nFrom: {}\nSubject: register\n\n".format(periodic.from_address,args.registerByMail))
        email_receiver.email_receiver("register",msg)

    if args.dump:
        import configparser,sys
        from subprocess import Popen,PIPE
        cfg = configparser.ConfigParser()
        cfg.read(tester.cfg_file)
        username = cfg.get("mysql","username")
        password = cfg.get("mysql","password")
        dbname = cfg.get("mysql","dbname")
        cmd = ['mysqldump','-u'+username,'-p'+password,'-d',dbname]
        sys.stdout.write(Popen(cmd,stdout=PIPE).communicate()[0].decode('utf-8'))
        
    if args.message:
        c.execute("select body,smtp_log from messages where messageid=%s",(args.message,))
        (body,log) = c.fetchone()
        print("Message Body:")
        print(body)
        if log:
            print("")
            print("SMTP Log")
            print(log)

    if args.dumpsmtp:
        c.execute("select smtp_log from messages where messageid=%s",(args.dumpsmtp,))
        print(c.fetchone()[0])

    if args.resend:
        import periodic
        c.execute("insert into messages (testid,body,received,toaddr,fromaddr,tag) select testid,body,received,toaddr,fromaddr,tag from messages where messageid=%s;",(args.resend))
        messageid = c.lastrowid
        c.execute("select testid from messages where messageid=%s",(messageid,))
        testid = c.fetchone()[0]
        print("testid=",testid)
        T.testid = testid
        T.insert_task(tester.TASK_SEND_MESSAGE, {"messageid": c.lastrowid})
        print("running periodic...")
        periodic.periodic()


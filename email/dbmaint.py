#!/usr/bin/env python3
#
# programs for maintaining the database

import tester                   # get my routine
import logging
import sys
import pymysql.err

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
    return c.fetchone()[0]
        
def user_hash(conn,userid):
    c = conn.cursor()
    c.execute("select hash from users where userid=%s",(userid,))
    return c.fetchone()[0]
        

if __name__=="__main__":
    import argparse
    from tester import Tester

    parser = argparse.ArgumentParser(description="database maintenance")
    parser.add_argument("--create",help="Create a new test")
    parser.add_argument("--list",help="List something [tests, email, messages]")
    parser.add_argument("--dump",help="Dump database",action="store_true")
    parser.add_argument("--dumpsmtp",help="Dump an SMTP transaction")
    parser.add_argument("--register",help="Register an email address as a user")
    parser.add_argument("--registerByMail",help="Fake registration from email address")
    parser.add_argument("--resend",help="Resend an email message")
    
    args = parser.parse_args()
    T = Tester()
    c = T.cursor()
    
    if args.create:
        try:
            c.execute("insert into testtypes (name) values (%s)",(args.create,))
            T.commit()
        except pymysql.err.IntegrityError as e:
            print("test {} already exists".format(args.create))

    if args.list:
        print("args.list=",args.list)
        if args.list.startswith("test"):
            cmd = "select testtype,name from testtypes"
        if args.list.startswith("user"):
            cmd = "select * from users"
        if args.list.startswith("message"):
            cmd = "select messageid,fromaddr,toaddr,received,sent,length(smtp_log) from messages"
        print("Tests:")
        print(cmd)
        c.execute(cmd)
        for row in c:
            print("\t".join([str(r) for r in row]))

    if args.register:
        userid = user_register(T.conn,args.register)
        print("Hash for {}: {}".format(args.register,user_hash(T.conn,userid)))
            
    if args.registerByMail:
        import email_receiver,email
        msg = email.message_from_string("To: pythentic@had-pilot.biz\nFrom: {}\nSubject: register\n\n".format(args.registerByMail))
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


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
        t.commit()
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
    parser.add_argument("--list",help="List the tests",action="store_true")
    parser.add_argument("--dump",help="Dump database",action="store_true")
    parser.add_argument("--register",help="Register an email address as a user")
    
    args = parser.parse_args()
    t = Tester()
    c = t.cursor()
    
    if args.create:
        try:
            c.execute("insert into testtypes (name) values (%s)",(args.create,))
            t.commit()
        except pymysql.err.IntegrityError as e:
            print("test {} already exists".format(args.create))
        args.list = True        # generate a list

    if args.list:
        print("Tests:")
        c.execute("select testtype,name from testtypes")
        for (testid,testtype) in c:
            print(testid,testtype)

    if args.register:
        userid = user_register(t.conn,args.register)
        print("Hash for {}: {}".format(args.register,user_hash(t.conn,userid)))
            

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

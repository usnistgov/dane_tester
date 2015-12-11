#!/usr/bin/env python3
#
# common routines for NIST email tester
# Requires PyMySQL

import os,os.path
import pymysql.cursors

DB_HOST = "localhost"
DB_NAME = "emaildb"
DEFAULT_HOME = "/home/slg"

home = os.getenv("HOME") if os.getenv("HOME") else DEFAULT_HOME
cfg_file = os.path.join(home,"email.cfg")

import pytest

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
                           
                           
             
if __name__=="__main__":
    import tester               # I can import myself!
    print("Current databases:")
    db = tester.mysql_connect()
    c = db.cursor()
    c.execute("show tables")
    for t in c:
        print(t[0])
    

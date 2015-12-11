#!/usr/bin/env python3
#
# dump the current schema to stdout.
#
import tester
import os,os.path

if __name__=="__main__":
    import configparser,sys
    from subprocess import Popen,PIPE
    cfg = configparser.ConfigParser()
    cfg.read(tester.cfg_file)
    username = cfg.get("mysql","username")
    password = cfg.get("mysql","password")
    dbname = cfg.get("mysql","dbname")
    cmd = ['mysqldump','-u'+username,'-p'+password,'-d',dbname]
    sys.stdout.write(Popen(cmd,stdout=PIPE).communicate()[0].decode('utf-8'))


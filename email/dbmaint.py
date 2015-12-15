#!/usr/bin/env python3
#
# programs for maintaining the database

import tester                   # get my routine
import logging
import sys

if __name__=="__main__":
    # Get the test type for our invocation
    con = tester.mysql_connect()
    c = con.cursor()
    cmd = sys.argv[1]
    if cmd=="create" and sys.argv[2]=="test":
        testname = sys.argv[3]
        c.execute("insert into testtypes (name) values (%s)",(testname,))
    print("Existing tests:")
    con.commit()
    c.execute("select testtype,name from testtypes")
    for (testid,testtype) in c:
        print(testid,testtype)
#!/usr/bin/env python3
#
# designed to be run from cron
#
# contains extra routines to make sure it isn't run twice

import os,os.path,fcntl

if not os.path.exists("CRON_ENABLED.txt"):
    exit(0)

fd = os.open(__file__,os.O_RDONLY)
if fd>0:
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        import periodic
        periodic.periodic()
    except IOError:
        print("Could not acquire lock")

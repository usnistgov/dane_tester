#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
# designed to be run from cron
#
# contains extra routines to make sure it isn't run twice

import os,os.path,fcntl,sys

assert sys.version > '3'

if __name__=="__main__":
    import argparse,sys

    parser = argparse.ArgumentParser(description="smimea tester")
    parser.add_argument("--debug",action="store_true")
    parser.add_argument("--list",help="List all of the tasks",action="store_true")
    args = parser.parse_args()

    # Try to acquire a lock on our own executable
    fd = os.open(__file__,os.O_RDONLY)
    if fd>0:
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
        except IOError:
            print("Could not acquire lock")
            exit(1)
    import periodic
    periodic.periodic()

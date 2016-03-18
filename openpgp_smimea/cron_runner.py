#!/usr/bin/env python3
#
# designed to be run from cron
#
# contains extra routines to make sure it isn't run twice

import os,os.path,fcntl

enabled_file = "/home/slg/CRON_ENABLED.txt"

if __name__=="__main__":
    import argparse,sys

    parser = argparse.ArgumentParser(description="smimea tester")
    parser.add_argument("--debug",action="store_true")
    parser.add_argument("--list",help="List all of the tasks",action="store_true")
    args = parser.parse_args()

    if not os.path.exists(enabled_file):
        if args.debug:
            print("{} not found".format(enabled_file))
        exit(0)

    fd = os.open(__file__,os.O_RDONLY)
    if fd>0:
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            import periodic
            periodic.periodic()
        except IOError:
            print("Could not acquire lock")

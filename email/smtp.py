#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-

import tempfile, smtplib, os, sys
import tester

def sendmailWithTranscript(server,port,from_header,to_headers,body):
    # See if we should send to an internal
    if tester.SMTP_INTERNAL_DOMAIN in to_headers[0]:
        server = tester.SMTP_INTERNAL_HOST


    # Send a message and return the transcript
    # Find an available file descriptor
    t = tempfile.TemporaryFile()
    available_fd = t.fileno()
    t.close()

    # now make a copy of stderr
    os.dup2(2,available_fd)

    # Now create a new tempfile and make Python's stderr go to that file
    t = tempfile.TemporaryFile()
    os.dup2(t.fileno(),2)

    # Now run the task that logs to stderr
    s = smtplib.SMTP(server,port)
    s.set_debuglevel(1)
    s.sendmail(from_header,to_headers,body)

    # Grab the stderr from the temp file
    sys.stderr.flush()
    t.flush()
    t.seek(0)
    smtp_envelope = t.read()
    t.close()

    # Put back stderr
    os.dup2(available_fd,2)
    os.close(available_fd)
    return smtp_envelope


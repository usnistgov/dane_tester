Each test consists of a testid and an incoming email message.

The testid is created in response to a user action (sending an email
message, requesting a test on a website) The test consists of a series
of named jobs (steps) which are executed.  Each job reads from the
database, performs an action, and writes to the database.

Each email message in the database has a tag to indicate what kind of
email message it is.


Clone of HAD Pythenic system:
================================
1. User sends email to register@had-ub1.
   - User gets hash in reponse.

2. User goes to website and provides email address and selects how to send
   - Website sends email.

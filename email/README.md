A "test" is an instance of a user requesting a test of the tester.

The "workqueue" is a list of work to be execute. If we had a large
production system this would be handled by a queue management
system. Instead, I handle it with a single SQL table that keeps track
of which task to run next and the arguments they are to be
given. For each task it notes when the task was created, how many
times it was attempted, and when it was completed. Tasks that are
attempted more than a certain number of times will be automatically
disabled.

I have implemented a simple echo test, in which a message is received
by the test system, a response is generated, and the response is sent.

The echo test involves the following steps:

1 - The incoming email message is read by an ingest script (mail_receiver.py). This script:
    1 - Creates a new testid
    2 - Saves the message in the `messages` table
    3 - Creates a work task that will create the reply message.

2 - The queue runner runs the reply-message-generator, which:
    1 - Reads the message out of the `messages` table.
    2 - Crafts a response.
    3 - Writes the response back to the `messages` table, and gets the messageid
    4 - Creates a new email-sender task with the messageid of the
        message that was just created.

   After the reply-message-generator runs successfully, this fact is
   noted and it doesn't need to run again. 

3 - The queue runner runs the email-sender, which:
    1 - Reads the message associated with the messageid.
    2 - Sends the email message.
    3 - Reports if the message was successfully sent, which results in
        the work job being marked as completed.

So when an email message is received on the auto-reply email
addresser, the queue runner needs to process the queue 
twice in order for the sender to receive the response. Currently each
process requires a separate invocation, although it will be
straightforward to have the queue runner run until there there is
nothing left in the worker queue to execute.

Test Design
===========

Each test consists of a testid and an incoming email message.

The testid is created in response to a user action (sending an email
message, requesting a test on a website) The test consists of a series
of named jobs (steps) which are executed.  Each job reads from the
database, performs an action, and writes to the database.

Each email message in the database has a tag to indicate what kind of
email message it is.


Test Infrastructure supported:
==============================
+ Register by email
+ Register by website
+ Verify Registration
+ Send plain email
- Send plain email with s/mime signature
- Send plain email with PGP signature
- Send smimea encrypted email 
- Send smimea encrypted email with s/mime signature
- Send PGP encrypted email
- Send PGP encrypted email with PGP signature


To do:
======
- Change template in process.py to use mako

Clone of HAD Pythenic system:
================================
1. User sends email to register@had-ub1.
   - User gets hash in reponse.

2. User goes to website and provides email address and selects how to send
   - Website sends plain email.
   - Website sends SMIMEA mail
   - Website sends OpenPGPKEY mail.


Simple email responder
======================
Activity: Mail sent to bouncer@had-ub1 results in a response to the sender

These lines are in `/etc/aliases`:

    ### email-bouncer test 
    bouncer: "|/home/slg/gits/dane_tester/email/email_receiver.py bouncer"

State machine:
--------------
1. email_receiver.py 
2. TASK_COMPOSE_SIMPLE_RESPONSE
3. TASK_SEND_MESSAGE


Website registration with hash-sent-back
========================================
Activity: users register online, receive a hash, enter the hash and the email address on the website to get a message.

1. User sends email to pythentic@had-ub1 with register as the subject.  (email_receiver.py)
2. TASK_COMPOSE_REGISTRATION_RESPONSE

Alternative registration:

3. email_register.py <emailaddress>
4. 


These lines are in `/etc/aliases`:


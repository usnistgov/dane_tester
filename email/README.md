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

I'm currently trying to figure out how to capture the SMTP output from
the python smtplib library. If that doesn't work, I'll call sendmail
direclty and capture the output that way.

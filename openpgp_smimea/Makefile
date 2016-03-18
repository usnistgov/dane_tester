CFG_FILE=$(HOME)/email.cfg
schema.sql: dbmail.py $(CFG_FILE)
	python3 dbmaint.py --dump > schema.sql

setup:	dbmaint.py
	python3 dbmaint.py create test bouncer
	python3 dbmaint.py create test dig

lbounce:
	@echo test email receiver with a simple bounce
	python3 email_receiver.py bouncer < msg-bounce.txt

bounce:	
	@echo Sending a test email message
	sendmail -t -v < msg-bounce.txt

clean:
	/bin/rm -f *~


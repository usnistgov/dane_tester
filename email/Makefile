CFG_FILE=$(HOME)/email.cfg
schema.sql: dump_schema.py $(CFG_FILE)
	python3 dump_schema.py > schema.sql

lbounce:
	@echo test email receiver with a simple bounce
	python3 email_receiver.py bouncer < msg-bounce.txt

bounce:	
	@echo Sending a test email message
	sendmail -t -v < msg-bounce.txt

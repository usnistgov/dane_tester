CFG_FILE=$(HOME)/email.cfg
schema.sql: dump_schema.py $(CFG_FILE)
	python3 dump_schema.py > schema.sql

bounce:	
	@echo Sending a test email message
	sendmail -t -v < msg-bounce.txt

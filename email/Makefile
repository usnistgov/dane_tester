
CFG_FILE=$(HOME)/email.cfg
schema.sql: dbmaint.py $(CFG_FILE)
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


bootstrap-3.3.7-dist.zip:
	wget https://github.com/twbs/bootstrap/releases/download/v3.3.7/bootstrap-3.3.7-dist.zip

install: bootstrap-3.3.7-dist.zip
	if [ ! -e bootstrap ]; then unzip bootstrap-3.3.7-dist.zip; ln -s bootstrap-3.3.7-dist bootstrap; fi


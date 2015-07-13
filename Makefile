get_altnames: get_altnames.c
	gcc -o get_altnames get_altnames.c -Wall -lssl -lcrypto 

pub:
	cp *.py *.cgi /var/www/html/

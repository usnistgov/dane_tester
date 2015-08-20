get_altnames: get_altnames.c
	gcc -o get_altnames get_altnames.c -Wall -lssl -lcrypto 

pub:
	cp *.py *.cgi /var/www/html/ 
	cp *.cgi ../public_html/

zip:
	zip dane_checker.zip *.py *.cgi

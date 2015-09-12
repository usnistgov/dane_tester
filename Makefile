get_altnames: get_altnames.c
	gcc -o get_altnames get_altnames.c -Wall -lssl -lcrypto 

pub:
	cp dane_check.cgi dane_checker.py /var/www/html/ 
	cp dane_check.cgi ../public_html/

zip:
	zip dane_checker.zip *.py *.cgi


centos-install:
	echo target for installing necessary packages on a centos build
	yum install -y gcc-c++
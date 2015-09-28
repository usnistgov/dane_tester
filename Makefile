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

centos-slg:
	echo target for installing useful packages for development
	yum install -y mlocate

# https://devops.profitbricks.com/tutorials/install-python-3-in-centos-7/
# to use python33 type:
# scl enable python33 bash
# easy_install pip
# #!/opt/rh/python33/root/usr/bin/python
centos7-prep:
	yum -y install scl-utils
	rpm -Uvh https://www.softwarecollections.org/en/scls/rhscl/python33/epel-7-x86_64/download/rhscl-python33-epel-7-x86_64.noarch.rpm
	yum -y install python33

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

/usr/lib64/python2.7/site-packages/getdns.so:
	git clone https://github.com/getdnsapi/getdns-python-bindings
	(cd getdns-python-bindings; python setup.py build; sudo python setup.py install)
	/bin/rm -rf  getdns-python-bindings



# https://devops.profitbricks.com/tutorials/install-python-3-in-centos-7/
# to use python33 type:
# scl enable python33 bash
# easy_install pip
# #!/opt/rh/python33/root/usr/bin/python
centos7-prep:
	yum -y install scl-utils
	rpm -Uvh https://www.softwarecollections.org/en/scls/rhscl/python33/epel-7-x86_64/download/rhscl-python33-epel-7-x86_64.noarch.rpm
	yum -y install python33


# Install our own version of OpenSSL
/usr/local/ssl/bin/openssl:
	wget https://www.openssl.org/source/openssl-1.0.2h.tar.gz
	tar xfz openssl-1.0.2h.tar.gz
	( cd openssl-1.0.2h && ./config && make depend && make && make test && make install )
	/bin/rm -rf openssl-1.0.2h.tar.gz openssl-1.0.2h

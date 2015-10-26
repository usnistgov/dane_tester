LDFLAGS:=-L/usr/local/lib -L/usr/local/ssl/lib
CPPFLAGS:=-I/usr/local/include -I/usr/local/ssl/include

get_altnames: get_altnames.c
	gcc $(CPPFLAGS) $(LDFLAGS) -o get_altnames get_altnames.c -Wall -lssl -lcrypto 

pub: get_altnames
	cp dane_check.cgi dane_checker.py get_altnames /var/www/html/ 
	cp dane_check.cgi get_altnames ../public_html/

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
	yum -y install pytest m2crypto
	yum -y install python33
	yum -y install gcc gcc-c++ libstdc++-devel expat-devel
	yum -y install zlib zlib-devel zlib-static
	yum -y install libidn libidn-devel
	yum -y install ldns ldns-devel ldns-python ldns-doc
	yum -y install python-devel
	yum -y install sudo yum install libevent-devel
	yum -y install libffi-devel

# Requires OpenSSL 1.0.2d
# Compile with:
#   ./Configure linux-x86_64 shared zlib
#
# Be sure to put this in your .bashrc:
# export LDFLAGS=-L/usr/local/lib:/usr/local/ssl/lib:$LDFLAGS
# export CPPFLAGS=-I/usr/local/include:/usr/local/ssl/include:$CFPPFLAGS
# export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/ssl/lib:$LD_LIBRARY_PATH
#
# getdns must be compiled --with-libevent

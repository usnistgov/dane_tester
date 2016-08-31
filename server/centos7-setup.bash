y#!/usr/bin/bash 
#
# configure centos7 to run the script
# note: this uses M2Crypto, so we are stuck with Python2

yum -y install python-setuptools openssl-devel getdns getdns-devel pytest m2crypto \
    httpd mod_ssl expat expat-devel 
apachectl start			# start the web server

make /usr/lib64/python2.7/site-packages/getdns.so	# getdns for python2
make /usr/local/ssl/bin/openssl				# openssl 1.0.2h 
make get_altnames					# make sure that it's running


# make sure firewall is up
firewall-cmd --add-service=http               2>&1 | grep -v 'Warning: ALREADY_ENABLED'
firewall-cmd --permanent --add-service=http   2>&1 | grep -v 'Warning: ALREADY_ENABLED'
firewall-cmd --add-service=https              2>&1 | grep -v 'Warning: ALREADY_ENABLED'
firewall-cmd --permanent --add-service=https  2>&1 | grep -v 'Warning: ALREADY_ENABLED'


# and test it!
py.test



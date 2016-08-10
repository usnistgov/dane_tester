#!/usr/bin/bash 
#
# configure centos7 to run the script
# note: this uses M2Crypto, so we are stuck with Python2

yum -y install python-setuptools openssl-devel getdns getdns-devel pytest m2crypto

# Install getdns python if it is not present
make /usr/lib64/python2.7/site-packages/getdns.so
make get_altnames

# and test it!
py.test


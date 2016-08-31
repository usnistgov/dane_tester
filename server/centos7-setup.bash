#!/usr/bin/bash 
#
# 
# Centos installation script. 
# May be rerun without causing problems

# Make the system more usable
yum -y install mlocate emacs telnet yum-cron git python-pip httpd mod_ssl libidn-devel 

# install needed componentst for package
yum -y install python-setuptools openssl-devel getdns getdns-devel pytest m2crypto \
    httpd mod_ssl expat expat-devel 

updatedb
apachectl start			# start the web server

# Install pip3 if it is not avaialble
pip3=$(which pip3)
if [ -x "$pip3" ] ; then
  echo pip3 already installed
else
  curl https://bootstrap.pypa.io/get-pip.py | python3.4
fi

yum -y install python-setuptools openssl-devel getdns getdns-devel pytest m2crypto 

if [ ! -r /usr/local/etc/unbound/unbound.conf ]; then
  echo Please manually download and install unbound and getdns
  echo They must be installed before openssl 1.1 is installed.
  exit 1
fi

# Make sure that getdns root key is installed
if [ ! -r  /etc/unbound/getdns-root.key ]; then
  sudo mkdir -p /etc/unbound
  sudo /usr/local/sbin/unbound-anchor -a "/etc/unbound/getdns-root.key"
fi

# Manually install getdns python bindings
if [ ! -r  /usr/lib64/python2.7/site-packages/getdns.so ]; then
  git clone https://github.com/getdnsapi/getdns-python-bindings.git
  cd getdns-python-bindings
  python setup.py build
  sudo python setup.py install
fi

# Install packages required for server tester
# note: this uses M2Crypto, so we are stuck with Python2

    
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



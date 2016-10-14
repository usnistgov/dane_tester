all: bootstrap
	(cd server;$(MAKE) all)
	(cd email;$(MAKE) all)

install:
	(cd email;$(MAKE) install) # installs bootstrap

bootstrap: bootstrap-3.3.7-dist.zip
	make install-bootstrap

bootstrap-3.3.7-dist.zip:
	wget https://github.com/twbs/bootstrap/releases/download/v3.3.7/bootstrap-3.3.7-dist.zip

install-bootstrap: bootstrap-3.3.7-dist.zip
	if [ ! -e bootstrap ]; then unzip bootstrap-3.3.7-dist.zip; ln -s bootstrap-3.3.7-dist bootstrap; fi

install: install-bootstrap

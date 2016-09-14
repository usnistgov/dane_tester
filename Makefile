all:
	(cd server;$(MAKE) all)
	(cd email;$(MAKE) all)

install:
	(cd email;$(MAKE) install) # installs bootstrap

######################################################################
#
#  A fake 'Makefile'.
#  $Id$
#

all:
	@echo Configure this module into Apache by going to the Apache root direcory,
	@echo and typing:
	@echo
	@echo ./configure --add-module=`pwd`/mod_auth_radius.c
	@echo make
	@echo

clean:
	@rm -f *~

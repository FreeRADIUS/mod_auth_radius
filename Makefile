######################################################################
#
#  A minimal 'Makefile', by Alan DeKok <aland@freeradius.org>
#
#  $Id$
#
######################################################################

VERSION=1.3.9

######################################################################
#
#  The default rule: tell the user what to REALLY do to use
#  the module.
#
all:
	@echo Configure this module into Apache by going to the Apache root direcory,
	@echo and typing:
	@echo
	@echo ./configure --add-module=`pwd`/mod_auth_radius.c
	@echo make
	@echo

######################################################################
#
#  Check a distribution out of the source tree, and make a tar file.
#
dist:
	cvs export -Dtoday -d mod_auth_radius-${VERSION} mod_auth_radius
	tar -cf mod_auth_radius-${VERSION}.tar mod_auth_radius-${VERSION}
	rm -rf mod_auth_radius-${VERSION}

######################################################################
#
#  Clean up everything.
#
clean:
	@rm -f *~ mod_auth_radius-${VERSION}.tar

######################################################################
#
#  A minimal 'Makefile', by Alan DeKok <aland@freeradius.org>
#
#  $Id$
#
######################################################################

VERSION=1.5.7

######################################################################
#
#  The default rule: tell the user what to REALLY do to use
#  the module.
#
all:
	@echo
	@echo Configure this module into Apache by going to the Apache root directory,
	@echo and typing:
	@echo
	@echo "     ./configure --add-module=`pwd`/mod_auth_radius.c --enable-shared=auth_radius"
	@echo
	@echo and then
	@echo
	@echo "     make"
	@echo "     make install"
	@echo
	@echo "Alternatively, if you've already built and installed Apache with"
	@echo dynamic modules, you should be able to install this module via:
	@echo
	@echo "     apxs -i -a -c mod_auth_radius.c"
	@echo	
	@echo You should add your additional site configuration options to the 'configure'
	@echo line, above.  Please read the README file for further information.
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
	@rm -f *~ *.o mod_auth_radius-${VERSION}.tar

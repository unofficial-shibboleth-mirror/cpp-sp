## $Id$ 

AUTOMAKE_OPTIONS = foreign

varrundir = /var/run
BUILDFILES = shibshar.fc
CLEANFILES = $(BUILDFILES)

all-data-local: $(BUILDFILES)

install-data-local:	all-data-local

shibshar.fc: ${srcdir}/shibshar.fc.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
	    -e 's:@-SBINDIR-@:${sbindir}:' \
	    -e 's:@-VARRUNDIR-@:${varrundir}:'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

EXTRA_DIST = .cvsignore shibshar.fc.in shibshar.te

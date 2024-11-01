AUTOMAKE_OPTIONS = foreign dist-zip dist-bzip2
ACLOCAL_AMFLAGS = -I m4

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = \
	doc \
	schemas \
	configs \
	shibsp \
	apache \
	fastcgi \
	unittests

pkgconfig_DATA = shibsp.pc

EXTRA_DIST = $(DX_CONFIG) \
	iis7_shib \
	Projects \
	config_win32.h \
	$(GENFILES) \
	$(GENFILES:%=%.in)

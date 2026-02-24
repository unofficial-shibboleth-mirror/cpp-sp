AUTOMAKE_OPTIONS = foreign dist-zip dist-bzip2
ACLOCAL_AMFLAGS = -I m4

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = \
	doc \
	configs \
	shibsp \
	apache \
	fastcgi \
	tests

pkgconfig_DATA = shibsp.pc

EXTRA_DIST = $(DX_CONFIG) \
	iis \
	msi \
	Projects \
	config_win32.h \
	$(GENFILES) \
	$(GENFILES:%=%.in)

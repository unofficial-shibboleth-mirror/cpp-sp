
AUTOMAKE_OPTIONS = foreign

SUBDIRS = . rpc

AM_CFLAGS = -D_rpc_dtablesize=getdtablesize

lib_LTLIBRARIES = liboncrpc.la

liboncrpc_la_SOURCES = \
  auth_non.c \
  auth_uni.c \
  authunix.c \
  clnt_gen.c \
  clnt_per.c \
  clnt_raw.c \
  clnt_sim.c \
  clnt_tcp.c \
  clnt_udp.c \
  get_myad.c \
  pmap_cln.c \
  pmap_get.c \
  pmap_gma.c \
  pmap_pr.c \
  pmap_pro.c \
  pmap_rmt.c \
  rpc_call.c \
  rpc_comm.c \
  rpc_prot.c \
  svc.c \
  svc_auth.c \
  svc_autu.c \
  svc_raw.c \
  svc_run.c \
  svc_simp.c \
  svc_tcp.c \
  svc_udp.c \
  xdr.c \
  xdr_arra.c \
  xdr_floa.c \
  xdr_mem.c \
  xdr_rec.c \
  xdr_refe.c \
  xdr_stdi.c

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
liboncrpc_la_LDFLAGS = -version-info 1:0:0

EXTRA_DIST = \
  .cvsignore \
  makefile.bc \
  makefile.nt \
  oncbcimp.def \
  oncrpc.def \
  oncrpc.rc \
  oncrpcbc.def \
  bcopy.c \
  bindresv.c \
  getrpcen.c \
  getrpcpo.c \
  nt.c \
  portmap.c


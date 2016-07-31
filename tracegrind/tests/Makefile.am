include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr filter_add filter_suppgen

EXTRA_DIST = \
	is_arch_supported \
	base.vgtest base.stdout.exp \
	base.stderr.exp-glibc28-amd64 \
	base.stderr.exp-gcc491-amd64

check_PROGRAMS = \
	base

# DDD: not sure if these ones should work on Darwin or not... if not, should
# be moved into x86-linux/.
#if ! VGCONF_OS_IS_DARWIN
#   check_PROGRAMS += \
#	ccc
#endif


AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)

# To make it a bit more realistic, build hackedbz2.c with at
# least some optimisation.
hackedbz2_CFLAGS	= $(AM_CFLAGS) -O -Wno-inline

globalerr_CFLAGS        = $(AM_CFLAGS) @FLAG_W_NO_UNINITIALIZED@
# C ones
#pth_create_LDADD	= -lpthread

# C++ ones
#ccc_SOURCES		= ccc.cpp

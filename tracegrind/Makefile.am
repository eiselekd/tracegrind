include $(top_srcdir)/Makefile.tool.am

#----------------------------------------------------------------------------
# Headers
#----------------------------------------------------------------------------

noinst_HEADERS = \
	trc_copy.h \
	trc_parser.h

#----------------------------------------------------------------------------
# tracegrind-<platform>
#----------------------------------------------------------------------------

noinst_PROGRAMS  = tracegrind-@VGCONF_ARCH_PRI@-@VGCONF_OS@
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += tracegrind-@VGCONF_ARCH_SEC@-@VGCONF_OS@
endif

tracegrind_SOURCES_COMMON = trc_main.c \
                            trc_dhelpers_@VGCONF_ARCH_PRI@.c

tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_SOURCES      = \
	$(tracegrind_SOURCES_COMMON)
tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_PRI_CAPS@)
tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_PRI_CAPS@)
tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_PRI@ \
	$(LINK) \
	$(tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS) \
	$(tracegrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS)

if VGCONF_HAVE_PLATFORM_SEC
tracegrind_SOURCES_SEC = trc_main.c \
                         trc_dhelpers_@VGCONF_ARCH_SEC@.c
tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_SOURCES      = \
	$(tracegrind_SOURCES_SEC)
tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_SEC_CAPS@)
tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_SEC_CAPS@)
tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_SEC@ \
	$(LINK) \
	$(tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS) \
	$(tracegrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS)
endif

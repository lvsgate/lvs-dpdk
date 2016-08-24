include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ipvs

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api
AM_CFLAGS +=  -I/usr/include/libnl3
AM_CFLAGS +=  -I$(RTE_SDK)/$(RTE_TARGET)/include
AM_CFLAGS +=  -I./include
AM_CFLAGS +=  -msse4.2

ipvs_LDFLAGS = $(AM_LDFLAGS) -static -lnl-3 -lnl-genl-3 -lnl-cli-3
ipvs_CFLAGS = $(AM_CFLAGS) -Woverride-init

dist_ipvs_SOURCES = main.c ofp_vs_core.c ofp_vs_ctl.c

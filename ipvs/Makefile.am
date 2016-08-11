include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ipvs

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api
AM_CFLAGS +=  -I/usr/include/libnl3

ipvs_LDFLAGS = $(AM_LDFLAGS) -static -lnl-3 -lnl-genl-3 -lnl-cli-3
ipvs_CFLAGS = $(AM_CFLAGS)

dist_ipvs_SOURCES = main.c ofp_vs_core.c ofp_vs_ctl.c

noinst_HEADERS = ${srcdir}/ofp_vs.h

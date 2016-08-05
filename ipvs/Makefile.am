include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ipvs

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

ipvs_LDFLAGS = $(AM_LDFLAGS) -static
ipvs_CFLAGS = $(AM_CFLAGS)

dist_ipvs_SOURCES = ofp_vs_core.c ofp_vs_ctl.c

noinst_HEADERS = ${srcdir}/ofp_vs.h

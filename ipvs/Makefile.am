include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ipvs

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api
AM_CFLAGS +=  -I/usr/local/include/libnl3
AM_CFLAGS +=  -I$(RTE_SDK)/$(RTE_TARGET)/include
AM_CFLAGS +=  -I./include
AM_CFLAGS +=  -msse4.2

ipvs_LDFLAGS = $(AM_LDFLAGS) -static -L/usr/local/lib -lnl-3 -lnl-genl-3 -lnl-cli-3
ipvs_CFLAGS = $(AM_CFLAGS) -Woverride-init \
			-DCONFIG_IP_VS_DEBUG \
			-DCONFIG_IP_VS_PROTO_TCP \
			-DCONFIG_IP_VS_PROTO_UDP

dist_ipvs_SOURCES = main.c ofp_vs_core.c ofp_vs_ctl.c ofp_vs_proto_tcp.c \
		ofp_vs_proto_udp.c ofp_vs_sched.c ofp_vs_rr.c ofp_vs_conn.c \
		ofp_vs_proto.c ofp_vs_xmit.c ofp_vs_stats.c

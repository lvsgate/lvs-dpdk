# Makefile
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>

CC	 = gcc
INCLUDES = -I../include -I../../lib
CFLAGS	 = -g -O2  -I/usr/src/linux/include $(INCLUDES) \
	   -Wall -Wunused -Wstrict-prototypes
DEFS	 = -D_KRNL_2_6_ -D_WITH_LVS_ -D_WITH_VRRP_ 
COMPILE	 = $(CC) $(CFLAGS) $(DEFS)

OBJS = 	main.o daemon.o pidfile.o layer4.o smtp.o \
	global_data.o global_parser.o
HEADERS = $(OBJS:.o=.h)

.c.o:
	$(COMPILE) -c $<

all:	$(OBJS)

clean:
	rm -f *.a *.o *~

distclean: clean
	rm -f Makefile


main.o: main.c ../include/main.h ../include/config.h ../../lib/signals.h
daemon.o: daemon.c ../include/daemon.h ../../lib/utils.h
pidfile.o: pidfile.c ../include/pidfile.h
layer4.o: layer4.c ../include/layer4.h ../include/check_api.h ../../lib/utils.h
smtp.o: smtp.c ../include/smtp.h ../include/global_data.h ../../lib/memory.h \
  ../../lib/list.h ../../lib/utils.h
global_data.o: global_data.c ../include/global_data.h ../../lib/memory.h \
  ../../lib/list.h ../../lib/utils.h
global_parser.o: global_parser.c ../include/global_parser.h \
  ../include/global_data.h ../../lib/parser.h ../../lib/memory.h \
  ../../lib/utils.h

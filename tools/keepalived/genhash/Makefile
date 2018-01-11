# Makefile.in
#
# Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>

EXEC = genhash
BIN  = ../bin

prefix      = /usr/local
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/bin
mandir      = ${prefix}/share/man

CC = gcc
STRIP = strip
INCLUDES = -I../lib
CFLAGS = -g -O2 -I/usr/include/libnl3/ -I/usr/src/linux/include $(INCLUDES) \
	 -Wall -Wunused -Wstrict-prototypes
LDFLAGS = -lpopt -lssl -lcrypto  -lnl-3 -lnl-genl-3 

OBJS = main.o sock.o layer4.o http.o ssl.o
LIB_OBJS = ../lib/timer.o ../lib/scheduler.o ../lib/memory.o ../lib/list.o \
	   ../lib/utils.o ../lib/html.o ../lib/signals.o ../lib/logger.o ../lib/epollwrapper.o

all:	$(BIN)/$(EXEC)
	$(STRIP) $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"

$(BIN)/$(EXEC): $(LIB_OBJS) $(OBJS)
	@set -e; \
	echo "Building $(BIN)/$(EXEC)" && \
	$(CC) -o $(BIN)/$(EXEC) $(LIB_OBJS) $(OBJS) $(LDFLAGS)

clean:
	rm -f core *.o

distclean: clean
	rm -f Makefile $(BIN)/$(EXEC)

uninstall:
	rm -f $(DESTDIR)$(bindir)/$(EXEC)
	rm -f $(DESTDIR)$(mandir)/man1/genhash.1

install:
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(BIN)/$(EXEC) $(DESTDIR)$(bindir)/
	install -d $(DESTDIR)$(mandir)/man1
	install -m 644 ../doc/man/man1/genhash.1 $(DESTDIR)$(mandir)/man1

mrproper: clean distclean
	rm -f config.*

# Code dependencies

main.o: main.c main.h ../lib/utils.h sock.h ../lib/timer.h \
	http.h ssl.h ../lib/scheduler.h ../lib/memory.h
sock.o: sock.c sock.h ../lib/utils.h layer4.h ssl.h main.h \
	../lib/memory.h
layer4.o: layer4.c layer4.h ../lib/scheduler.h ../lib/utils.h \
	main.h ssl.h
http.o: http.c http.h sock.h ../lib/scheduler.h ../lib/utils.h \
	layer4.h main.h ../lib/html.h ../lib/timer.h ../lib/scheduler.h \
	../lib/memory.h
ssl.o: ssl.c ssl.h http.h main.h ../lib/utils.h ../lib/html.h

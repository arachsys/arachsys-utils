CC = gcc
CFLAGS = -Os -Wall
LDFLAGS =

PREFIX =
BINDIR = ${PREFIX}/bin
DESTDIR =

SCRIPTS = fixscriptpaths where which

all: really send-arp ${SCRIPTS}

really: really.c

send-arp: send-arp.c

install: really send-arp ${SCRIPTS}
	mkdir -p ${DESTDIR}${BINDIR}
	install -m 4754 -o root -g staff -s really ${DESTDIR}${BINDIR}
	install -m 0755 send-arp ${SCRIPTS} ${DESTDIR}${BINDIR}

clean:
	rm -f *.o really send-arp

.PHONY: install clean

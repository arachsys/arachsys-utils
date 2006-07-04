CC = gcc
CFLAGS = -Os -Wall
LDFLAGS =

PREFIX =
BINDIR = ${PREFIX}/bin
DESTDIR =

SCRIPTS = fixscriptpaths where which

really: really.c

install: really ${SCRIPTS}
	mkdir -p ${DESTDIR}${BINDIR}
	install -m 4754 -o root -g staff -s really ${DESTDIR}${BINDIR}
	install -m 0755 ${SCRIPTS} ${DESTDIR}${BINDIR}

clean:
	rm -f *.o really

.PHONY: install clean

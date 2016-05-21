PREFIX =
BINDIR = ${PREFIX}/bin
DESTDIR =

CC = gcc
CFLAGS = -Os -Wall -Wextra

BINARIES = nosetuid
SCRIPTS = fixscriptpaths where which
SUIDROOT = privbind really

all: ${BINARIES} ${SCRIPTS} ${SUIDROOT}

clean:
	rm -f -- ${BINARIES} ${SUIDROOT} tags *.o

install: ${BINARIES} ${SUIDROOT}
	mkdir -p ${DESTDIR}${BINDIR}
	install -s ${BINARIES} ${DESTDIR}${BINDIR}
	install ${SCRIPTS} ${DESTDIR}${BINDIR}
	install -g staff -m 4754 -o root -s ${SUIDROOT} ${DESTDIR}${BINDIR}

tags:
	ctags -R

.PHONY: all clean install tags

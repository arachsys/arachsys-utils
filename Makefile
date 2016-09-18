PREFIX =
BINDIR = ${PREFIX}/bin
LIBDIR = ${PREFIX}/lib
DESTDIR =

CC = gcc

ARFLAGS = crs
CFLAGS = -Os -Wall -Wextra
LDFLAGS =

BINARIES = checklocal nosetuid
LIBRARIES = libuserbind.a libwrapbind.so
SCRIPTS = fixscriptpaths where which wrapbind
STAFFSETUID = privbind really
OTHERSETUID = userbind

all: ${BINARIES} ${LIBRARIES} ${SCRIPTS} ${STAFFSETUID} ${OTHERSETUID}

clean:
	rm -f ${BINARIES} ${LIBRARIES} ${STAFFSETUID} ${OTHERSETUID} tags *.o

install: ${BINARIES} ${LIBRARIES} ${SCRIPTS} ${STAFFSETUID} ${OTHERSETUID}
	mkdir -p ${DESTDIR}${BINDIR} ${DESTDIR}${LIBDIR}
	install -s ${BINARIES} ${DESTDIR}${BINDIR}
	install ${SCRIPTS} ${DESTDIR}${BINDIR}
	install -g staff -m 4754 -o root -s ${STAFFSETUID} ${DESTDIR}${BINDIR}
	install -g root -m 4755 -o root -s ${OTHERSETUID} ${DESTDIR}${BINDIR}
	install -m 0644 ${LIBRARIES} ${DESTDIR}${LIBDIR}
	strip --strip-unneeded ${foreach LIBRARY, ${LIBRARIES}, \
		${DESTDIR}${LIBDIR}/${LIBRARY}}

libuserbind.o: CFLAGS += -DHELPER=\"${BINDIR}/userbind\" -fpic
libuserbind.a: libuserbind.a(libuserbind.o)

libwrapbind.o: CFLAGS += -fpic
libwrapbind.so: libuserbind.o libwrapbind.o
	${CC} ${LDFLAGS} -shared -Wl,--defsym,bind=__wrap_bind $^ -ldl -o $@

tags:
	ctags -R

.PHONY: all clean install tags

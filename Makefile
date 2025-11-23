BINDIR := $(PREFIX)/bin
CFLAGS := -O2 -Wall

%:: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -I . -o $@ $(filter %.c,$^)

all: dnsconfig dnsedit userbind

dnsconfig: auth.c dnsconfig.h filter.c scan.[ch] stralloc.h

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 4755 -s dnsconfig $(DESTDIR)$(BINDIR)
	install -m 4755 -s userbind $(DESTDIR)$(BINDIR)
	install dnsedit $(DESTDIR)$(BINDIR)

clean:
	rm -f dnsconfig userbind

.PHONY: all clean install

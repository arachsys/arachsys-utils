BINDIR := $(PREFIX)/bin
CFLAGS := -O2 -Wall

%:: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(filter %.c,$^)

all: dnsconfig dnsedit dnslist dnssort userbind usernetns

dnsconfig: auth.c dnsconfig.h filter.c scan.[ch] stralloc.h

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 4755 -s dnsconfig $(DESTDIR)$(BINDIR)
	install -m 4755 -s dnslist $(DESTDIR)$(BINDIR)
	install -m 4755 -s userbind $(DESTDIR)$(BINDIR)
	install dnsedit dnssort usernetns $(DESTDIR)$(BINDIR)

clean:
	rm -f dnsconfig dnslist userbind

.PHONY: all clean install

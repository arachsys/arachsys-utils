BINDIR := $(PREFIX)/bin
CFLAGS := -O2 -Wall

%:: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(filter %.c,$^)

all: dns-sync guest monitor ifstatd wifiguard

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	install dns-sync guest monitor wifiguard $(DESTDIR)$(BINDIR)
	install -s ifstatd $(DESTDIR)$(BINDIR)

clean:
	rm -f ifstatd

.PHONY: all clean install

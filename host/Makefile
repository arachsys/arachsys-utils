BINDIR := $(PREFIX)/bin

all: dns-sync guest monitor wifiguard

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	install dns-sync guest monitor wifiguard $(DESTDIR)$(BINDIR)

.PHONY: all install

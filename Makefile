BINDIR = bin

SERVER_BINARY = micro-chat-server
CLIENT_BINARY = micro-chat-client

$(BINDIR):
	if [ ! -d $@ ]; then mkdir -p $@; fi

CFLAGS  = -std=c99 -O3 -Wall 
LDFLAGS = -pthread -lulfius

.PHONY: build
build: $(BINDIR)/$(SERVER_BINARY)

$(BINDIR)/$(SERVER_BINARY): clean
	$(CC) -o $(BINDIR)/$@ server/*.c $(LDFLAGS)

$(BINDIR)/$(CLIENT_BINARY): clean
	$(CC) -o $(BINDIR)/$@ *.c $(LDFLAGS)

.PHONY: test
test:
	# unimplemented

.PHONY: clean
clean:
	rm -f bin/*

.PHONY: create-aik clean

CC=clang
CFLAGS=--std=c99 -O0 -ggdb -Wall -pedantic
LDFLAGS=-ltspi

all: quote verify

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

quote: quote.o blobfuncs.o toutf16le.o
	$(CC) $(LDFLAGS) -o $@ $^

verify: verify.o blobfuncs.o toutf16le.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f quote verify *.o

create-aik:
	tpm_mkaik aik.blob aik.pub

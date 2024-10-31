CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra
LDFLAGS=-pthread

.PHONY: all
all: nyuenc

nyuenc: nyuenc.o 
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

nyuenc.o: nyuenc.c 
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.o nyuenc

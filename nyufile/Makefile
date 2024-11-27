CC = gcc
CFLAGS = -g -pedantic -std=gnu17 -Wall -Werror -Wextra
LDFLAGS = -lcrypto

.PHONY: all
all: nyufile

nyufile: nyufile.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

nyufile.o: nyufile.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.o nyufile
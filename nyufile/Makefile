CC = gcc
CFLAGS = -g -pedantic -std=gnu17 -Wall -Werror -Wextra
LDFLAGS = -lcrypto
OPTION = -lm

.PHONY: all
all: nyufile

nyufile: nyufile.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(OPTION)

nyufile.o: nyufile.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.o nyufile
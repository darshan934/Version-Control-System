.PHONY : all clean
all:  WTFServer
clean:
	rm -rf WTFServer main.o
WTFServer : main.o
	/usr/bin/gcc -g -o WTFServer main.o -lcrypto -pthread   `pkg-config --libs glib-2.0` -std=c99

main.o: wtf_server.h main.c ../lib/common.h ../lib/socket_routines.h ../lib/archive_routines2.h
	/usr/bin/gcc -g -c main.c -o main.o `pkg-config --cflags glib-2.0` -std=c99

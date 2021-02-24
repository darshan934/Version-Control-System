.PHONY : all clean
all:  WTF
clean:
	rm -rf WTF main.o
WTF: main.o
	gcc -g -o WTF main.o -lcrypto `pkg-config --libs glib-2.0` -std=c99

main.o: wtf_client.h main.c ../lib/common.h ../lib/socket_routines.h ../lib/archive_routines2.h ../lib/manifest.h
	gcc -g -c main.c -o main.o `pkg-config --cflags glib-2.0`  -std=c99

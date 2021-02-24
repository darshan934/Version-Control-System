.PHONY : all clean
all:  WTFtest
clean:
	rm -rf WTFtest wtf_test.o
WTFtest : wtf_test.o
	/usr/bin/gcc -g -o WTFtest wtf_test.o -lcrypto -pthread   `pkg-config --libs glib-2.0` -std=c99

wtf_test.o: wtf_test.c ../lib/common.h ../lib/socket_routines.h ../lib/archive_routines2.h ../client/wtf_client.h ../server/wtf_server.h
	/usr/bin/gcc -g -c wtf_test.c `pkg-config --cflags glib-2.0` -std=c99

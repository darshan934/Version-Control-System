#ifndef WTF_COMMON_H
#define WTF_COMMON_H


#include<stdio.h>
#include <string.h>
#include<stdlib.h>
#include "socket_routines.h"
#include "archive_routines2.h"
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <openssl/sha.h>

enum ClientMsgType {
	CREATE=1,
	CHECKOUT,
	COMMIT,
	DESTROY,
	MANIFEST, // Get Manfiest
	HISTORY,
	PUSH,
	ROLLBACK,
	GETFILE,
	CURRENTVERSION,
};

enum ServerMsgType {
	CREATEACK=1,
	COMMITACK,
	CHECKOUTACK, // send project and files
	DESTROYACK,
	MANIFESTACK, // send manifest
	HISTORYACK,
	ROLLBACKACK,
	PUSHACK,
	GETFILEACK,
	CURRENTVERSIONACK
	};

struct request_header{
	int message_type;
	int message_length;
};

struct response_header{
	int message_type;
	int message_length;
	int status;
};

const char *MANIFEST_FILE_NAME = ".Manifest";
const char *CONFIGURE_FILE = ".configure";

int min(int a,int b) {  return a> b?  b : a; }
int max(int a,int b) {  return a> b?  a : b; }

int get_file_length(const char *filename){
	struct stat st;
	if(stat(filename,&st)==0)
		return st.st_size;
	return -1;
}

int valid_project(const char *project_name){
	char filename[1024];
	sprintf(filename,"%s/%s",project_name,MANIFEST_FILE_NAME);
	if(access(filename,F_OK)!= -1 )
		return 1;
	return 0;
}

char *strdup(const char *s);

int mkpath(char *dir, mode_t mode)
{
    struct stat sb;

    if (!dir) {
        errno = EINVAL;
        return 1;
    }

    if (!stat(dir, &sb))
        return 0;

    char *tmp = strdup(dir);
    mkpath(dirname(tmp), mode);
    free(tmp);

    mkdir(dir, mode);
}

void print_sha256(const unsigned char *digest){
	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		printf("%02x", digest[i]);
	}
}
int get_sha256(const char *buffer,int len,char *digest){
	SHA256(buffer,len,digest);
}
int get_sha256_for_file(const char *project_name, const char *filename,char *digest){

	char full_path[1024];

	sprintf(full_path,"%s/%s",project_name,filename);
	struct stat st;
	if(stat(full_path, &st)<0){
		return -1;
	}

	char *buf = NULL;
	buf  = malloc(st.st_size);

	if(!buf){
		printf("unable to allocate memory\n");
		return -1;
	}

	FILE *fp;
	fp = fopen(full_path,"r");
	if(fp == NULL){
		printf("unable to open file %s\n",full_path);
		return -1;
	}
	int rc = fread(buf,sizeof(char),st.st_size,fp);

	if ( ferror( fp ) != 0 ) {
		printf("error reading file\n");
		return -1;
	}
	SHA256(buf,st.st_size,digest);
	free(buf);
	return 0;
}



#endif // WTF_COMMON_H

#ifndef WTF_SOCKET_ROUTINES_H
#define WTF_SOCKET_ROUTINES_H
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int send_bytes(int sockfd,const void *buf,int len){
	int rc=0;
	int total=0;
	int to_send=len;
	while( total < len ) {
		rc = write(sockfd,buf+total,len-total);
		if(rc < 0 ){
			break;
		}
		total+=rc;
	}
	//printf("to_sent=%d,sent=%d\n",len,total);
	//for(int i=0;i < len;i++){
 	//   printf("%02x ",(unsigned char)buf[i]);
//	}
	//printf("\n");

	return total;
}

int send_file(int sockfd, const char *filename){

	int length = strlen(filename);

	send_bytes(sockfd,(void *)&length,4);
	send_bytes(sockfd,filename,length);
	//printf("filename=%s,len=%d\n",filename,length);
        int file_fd = open(filename,O_RDONLY);
	if(file_fd == -1){
		printf("unable to send file=%s\n",filename);
		return -1;
	}
	struct stat st;
	stat(filename, &st);
	int sz = st.st_size;
	send_bytes(sockfd,(const char *)&sz,4);
	int rc = sendfile(sockfd,file_fd,NULL,st.st_size);
	//printf("file_size=%d,rc=%d\n",sz,rc);
	if(rc < 0 ){
		printf("unable to sendfile= %s\n",filename);
	}
	return 0;
}

int read_bytes(int fd,void* buffer,int len){
	int offset = 0;
	int read_size=0;
	while(read_size < len && (read_size = read(fd, buffer+offset, len-offset)) > 0) {
		offset+=read_size;
	//	printf("read_size=%d\n",read_size);
	}
//	printf("read bytes=%d,toread=%d\n",offset,len);
//	for(int i=0;i < len;i++){
 //	   printf("%02x ", ((unsigned char *)buffer)[i]);
//	}
//	printf("\n");
	return offset;
}

int read_file(int sockfd,char *outfile,char **buffer,int *buf_len){
	int offset = 0;

	offset+=read_bytes(sockfd,buf_len,sizeof(int));
	offset+=read_bytes(sockfd,outfile,*buf_len);
	offset+=read_bytes(sockfd,buf_len,sizeof(int));
	*buffer = malloc(*buf_len);
	offset+=read_bytes(sockfd,*buffer,*buf_len);
	return offset; //total bytes read from socket
}

#endif

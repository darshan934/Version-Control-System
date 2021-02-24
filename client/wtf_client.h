
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdbool.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/stat.h>
#include<errno.h>
#include <libgen.h>
#include <sys/types.h>
#include <dirent.h>


#include "../lib/common.h"
#include "../lib/manifest.h"
#include "../lib/socket_routines.h"

void print_help() {
    printf( "Usage: WTF command [args] \n");

    printf("commands:\n");
    printf("\nconfigure server \n" );
    printf("\tconfigure\t<ip> <port>\n");
    printf("\nworking on project\n");
    printf("\tcreate\t\t<projectname>\n");
    printf("\tcheckout\t<projectname>\n");
    printf("\tdestroy\t\t<projectname>\n");
    printf("\trollback\t\t<projectname> <version>\n");
    printf("\tcommit\t\t<projectname>\n");
    printf("\thistory\t\t<projectname>\n");
    printf("\tadd\t\t<projectname> <filename>\n");
    printf("\tremove\t\t<projectname> <filename>\n");
    printf("\tpush\t\t<projectname>\n");
    printf("\tupdate\t\t<projectname>\n");
    printf("\tupgrade\t\t<projectname>\n");



}

const char *get_sha256_str(const unsigned char *digest){
	static char buffer[SHA256_DIGEST_LENGTH*2 +1];
	buffer[SHA256_DIGEST_LENGTH*2]='\0';
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(buffer+i*2,"%02x", digest[i]);
	}
	return buffer;
}

struct update_entry {
    char status;
    char filename[512];
    char sha256[SHA256_DIGEST_LENGTH*2+1];
};

const char *COMMIT_FILE = ".Commit";
const char *CONFLICT_FILE = ".Conflict";
const char *UPDATE_FILE = ".Update";
struct IPPort {
    char host[256];
    unsigned short port;
};


int handle_configure(char *ip,char *port){
    FILE *fp = fopen(CONFIGURE_FILE,"w");

    if(fp == NULL){
        printf("unable to open file: %s\n" , CONFIGURE_FILE);
        return -1;
    } else {
        fprintf(fp,"%s %s\n",ip,port);
        fclose(fp);
    }
    return 0;

}

int get_config(struct IPPort *ipport){

    FILE *fp = fopen(CONFIGURE_FILE,"r");
    if(fp == NULL) {
        printf("unable to open .configure file\n");
        return -1;
    }
    char port_str[10];
    fscanf(fp,"%s%s",ipport->host,port_str);
    ipport->port = atoi(port_str);
}

int connect_server(){

    struct IPPort ipport;
    if(!get_config(&ipport)){
        printf("unable to get server IP PORT configuration\n");
        return -1;
    }

    printf("connecting to server host=%s,port=%d\n",ipport.host,ipport.port);


    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ipport.host);
    servaddr.sin_port = htons(ipport.port);
    while(1)
    {
        printf("connecting to server...\n");
        if(connect(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) != 0) {
            printf("connection failed.retrying after 3 seconds\n");
        } else {
            break;// connection succesfull
        }
        sleep(3);
    }
    printf("connection successful\n");
    return sockfd;
}


int write_to_socket(int fd,const char *buf,int length){

    if(fd == -1){
        printf("invalid socket\n");
        return -1;
    }
    int sent_so_far=0;
    while(sent_so_far<length) {
        int sent;
        sent = write(fd,buf,length);
        if(sent == -1){
            printf("error writing to socket\n");
            return -1;
        }
        sent_so_far += sent;
    }

    return sent_so_far;
}


void get_from_server_manifest(int fd, const char *project_name,struct manifest *m) {
    struct request_header header;

    header.message_type = MANIFEST;
    header.message_length = strlen(project_name)+1;

    send_bytes(fd,&header,sizeof(header));
    send_bytes(fd,project_name,header.message_length);

    struct response_header response;
    read_bytes(fd,&response,sizeof(response));

    if(response.status == 0 ){
        int length;
        char filename[512];
        read_bytes(fd,&length,sizeof(length)); //filename length
        read_bytes(fd,filename,length); // filename
        read_bytes(fd,&length,sizeof(length)); //file length
        char *buffer;
        buffer = malloc(length);
        read_bytes(fd,buffer,length); //file
        deserialize_manifest(buffer,m);
        free(buffer);
    }
}

int update_file_from_server(int fd,const char *project_name,const char *filename){
    struct request_header header;
    header.message_type = GETFILE;
    header.message_length = strlen(project_name)+1 + strlen(filename) + 1 + sizeof(int) + sizeof(int);
    send_bytes(fd,&header,sizeof(header));

    int length = strlen(project_name)+1;
    send_bytes(fd,&length,sizeof(int));
    send_bytes(fd,project_name,length);
    length = strlen(filename)+1;
    send_bytes(fd,&length,sizeof(int));
    send_bytes(fd,filename,length);


    struct response_header response;

    read_bytes(fd,&response,sizeof(response));

    if(response.status == 0) {
        read_bytes(fd,&length,sizeof(int)); //filename length
        char *file = malloc(length);
        read_bytes(fd,file,length);

        read_bytes(fd,&length,sizeof(int)); //file size
        char *filecontents = malloc(length);
        read_bytes(fd,filecontents,length);

        char full_path[512];
        sprintf(full_path,"%s/%s",project_name,filename);
        FILE *fp = fopen(full_path,"w");
        if(fp== NULL){
            printf("unable to open file:%s\n",filename);
            free(file);
            free(filecontents);
            return -1;
        }

        fwrite(filecontents,1,length,fp);
        fclose(fp);

        printf("%s file updated\n",filename);

        free(file);
        free(filecontents);
        return 0;

    } else {
        printf("update_file_from_server: error response from server =%d\n",response.status);
        return -1;
    }
}

int receive_file(int fd) {
    int rc;
    int read_size;
    int total_read = 0;
    char buffer[4096];
    read_bytes(fd,buffer,4);
    int filename_len = *(int*)(buffer);

    read_bytes(fd,buffer,filename_len);
    char filename[1024]={'\0'};
    strncpy(filename,buffer,filename_len);
    read_bytes(fd,buffer,4);
    int file_size = *(int*)(buffer);
    mkpath(dirname(strdup(filename)),S_IRWXU);
    int write_fd = open(filename,O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP);
    if(write_fd ==  -1){
        printf("unable to open file=%s\n",filename);
    }
    total_read=0;
    while(total_read < file_size ) {
        read_size = read(fd,buffer,min(file_size-total_read,sizeof(buffer)));
        if(read_size < 0 )
            break;
        if(write_fd!=-1)
            write(write_fd,buffer,read_size);
        total_read+=read_size;
    }

    if(write_fd!=-1)
        close(write_fd);

    rc = extract_file(filename,".");
    if(rc < 0) {
        printf("error extracting archive\n");
    }
    return 0;
}

int receive_project_tar_gz(int fd) {
    int rc;
    size_t buf_size;
    read_bytes(fd,(char *)&buf_size,sizeof(buf_size));
    char *buffer;
    buffer = malloc(buf_size);
    read_bytes(fd,buffer,buf_size);
    rc= extract_from_buffer(buffer,buf_size,".");
    free(buffer);
    return rc;
}

int checkout_project(char *project_name){

    if(valid_project(project_name)){
        printf("project already present\n");
        return -1;
    }
    int fd = connect_server();
    if(fd < 0){
        printf("unable to connect to server\n");
        return -1;
    }
    struct request_header header;
    header.message_type = CHECKOUT;
    header.message_length = strlen(project_name)+1;
    send_bytes(fd,(const char *)&header,sizeof(header));
    int bytes = write_to_socket(fd,project_name,strlen(project_name)+1);
    struct response_header response_header;
    read_bytes(fd,(char *)&response_header,sizeof(response_header));
    if(response_header.message_type == CHECKOUTACK){
        if(response_header.status<0){
            printf("checkout_project: error response from server. status=%d\n",response_header.status);
            return -1;
        }
    }
    return receive_project_tar_gz(fd);
}
int update_project(char *project_name) {
    int rc = 0;
    int fd= connect_server();

    if(fd<0){
        return -1;
    }
    struct manifest server_manifest;
    struct manifest client_manifest;

    get_from_server_manifest(fd,project_name,&server_manifest);
    read_manifest(project_name,&client_manifest);

    char update_file[512];
    sprintf(update_file,"%s/%s",project_name,UPDATE_FILE);
    FILE *fp = fopen(update_file,"w");
    if(fp == NULL){
        printf("unable to open update file =%s\n",update_file);
        free_manifest(&server_manifest);
        free_manifest(&client_manifest);
        return -1;
    }
    if(server_manifest.version == client_manifest.version) {
        printf("nothing to update");
        free_manifest(&server_manifest);
        free_manifest(&client_manifest);
        fclose(fp);
        return -1;
    }
    FILE *conflict_fp = NULL;
    for(int i=0;i < server_manifest.no_of_entries; i++){
        struct file_entry *server_entry = &server_manifest.entries[i];
        struct file_entry *client_entry = find_file_entry(&client_manifest,server_entry->filename);
        if( client_entry == NULL){
            // New entry
            char live_sha256[SHA256_DIGEST_LENGTH];
            get_sha256_for_file(project_name,server_entry->filename,live_sha256);
            fprintf(fp,"A %s %s\n",server_entry->filename,get_sha256_str(live_sha256));
            printf("A %s\n",server_entry->filename);
        } else if(memcmp(client_entry->sha256,server_entry->sha256,SHA256_DIGEST_LENGTH) != 0){
            char live_sha256[SHA256_DIGEST_LENGTH];
            get_sha256_for_file(project_name,server_entry->filename,live_sha256);
            if(memcmp(client_entry->sha256,server_entry->sha256,SHA256_DIGEST_LENGTH) != 0) {
                if(memcmp(live_sha256,client_entry->sha256,SHA256_DIGEST_LENGTH) == 0) {
                    //Modify
                    fprintf(fp,"M %s %s\n",client_entry->filename,get_sha256_str(client_entry->sha256));
                    printf("M %s\n",client_entry->filename);
                } else {
			char conflict_file[512];
			sprintf(conflict_file,"%s/%s",project_name,CONFLICT_FILE);
			conflict_fp = fopen(conflict_file,"a");
			if(conflict_fp == NULL){
				rc= -1;
				goto EXIT;
			}
			fprintf(conflict_fp,"C %s %s\n",client_entry->filename,get_sha256_str(client_entry->sha256));
			fclose(conflict_fp);
			printf("C %s\n",client_entry->filename);

                }
            }
        }
    }
    for(int i=0;i < client_manifest.no_of_entries; i++){
        struct file_entry *client_entry = &client_manifest.entries[i];
        struct file_entry *server_entry= find_file_entry(&server_manifest,client_entry->filename);
        if(server_entry==NULL){
            //Deleted
            fprintf(fp,"D %s %s\n",client_entry->filename,get_sha256_str(client_entry->sha256));
            printf("D %s\n",client_entry->filename);
        }
    }
EXIT:
    fclose(fp);
    free_manifest(&server_manifest);
    free_manifest(&client_manifest);
    printf("update done\n");
    return rc;
}
int upgrade_project(char *project_name){

    int fd = connect_server();

    if(fd <0 ){
        printf("unable to connect to server\n");
        return -1;
    }

    // check if conflict file present. abort upgrade
    char conflict_file[512];
    sprintf(conflict_file,"%s/%s",project_name,CONFLICT_FILE);
    struct stat st;
    if(stat(conflict_file,&st)== 0 ){
        if(st.st_size == 0) {
                unlink(conflict_file);
        } else {
        printf(".Conflict file present. Please resolve the conflict and run update/upgrade again.\n");
        return -1;
        }
    }

    char update_file[512];
    sprintf(update_file,"%s/%s",project_name,UPDATE_FILE);
    FILE *fp = fopen(update_file,"r");

    if(fp == NULL){
        printf("No .Update file found\n");
        return -1;
    }

    struct manifest server_manifest;
    struct manifest client_manifest;

    read_manifest(project_name,&client_manifest);
    get_from_server_manifest(fd,project_name,&server_manifest);


    char line[512];
    struct update_entry update;
    int rc=0;
    while(fgets(line,sizeof(line),fp) != NULL){
        sscanf(line,"%c %s %s",&update.status,update.filename,update.sha256);
        printf("%c %s %s\n",update.status,update.filename,update.sha256);
        if(update.status == 'D'){
            remove_file_from_manifest_buf(&client_manifest,update.filename);
            char remove_file[1024];
            sprintf(remove_file,"%s/%s",project_name,update.filename);
            unlink(remove_file);
        } else if(update.status == 'A'){
            if((rc=update_file_from_server(fd,project_name,update.filename))<0){
                printf("error getting file from server\n");
                break;
            }
            struct file_entry *client_entry = add_file_to_manifest_buf(&client_manifest,project_name,update.filename);
            struct file_entry *server_entry = find_file_entry(&server_manifest,update.filename);
            if(server_entry && client_entry)
                client_entry->version = server_entry->version;
        } else if (update.status == 'M'){
            if( (rc =update_file_from_server(fd,project_name,update.filename) )< 0 ){
                printf("error getting file from server\n");
                break;
            }
            struct file_entry *client_entry = find_file_entry(&client_manifest,update.filename);
            struct file_entry *server_entry = find_file_entry(&server_manifest,update.filename);
            if(client_entry && server_entry){
                client_entry->version =  server_entry->version;
                memcpy(client_entry->sha256 , server_entry->sha256,sizeof(client_entry->sha256));
            }
        }
    }
    fclose(fp);
    if(rc == 0 ){
        client_manifest.version = server_manifest.version;
        write_manifest(project_name,&client_manifest);
        unlink(update_file);
        printf("upgrade succesful\n");
        return 0;
    } else {
        printf("upgrade failed\n");
        return -1;
    }
}
int add_file(const char *project_name,const char *filename){
    if(add_file_to_manifest(project_name,filename)<0){
        printf("error couldnt add file\n");
        return -1;
    } else {
        printf("file added succesfully\n");
        return 0;
    }
}

int remove_file(char *project_name,char *filename){
    if(remove_file_from_manifest(project_name,filename)<0){
        printf("file not found in manifest\n");
        return -1;
    }
    char remove_file[1024];
    sprintf(remove_file,"%s/%s",project_name,filename);
    unlink(remove_file);
    printf("file removed succesfully\n");
    return 0;
}
int commit_project(char *project_name){
    // checks 

    char update_file[512];
    char conflict_file[512];
    char commit_file[512];

    sprintf(commit_file,"%s/%s",project_name,COMMIT_FILE);
    sprintf(update_file,"%s/%s",project_name,UPDATE_FILE);
    sprintf(conflict_file,"%s/%s",project_name,CONFLICT_FILE);

    struct stat sb;
    if(stat(update_file,&sb) ==  0  && sb.st_size > 0 ) {
        printf("Error: non empty update file is present: %s\n",update_file);
        return -1;
    }

    if(stat(conflict_file,&sb) == 0 ){
        printf("Error: conflict file is present: %s \n",conflict_file);
        return -1;
    }
    FILE *fp;
    fp = fopen(commit_file,"w");

    if(fp==NULL){
        printf("Error: unable to create commit file:  %s\n",commit_file);
        return -1;
    }
    int fd = connect_server();
    if(fd < 0){
        printf("connect failed\n");
        return -1;
    }
    struct manifest server_manifest;
    struct manifest client_manifest;
    get_from_server_manifest(fd,project_name,&server_manifest);
    read_manifest(project_name,&client_manifest);

    //  print_manifest(&server_manifest);
    //  print_manifest(&client_manifest);

    if(server_manifest.version != client_manifest.version) {
        printf("Error: manifest version mismatch. update project to get latest manifest/files and try commit again\n");
        printf("server version %d , client version %d\n",server_manifest.version,client_manifest.version);
        return -1;
    }

    for(int i=0;i < client_manifest.no_of_entries; i++){
        struct file_entry *client_entry = &client_manifest.entries[i];
        struct file_entry *server_entry = find_file_entry(&server_manifest,client_entry->filename);
        if(server_entry == NULL){
            // New entry
            char live_sha256[SHA256_DIGEST_LENGTH];
            get_sha256_for_file(project_name,client_entry->filename,live_sha256);
            fprintf(fp,"A %s %s\n",client_entry->filename,get_sha256_str(live_sha256));
            printf("A %s\n",client_entry->filename);
        } else {
            //Modify
            char live_sha256[SHA256_DIGEST_LENGTH];
            get_sha256_for_file(project_name,client_entry->filename,live_sha256); // live hash and client manifest hash
            if(memcmp(live_sha256,client_entry->sha256,SHA256_DIGEST_LENGTH) != 0) {
                fprintf(fp,"M %s %s\n",client_entry->filename,get_sha256_str(server_entry->sha256));
                printf("M %s\n",client_entry->filename);
            }
        }
    }
    for(int i=0;i < server_manifest.no_of_entries; i++){
        struct file_entry *server_entry = &server_manifest.entries[i];
        struct file_entry *client_entry = find_file_entry(&client_manifest,server_entry->filename);
        if(client_entry ==NULL){
            //Deleted
            fprintf(fp,"D %s %s\n",server_entry->filename,get_sha256_str(server_entry->sha256));
            printf("D %s\n",server_entry->filename);
        }
    }

    fclose(fp);
    printf("commit file created\n");


    stat(commit_file,&sb);

    if(sb.st_size == 0){
        printf("no changes made to the local project. nothing to commit\n");
        unlink(commit_file);
        return 0;
    }

    int length = strlen(project_name)+1;
    struct request_header header;
    printf("sending commit file to server\n");
    header.message_type  = COMMIT;
    header.message_length = sizeof(int) + length + sizeof(int) + sb.st_size +sizeof(int) + strlen(commit_file) ;
    send_bytes(fd,&header,sizeof(header));
    send_bytes(fd,&length,sizeof(int));
    send_bytes(fd,project_name,length);
    send_file(fd,commit_file);

    struct response_header response;
    read_bytes(fd,&response,sizeof(response));

    if(response.status == 0){
        printf("commit success\n");
    } else {
        printf("commit failed at server. removing commit file\n");
        unlink(commit_file);
        return -1;
    }
    return 0;
}

int create_project(char *project_name){

    int fd = connect_server();
    struct request_header header;

    header.message_type = CREATE;
    header.message_length = strlen(project_name) +1 ;
    send_bytes(fd,(const char *)&header,sizeof(header));
    send_bytes(fd,project_name,header.message_length);

    struct response_header response_header;
    read_bytes(fd,(char *)&response_header,sizeof(response_header));
    if(response_header.message_type == CREATEACK) {
        if(response_header.status == 0){
            return receive_project_tar_gz(fd);
        } else {
            return -1;
        }
    }
    return -1;
}

int destroy_project(char *project_name){
    int fd = connect_server();
    if(fd < 0)
        return -1;
    struct request_header header;

    header.message_type = DESTROY;
    header.message_length = strlen(project_name) +1 ;
    send_bytes(fd,(const char *)&header,sizeof(header));
    send_bytes(fd,project_name,header.message_length);

    struct response_header response;
    read_bytes(fd,(char *)&response,sizeof(response));
    if(response.message_type == DESTROYACK) {
        if(response.status!=0) {
            printf("project not destroyed \n");
            return -1;
        } else {
            printf("project destroyed succesfully\n");
            return 0;
        }
    }
    return -1;
}

void get_commit_file(const char *project_name,char *filename){
    sprintf(filename,"%s/%s",project_name,COMMIT_FILE);
}
int push_commit(char *project_name){

    int fd = connect_server();

    if(fd<0){
        printf("unable to connect to server\n");
        return -1;
    }

    struct request_header request;
    request.message_type = PUSH;

    char commit_filename[512];
    get_commit_file(project_name,commit_filename);
    int length = get_file_length(commit_filename);
    if( length < 0) {
        return -1;
    }
    request.message_length = 4 + strlen(project_name)+1;
    request.message_length += 4 + strlen(commit_filename) + 4 + length ;

    FILE *fp = fopen(commit_filename,"r");

    if(fp == NULL){
        printf("unable to open commit file = %s\n",commit_filename);
        return -1;
    }
    char line[512];
    while( fgets (line, sizeof(line), fp)!=NULL ) {
        char status;
        char filename[512];
        char full_path[512];
        char sha256[SHA256_DIGEST_LENGTH*2+1];
        sscanf(line,"%c %s %s",&status,filename,sha256);
        //	printf("entry: %c %s %s \n", status,filename,sha256);
        if(status !='D') {
            sprintf(full_path,"%s/%s",project_name,filename);
            length = get_file_length(full_path);
            if(length<0){
                return -1;
            }
            request.message_length += strlen(full_path) + length + 8 ;
        }
    }

    //send header
    send_bytes(fd,&request,sizeof(request));
    length = strlen(project_name) + 1;
    //send project name
    send_bytes(fd,&length,sizeof(int));
    send_bytes(fd,project_name,strlen(project_name)+1);
    // send commit file
    send_file(fd,commit_filename);
    rewind(fp);
    // send files
    while( fgets (line, sizeof(line), fp)!=NULL ) {
        char status;
        char filename[512];
        char full_path[512];
        char sha256[SHA256_DIGEST_LENGTH*2+1];
        sscanf(line,"%c %s %s",&status,filename,sha256);
        if(status!='D') {
            sprintf(full_path,"%s/%s",project_name,filename);
            send_file(fd,full_path);
        }
    }

    fclose(fp);
    printf("commit pushed\n");

    struct response_header response;

    read_bytes(fd,&response,sizeof(response));

    if(response.status == 0){
        // response should follow new commit file
        int length;
        char filename[512];
        read_bytes(fd,&length,sizeof(length)); //filename length
        read_bytes(fd,filename,length); // filename
        read_bytes(fd,&length,sizeof(length)); //file length
        char *buffer;
        buffer = malloc(length);
        read_bytes(fd,buffer,length); //file
        struct manifest m;
        deserialize_manifest(buffer,&m);
        write_manifest(project_name,&m);
        free(buffer);
        unlink(commit_filename);
        printf("commit push accepted by server succesfully\n");
        return 0;
    } else {
        printf("commit push failed\n");
        return -1;
    }
    return -1;
}

int valid_config(){
    if( access( CONFIGURE_FILE , F_OK ) != -1) {
        return 1;
    }
    return 0;
}

int handle_rollback(const char *project,int version) {
    int fd = connect_server();
    if(fd<0){
        return -1;
    }
    int length = strlen(project)+1;
    struct request_header request;
    request.message_type = ROLLBACK;
    request.message_length = sizeof(int) + length + sizeof(int) ;
    send_bytes(fd,&request,sizeof(request));
    send_bytes(fd,&length,sizeof(int));
    send_bytes(fd,project,length);
    send_bytes(fd,&version,sizeof(int));
    struct response_header response;
    read_bytes(fd,&response,sizeof(response));
    if(response.status == 0 ){
        printf("rollback succesfull at server\n");
        return 0;
    } else {
        printf("rollback failed at server\n");
        return -1;
    }
}

int handle_currentversion(const char *project_name){
    int fd = connect_server();
    if(fd<0){
        return -1;
    }
    int length = strlen(project_name)+1;
    struct request_header request;
    request.message_type = CURRENTVERSION;
    request.message_length = sizeof(int) + length;
    send_bytes(fd,&request,sizeof(request));
    send_bytes(fd,&length,sizeof(int));
    send_bytes(fd,project_name,length);
    struct response_header response;
    read_bytes(fd,&response,sizeof(response));
    if(response.status == 0 ){
        int length;
        char filename[512];
        read_bytes(fd,&length,sizeof(length)); //filename length
        read_bytes(fd,filename,length); // filename
        read_bytes(fd,&length,sizeof(length)); //file length
        char *buffer;
        buffer = malloc(length);
        read_bytes(fd,buffer,length); //file
        struct manifest m;
        deserialize_manifest(buffer,&m);
        printf("CURRENT VERSION AT SERVER:\n");
        print_manifest(&m);
        free_manifest(&m);
        free(buffer);
        return 0;
    } else {
        printf("currentversion failed at server\n");
        return -1;
    }
  return -1;
}


int handle_history(const char *project_name){
    int fd = connect_server();
    if(fd<0){
        return -1;
    }
    int length = strlen(project_name)+1;
    struct request_header request;
    request.message_type = HISTORY;
    request.message_length = sizeof(int) + length;
    send_bytes(fd,&request,sizeof(request));
    send_bytes(fd,&length,sizeof(int));
    send_bytes(fd,project_name,length);
    struct response_header response;
    read_bytes(fd,&response,sizeof(response));
    if(response.status == 0 ){
        int length;
        char filename[512];
        read_bytes(fd,&length,sizeof(length)); //filename length
        read_bytes(fd,filename,length); // filename
        read_bytes(fd,&length,sizeof(length)); //file length
        char *buffer;
        buffer = malloc(length);
        read_bytes(fd,buffer,length); //file
        printf("HISTORY:\n");
        printf("%.*s\n",length,buffer);
        free(buffer);
        return 0;
    } else {
        printf("get history failed at server\n");
        return -1;
    }
    return -1;
}
int wtf_client(int argc,char **argv)
{


    if(argc < 3) {
        print_help();
        return -1;
    }

    char *command = argv[1];


    // commands in alphabetical order
    if(strcmp(command,"add") == 0 ) { // done
        char *project_name = argv[2];
        char *filename = argv[3];
        if(!valid_project(project_name)) {
            printf("not valid project. %s file not present\n",MANIFEST_FILE_NAME);
            return -1;
        }
        int rc = add_file(project_name,filename);

        struct manifest m;
        if(read_manifest(project_name,&m)==0){
            print_manifest(&m);
            free_manifest(&m);
        }
        return rc;
    } else if(strcmp(command,"checkout") == 0 ) { //done
        char *project_name = argv[2];
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        return checkout_project(project_name);
    } else if(strcmp(command,"configure") == 0 ) { // done
        if(argc < 4) {
            print_help();
            return -1;
        }
        char *ip = argv[2];
        char *port = argv[3];
        return handle_configure(ip,port);
    } else if(strcmp(command,"commit") == 0 ) { // done
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project_name = argv[2];
        if(!valid_project(project_name)) {
            printf("not valid project. %s file not present\n",MANIFEST_FILE_NAME);
            return -1;
        }
        int rc = commit_project(project_name);
        struct manifest m;
        if(read_manifest(project_name,&m)==0){
            print_manifest(&m);
            free_manifest(&m);
        }
        return rc;
    } else if(strcmp(command,"create")  == 0 ) { // done
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project_name = argv[2];
        return create_project(project_name);
    } else if(strcmp(command,"currentversion") == 0 ) { // done
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project_name = argv[2];
        return handle_currentversion(project_name);
    } else if(strcmp(command,"destroy") == 0 ) { // done
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project_name = argv[2];
        return destroy_project(project_name);
    } else if(strcmp(command,"history") == 0 ) { // done
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project_name = argv[2];
        return handle_history(project_name);
    } else if(strcmp(command,"push")  == 0 ) { // done
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project_name = argv[2];
        if(!valid_project(project_name)) {
            printf("not valid project. %s file not present\n",MANIFEST_FILE_NAME);
            return -1;
        }
        return push_commit(project_name);
    } else if(strcmp(command,"remove") == 0 ) { // done
        char *project_name = argv[2];
        char *filename = argv[3];
        int rc = remove_file(project_name,filename);
        struct manifest m;
        if(read_manifest(project_name,&m)==0){
            print_manifest(&m);
            free_manifest(&m);
        }
        return rc;
    } else if(strcmp(command,"rollback") == 0 ) { // done
        if(argc < 4) {
                print_help();
                return -1;
        }
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project = argv[2];
        int version = atoi(argv[3]);
        if(version>0){
            return handle_rollback(project,version);
        }
    } else if(strcmp(command,"show") == 0 ) { // done
        char *project_name = argv[2];
        if(!valid_project(project_name)) {
            printf("not valid project. %s file not present\n",MANIFEST_FILE_NAME);
            return -1;
        }
        struct manifest m;
        if(read_manifest(project_name,&m)==0){
            print_manifest(&m);
            free_manifest(&m);
        } else {
            return -1;
        }
    } else if(strcmp(command,"update") == 0 ) {  // done
        char *project_name = argv[2];
        if(!valid_project(project_name)) {
            printf("not valid project. %s file not present\n",MANIFEST_FILE_NAME);
            return -1;
        }
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        return update_project(project_name);
    } else if(strcmp(command,"upgrade") == 0 ) { // done
        if(!valid_config()) {
            printf("server settings not configured. run configure command\n");
            return -1;
        }
        char *project_name = argv[2];
        if(!valid_project(project_name)) {
            printf("not valid project. %s file not present\n",MANIFEST_FILE_NAME);
            return -1;
        }
        return upgrade_project(project_name);
    }

    return 0;
}

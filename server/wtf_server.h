#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <glib.h>

#include "../lib/common.h"
#include "../lib/manifest.h"
#include "../lib/socket_routines.h"

const char *PROJECT_DIR = "projects";
const char *ARCHIVE_DIR = "archives";
const char *COMMIT_DIR  = "commits";
const char *HISTORY_FILENAME = ".history";


#define MAX_PROJECT_MUTEXES 200

struct commit_entry {
    char status;
    char filename[512];
    char sha256[SHA256_DIGEST_LENGTH*2+1];
};

pthread_mutex_t mutexes[MAX_PROJECT_MUTEXES]; // max projects

static int g_next_mutex_id=0;

GHashTable *g_hash_table = NULL;

pthread_mutex_t * get_mutex(const char *project_name){
    pthread_mutex_t *mutex = g_hash_table_lookup(g_hash_table,project_name);
    if(mutex == NULL) {
        g_hash_table_insert (g_hash_table,g_strdup(project_name), &mutexes[g_next_mutex_id]);
        return &mutexes[g_next_mutex_id++]; // increment the mutex id after insert
    } else {
        return mutex;
    }
}


void lock_project(const char *project_name){
    printf("locking project=%s\n",project_name);
    pthread_mutex_lock(get_mutex(project_name));
}

void unlock_project(const char *project_name){
    printf("unlocking project=%s\n",project_name);
    pthread_mutex_unlock(get_mutex(project_name));
}

int send_project_tarzipped(int fd, const char *project_name){

    char manifest_path[512];
    sprintf(manifest_path,"%s/%s/%s",PROJECT_DIR,project_name,MANIFEST_FILE_NAME);
    struct manifest m;
    char project_path[512];
    sprintf(project_path,"%s/%s",PROJECT_DIR,project_name);
    int rc = read_manifest(project_path,&m);
    if(rc<0){
        return -1;
    }

    int buf_size = 200;  // min tar size .
    struct stat statbuf;
    if(stat(manifest_path,&statbuf)<0)
        return -1;

    buf_size += statbuf.st_size;
    int num_files = m.no_of_entries+1;
    char **files = malloc(sizeof(char *)*(num_files));
    files[0] = strdup(manifest_path+strlen(PROJECT_DIR)+1);

    for(int i=0;i<m.no_of_entries;i++){
        files[i+1] = malloc(strlen(project_name)+strlen(m.entries[i].filename)+2);
        sprintf(files[i+1],"%s/%s",project_name,m.entries[i].filename);
        stat(files[i+1],&statbuf);
        buf_size+=statbuf.st_size;
    }
    char *buffer;
    buffer = malloc(buf_size); //buf_size is max possible size
    long written_size = archive_to_buffer(num_files,PROJECT_DIR,files,buffer,buf_size);
    if(rc<0){
        printf("error creating archive\n");
        goto EXIT;
    }
    send_bytes(fd,(const char *)&written_size,sizeof(written_size));
    rc = send_bytes(fd,buffer,written_size);

EXIT:
    free(buffer);
    for(int i=0;i<m.no_of_entries+1;i++){
        free(files[i]);
    }
    free(files);


    if(rc <0){
        return -1;
    }

    return 0;
}

int server_handle_checkout(int fd, const char *buf,int len)
{
    printf("handling checkout\n");
    const char *project_name = buf;
    struct response_header response;
    response.message_type = CHECKOUTACK;
    response.message_length = 0;
    char project_path[512];
    sprintf(project_path,"%s/%s",PROJECT_DIR,project_name);
    if(!valid_project(project_path)){
        response.status = -1;
    } else {
        response.status = 0;
    }
    send_bytes(fd,(const char *)&response,sizeof(response));
    if(response.status==0) {
        lock_project(project_name);
        send_project_tarzipped(fd,project_name);
        unlock_project(project_name);
    }
}

int server_create_project(int fd, const char *project_name)
{
    char project_path[512];
    sprintf(project_path,"%s/%s",PROJECT_DIR,project_name);
    DIR *dir = opendir(project_path);

    if(dir){
        printf("project directory already exists\n");
        closedir(dir);
        return -1;
    } else {
        mkpath(project_path,S_IRWXU|S_IRWXG|S_IROTH);
        char filename[256];
        sprintf(filename,"%s/%s/%s",PROJECT_DIR,project_name,MANIFEST_FILE_NAME);
        int rc = creat(filename,S_IRUSR|S_IWUSR|S_IRGRP);
        if(rc == -1){
            printf("unable to create %s file\n",filename);
            return -1;
        } else {
            struct manifest m;
            m.version=1;
            m.no_of_entries=0;
            write_manifest(project_path,&m);
            char history_file[512]; //history file
            sprintf(history_file,"%s/%s/%s",PROJECT_DIR,project_name,HISTORY_FILENAME);
            FILE *history_fp = fopen(history_file,"a");
            if(history_fp){
                fprintf(history_fp,"INITIAL VERSION : %d\n",m.version );
                fprintf(history_fp,"____________________________________________\n\n");
                fclose(history_fp);
            }
            printf("Project created succesfully\n");
        }
    }

    return 0;
}

int server_handle_create(int fd,const char *buffer,int buf_size) {
    printf("create project\n");
    const char *project_name= buffer;
    int rc = server_create_project(fd, project_name);
    struct response_header header;
    if(rc < 0) {
        header.message_type = CREATEACK;
        header.message_length = 0;
        header.status =-1;
        send_bytes(fd,&header,sizeof(header));
    } else {
        header.message_type = CREATEACK;
        header.message_length = 0;
        header.status = 0;
        send_bytes(fd,&header,sizeof(header));
        send_project_tarzipped(fd,project_name);
    }
}

int remove_dir(const char *path){

    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d) {
        struct dirent *p;

        r = 0;
        while (!r && (p=readdir(d))) {
            int r2 = -1;
            char *buf;
            size_t len;

            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
                continue;

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf) {
                struct stat statbuf;

                snprintf(buf, len, "%s/%s", path, p->d_name);
                if (!stat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode))
                        r2 = remove_dir(buf);
                    else
                        r2 = unlink(buf);
                }
                free(buf);
            }
            r = r2;
        }
        closedir(d);
    }

    if (!r)
        r = rmdir(path);

    return r;
}

int remove_project(const char *project_name)
{
    int rc = -1;
    char project_path[512];
    sprintf(project_path,"%s/%s",PROJECT_DIR,project_name);
    if(valid_project(project_path)){
        rc = remove_dir(project_name);
        char archive_dir[512];
        sprintf(archive_dir,"%s/%s",ARCHIVE_DIR,project_name);
        printf("archive dir =%s\n",archive_dir);
        remove_dir(archive_dir);
    } else {
        printf("project not found: %s\n", project_name);
    }
    return rc;
}

int server_handle_destroy(int fd,const char *buffer,int buf_size) {
    printf("destroy project=%s\n",buffer);
    const char *project_name = buffer;
    lock_project(project_name);
    int rc= remove_project(project_name);
    unlock_project(project_name);
    struct response_header header;
    header.message_type = DESTROYACK;
    header.message_length = 0;
    header.status = rc;
    send_bytes(fd,&header,sizeof(header));
}

int server_handle_manifest(int fd,const char *buffer,int buf_size) {
    printf("handle manifest\n");
    const char *project_name = buffer;
    char manifest_file[512];
    sprintf(manifest_file,"%s/%s/%s",PROJECT_DIR,project_name,MANIFEST_FILE_NAME);
    printf("sending manifest file = %s\n",manifest_file);
    lock_project(project_name);
    struct response_header header;
    header.message_type = MANIFEST;
    header.message_length=0;
    header.status = 0;
    send_bytes(fd,&header,sizeof(header));
    send_file(fd,manifest_file);
    unlock_project(project_name);
    return buf_size;
}

int rollback_project(const char *project_name,int version) {

    struct manifest m;
    char project_path[512];
    sprintf(project_path,"%s/%s",PROJECT_DIR,project_name);
    int rc = read_manifest(project_path,&m);
    if(rc < 0){
        return rc;
    }

    if(version >= m.version){
        return -1;
    }
    char tmp_dir[512];
    sprintf(tmp_dir,"%s/%s.bak",PROJECT_DIR,project_name);
    rename(project_path,tmp_dir);
    char archive_file[512];
    sprintf(archive_file,"%s/%s/%d.tar.gz",ARCHIVE_DIR,project_name,version);
   // printf("extracting archive file = %s\n",archive_file);
    if((rc = access(archive_file,F_OK)) == -1  ){
        rename(tmp_dir,project_path);//undo rename dir
        free_manifest(&m);
        return -1;
    }
    rc = extract_file(archive_file,PROJECT_DIR);
    if(rc < 0){
        rename(tmp_dir,project_path);//undo rename dir
    } else {
        remove_dir(tmp_dir); // remove tmp dir
        //remove all version archive files newer the rollback version
        for(int i=version;i<m.version;i++){
            sprintf(archive_file,"%s/%s/%d.tar.gz",ARCHIVE_DIR,project_name,i);
     //       printf("removing archive file = %s \n",archive_file);
            unlink(archive_file);
        }
    }
    free_manifest(&m);
    return rc;
}

int server_handle_rollback(int fd,const char *buffer,int buf_size) {
    printf("handle rollback\n");
    int offset=0;
    int len;
    len = *(int *)(buffer+offset); // project name length
    offset+=sizeof(int);

    const char *project_name = buffer+offset; //project name
    offset+= len;

    int version = *(int *)(buffer+offset); //version

    lock_project(project_name);
    int rc = rollback_project(project_name,version);
    unlock_project(project_name);
    struct response_header response;
    response.message_type = ROLLBACKACK;
    response.message_length = 0;
    response.status = rc;
    send_bytes(fd,&response,sizeof(response));
}

int server_handle_history(int fd,const char *buffer,int buf_size) {
    printf("handle history\n");
    int offset=0;
    int len;
    len = *(int *)(buffer+offset); // project name length
    offset+=sizeof(int);

    const char *project_name = buffer+offset;
    offset+= len;

    char full_path[512];
    sprintf(full_path,"%s/%s/%s",PROJECT_DIR ,project_name,HISTORY_FILENAME);
    printf("sending file = %s\n",full_path);
    struct response_header header;
    header.message_type = GETFILEACK;
    header.message_length=0;
    header.status = 0;
    send_bytes(fd,&header,sizeof(header));
    send_file(fd,full_path);
    return buf_size;
}

int archive_project(const char *project_name){
    char manifest_path[512];
    sprintf(manifest_path,"%s/%s/%s",PROJECT_DIR,project_name,MANIFEST_FILE_NAME);
    struct manifest m;
    char project_path[512];
    sprintf(project_path,"%s/%s",PROJECT_DIR,project_name);
    int rc = read_manifest(project_path,&m);

    if(rc<0){
        return rc;
    }

    char history_path[512];
    sprintf(history_path,"%s/%s",project_name,HISTORY_FILENAME);
    struct stat statbuf;
    stat(manifest_path,&statbuf);

    int no_of_files = m.no_of_entries+2;
    char **files;
    files = malloc(sizeof(char*)*no_of_files);
    files[0] = strdup(manifest_path+strlen(PROJECT_DIR)+1);
    files[1] = strdup(history_path); // we need to archive history file too
    for(int i=0;i<m.no_of_entries;i++){
        files[i+2] = malloc(strlen(project_name)+strlen(m.entries[i].filename)+2);
        sprintf(files[i+2],"%s/%s",project_name,m.entries[i].filename);
    }
    char archive_dir[256];
    char archive_file[512];

    sprintf(archive_dir,"%s/%s",ARCHIVE_DIR,project_name);
    mkpath(archive_dir,S_IRWXU);

    sprintf(archive_file,"%s/%d.tar.gz",archive_dir,m.version);
    printf("archive file=%s\n",archive_file);
    long written_size = archive_to_file(archive_file,PROJECT_DIR,no_of_files,files);
    if(written_size<0){
        printf("error creating archive\n");
    }
    free_manifest(&m);
    for(int i=0;i<m.no_of_entries+1;i++){
        free(files[i]);
    }
    free(files);
    if(rc <0){
        return -1;
    }

    return 0;
}

int valid_commit_file(const char *project_name,const char *commit_contents,int length){
    int rc = -1;
    char commit_dir[512];
    sprintf(commit_dir,"%s/%s",COMMIT_DIR,project_name);
    DIR *dir = opendir(commit_dir);
    struct dirent *entry;
    if(dir == NULL)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char filename[1024];
        sprintf(filename,"%s/%s",commit_dir,entry->d_name);
        struct stat st;
        if(stat(filename,&st)== 0 && !S_ISDIR(st.st_mode)) {
            if(st.st_size ==length) {
                FILE *fp = fopen(filename,"r");
                char *buffer = malloc(st.st_size);
                if(buffer){
                    fread(buffer,1,st.st_size,fp);
                    if(memcmp(commit_contents,buffer,length) ==0) {
                        fclose(fp);
                        closedir(dir);
                        free(buffer);
                        return 0; // commit file matched
                    }
                    free(buffer);
                }
                fclose(fp);
            }
        }
    }

    closedir(dir);
    return rc;
}

int server_handle_push(int fd,char *buffer,int buf_size) {

    // archive old version of the project. increment project version and make updates of clients to project
    printf("handle push\n");
    int rc=0;
    int offset=0;
    int len;

    len = *(int *)(buffer+offset);
    offset+= sizeof(int); // project name length

    char *project_name = buffer + offset;
    offset += len;

    //lock project
    lock_project(project_name);

    //commit file
    len = *(int *)(buffer+offset); // name length
    offset+=sizeof(int);

    offset+=len; // commitfile name

    int file_size = *(int *)(buffer+offset); // file size
    offset+=sizeof(int);

    char *commit_contents = buffer+offset;
    int read=0;
    int total=0;
    char *line = commit_contents;
    struct commit_entry commit[500]; // max commit entries
    int no_of_commit_files=0;
    int i=0;
    // update project with new files
    struct manifest m;
    char project_path[512];
    sprintf(project_path,"%s/%s",PROJECT_DIR,project_name);
    rc = read_manifest(project_path,&m);
    while(line  && line-commit_contents < file_size){
        sscanf(line, "%c %s %s",&commit[i].status,commit[i].filename,commit[i].sha256);
        printf("entry: %c %s %s \n", commit[i].status,commit[i].filename,commit[i].sha256);
        if(commit[i].status == 'D'){
            char full_path[1024];
            sprintf(full_path,"%s/%s/%s",PROJECT_DIR,project_name,commit[i].filename);
            printf("removing file =%s\n",full_path);
            unlink(full_path);
            remove_file_from_manifest_buf(&m,commit[i].filename);
        }
        i++;
        line = memchr(line,'\n', file_size- (line - commit_contents));
        if(line)
            ++line;//skip new line

    }
    offset+=file_size;
    //validate commit file


    if(valid_commit_file(project_name,commit_contents,file_size)<0){
        printf("commit file not matched with any previously sent commit files\n");
        return buf_size;
    }




    no_of_commit_files = i;

    //archive current project
    archive_project(project_name);
    while(offset < buf_size){
        len = *(int *)(buffer+offset); // filename length
        offset+=sizeof(int);

        char *file = buffer+offset;
        offset+=len;

        char full_path[1024];
        memset(full_path,0,sizeof(full_path));
        sprintf(full_path,"%s/",PROJECT_DIR);
        memcpy(full_path+strlen(PROJECT_DIR)+1,file,len);
        len = *(int *)(buffer+offset); // file size
        offset+=sizeof(int);
        FILE *fp = fopen(full_path,"w");
        if(fp  == NULL){
            printf("error opening file=%s\n",full_path);
            rc = -1;
            goto EXIT;
        }
        fwrite(buffer+offset,1,len,fp);
        fclose(fp);
        struct file_entry *entry = find_file_entry(&m,full_path+strlen(PROJECT_DIR)+strlen(project_name)+2);
        if(entry){
            ++entry->version;
            get_sha256_for_file(project_path,entry->filename,entry->sha256);
        } else {
            add_file_to_manifest_buf(&m,project_path,full_path+strlen(PROJECT_DIR)+strlen(project_name)+2);
        }
        offset+=len;
    }
    ++m.version;


    char history_file[512]; //history file
    sprintf(history_file,"%s/%s/%s",PROJECT_DIR,project_name,HISTORY_FILENAME);
    FILE *history_fp = fopen(history_file,"a");
    if(history_fp!=NULL){
        fprintf(history_fp,"VERSION : %d\n",m.version );
        fwrite(commit_contents,1,file_size, history_fp);
        fprintf(history_fp,"____________________________________________\n");
        fclose(history_fp);
    }

    write_manifest(project_path,&m);
    /*
    char manifest_buffer[2*1024*1024]; // 2mb max file size for manifest
    int bytes = serialize_manifest(&m,manifest_buffer);
    char manifest_file[1024];
    sprintf(manifest_file,"%s/%s/%s",PROJECT_DIR,project_name,MANIFEST_FILE_NAME);
    FILE *fp = fopen(manifest_file,"w");
    fwrite(manifest_buffer,1,bytes,fp);
    fclose(fp);
    */
EXIT:
    unlock_project(project_name); // all done unlock the project

    struct response_header response;
    response.message_type = PUSHACK;
    response.message_length = 0;
    response.status = rc;
    send_bytes(fd,&response,sizeof(response));
    if(rc == 0) {
        char manifest_file[1024];
        sprintf(manifest_file,"%s/%s/%s",PROJECT_DIR,project_name,MANIFEST_FILE_NAME);
        send_file(fd,manifest_file);
    }
    char commit_dir[512];
    sprintf(commit_dir,"%s/%s",COMMIT_DIR,project_name);
    //remove project commit dir
    remove_dir(commit_dir);
}
int get_next_commit_num(const char *project){

    char dir_path[1024];

    sprintf(dir_path,"%s/%s",COMMIT_DIR,project);
    DIR *dir;
    struct dirent *entry;
    if (!(dir = opendir(dir_path)))
        return -1;
    int max_num=0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        int num = atoi(entry->d_name);
        if(num > max_num)
            max_num = num;
    }
    closedir(dir);

    return max_num+1;
}

int server_handle_getfile(int fd, const char *buffer,int buf_size){
    int offset=0;
    int len;
    len = *(int *)(buffer+offset); // project name length
    offset+=sizeof(int);

    const char *project_name = buffer+offset;
    offset+= len;

    len = *(int *)(buffer+offset); // filename length
    offset+=sizeof(int);
    const char *filename = buffer + offset;
    char full_path[512];
    sprintf(full_path,"%s/%s/%s",PROJECT_DIR,project_name,filename);
    struct response_header header;
    header.message_type = GETFILEACK;
    header.message_length=0;
    header.status = 0;
    send_bytes(fd,&header,sizeof(header));
    lock_project(project_name);
    send_file(fd,full_path);
    unlock_project(project_name);
    return buf_size;

}
int server_handle_commit(int fd,const char *buffer,int buf_size) {

    int rc = -1;
    int  offset=0;
    int len = *(int *)(buffer+offset); // project name length
    offset+=sizeof(int);


    const char *project_name = buffer + offset;

    offset+=strlen(project_name)+1; // project name

    len = *(int *)(buffer+offset);
    offset+=sizeof(int); // filename length

    offset+= len; // filename

    len = *(int *)(buffer+offset); // file length
    offset+=sizeof(int);

    char project_commit_dir[512];
    sprintf(project_commit_dir,"%s/%s",COMMIT_DIR,project_name);
    mkpath(project_commit_dir,S_IRWXU);
    int next_commit_num = get_next_commit_num(project_name);
    char filename[256];
    sprintf(filename,"%s/%d",project_commit_dir,next_commit_num);
    FILE *fp = fopen(filename,"w");
    if(fp == NULL) {
        printf("unable to create commit file=%s\n",filename);
        rc = -1;
        goto EXIT;
    }
    fwrite(buffer+offset,1,len,fp); // write to file
    fclose(fp);
    rc = 0;//success
EXIT:
    printf("commit completed\n");
    struct response_header response;
    response.message_type = COMMITACK;
    response.message_length=0;
    response.status = rc;
    send_bytes(fd,&response,sizeof(response));
    return buf_size;
}


int server_handle_currentversion(int fd,char *buffer,int buf_size) {
    int offset =0;


    //len
    offset+= sizeof(int); // skip length .we will get null terminated string

    char *project_name = buffer + offset;

    struct response_header response;
    response.message_type = CURRENTVERSIONACK;
    response.message_length = 0;
    int rc;
    char manifest_file[512];
    sprintf(manifest_file,"%s/%s/%s",PROJECT_DIR,project_name,MANIFEST_FILE_NAME);
    rc = access(manifest_file,F_OK);
    response.status = rc;
    send_bytes(fd,&response,sizeof(response)); // response header
    if(rc == 0){
        send_file(fd,manifest_file);
    }
    return buf_size;
}


int server_handle_message(int fd,int msg_type, char *buffer,int buf_size)
{
    switch(msg_type){
        case CHECKOUT: {
                           server_handle_checkout(fd, buffer,buf_size); // DONE
                           break;
                       }
        case COMMIT: {
                         server_handle_commit(fd,buffer,buf_size); // DONE
                         break;
                     }
        case DESTROY: {
                          server_handle_destroy(fd, buffer,buf_size); // DONE
                          break;
                      }
        case PUSH:
                      {
                          server_handle_push(fd,buffer,buf_size); // done
                          break;
                      }
        case GETFILE: {
                          server_handle_getfile(fd,buffer,buf_size); //done
                          break;
                      }
        case MANIFEST: {
                           server_handle_manifest(fd, buffer,buf_size); // DONE
                           break;
                       }
        case HISTORY: {
                          server_handle_history(fd, buffer,buf_size); // DONE
                          break;
                      }
        case CURRENTVERSION: {
                                 server_handle_currentversion(fd, buffer,buf_size); // DONE
                                 break;
                             }
        case ROLLBACK: {
                           server_handle_rollback(fd, buffer,buf_size); // DONE
                           break;
                       }
        case CREATE: {
                         server_handle_create(fd, buffer,buf_size); // DONE
                         break;
                     }
        default:
                     printf("unknown message type =%d\n",msg_type);
    }
    return buf_size;
}

void *client_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char *message , client_message[1024];

    //Receive a message from client
    int total_read = 0;
    struct request_header header;
    int rc;
    while(1){
        rc = read_bytes(sock,(char *)&header,sizeof(header));
        if(rc <=  0) {
            break;
        }
 //       printf("message_type=%d,message_length=%d\n",header.message_type,header.message_length);
        char *buffer = malloc(header.message_length);
        rc = read_bytes(sock,buffer,header.message_length);
        if(rc <= 0 ){
            break;
        }
        server_handle_message(sock,header.message_type,buffer,header.message_length);
        free(buffer);
    }

    printf("Client disconnected\n");
    close(sock);

    return 0;
}

void start_server(int port)
{
    int sock_fd, client_sock , c;
    struct sockaddr_in server , client;

    printf("starting WTF server\n");
    //Create socket
    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1)
    {
        printf("Could not create socket");
    }



    for(int i=0;i < 100;i++){
        if (pthread_mutex_init(&mutexes[i], NULL) != 0) {
            printf("\n mutex init has failed\n");
            return;
        }
    }
    g_hash_table = g_hash_table_new (g_str_hash, g_str_equal);


    int reuse=1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) // not to wait during restarts to bind to port.
        printf("setsockopt(SO_REUSEADDR) failed");
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( port);


    if( bind(sock_fd,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        printf("bind failed. Error");
        return;
    }


    if(listen(sock_fd, 10) < 0){ // backlog queue = 10
        printf("cannot listen on port\n");

    }
    printf("server listening..\n");

    //Accept and incoming connection
    printf("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_in);
    pthread_t thread_id;

    while(1) {
        client_sock = accept(sock_fd, (struct sockaddr *)&client, (socklen_t*)&c);
        printf("Connection accepted\n");
        if (client_sock < 0)
        {
            perror("accept failed");
        } else {

            if( pthread_create( &thread_id , NULL ,  client_handler , (void*) &client_sock) < 0)
            {
                perror("could not create thread");
                return;
            }
            printf("client connected.. handling request\n");
            pthread_detach(thread_id);
        }
    }
    for(int i=0;i < 100;i++){
        pthread_mutex_destroy(&mutexes[i]);
    }
}

int wtf_server(int argc,char **argv)
{
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working dir: %s\n", cwd);
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(1);
    }
    char *end;
    int port = strtol(argv[1],&end,10);
    printf("server starting on port:  %d\n",port);
    if(port>0) {
        start_server(port);
    }
    return 0;
}

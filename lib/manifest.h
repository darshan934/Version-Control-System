#ifndef WTF_MANIFEST_H
#define WTF_MANIFEST_H
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>


struct file_entry {
	int version;
	char sha256[SHA256_DIGEST_LENGTH];
	char *filename;
};


struct manifest {
	int version;
	int no_of_entries;
	struct file_entry *entries;
};


struct file_entry * find_file_entry(const struct manifest *m, char *filename){
	for(int i=0;i < m->no_of_entries;i++){
		if(strcmp(m->entries[i].filename,filename) == 0){
			return &m->entries[i];
		}
	}
	return NULL;
}

int read_manifest(const char *project_name, struct manifest *m){
	char filename[1000];
	sprintf(filename,"%s/%s",project_name,MANIFEST_FILE_NAME);
	FILE *fp = fopen(filename,"r");
	if(fp == NULL){
           printf("unable to open %s file\n",filename);
	   return -1;
	}

	fread(&m->version,1,sizeof(int),fp);
	fread(&m->no_of_entries,1,sizeof(int),fp);
	m->entries=NULL;
	if(m->no_of_entries > 0)
		m->entries = (struct file_entry *)malloc(sizeof(struct file_entry)*m->no_of_entries);
	for(int i=0;i < m->no_of_entries;i++){
		struct file_entry *entry = &m->entries[i];
		fread(&entry->version,1,sizeof(int),fp);
		fread(entry->sha256,1,sizeof(entry->sha256),fp);
		int filename_length;
		fread(&filename_length,1,sizeof(int),fp);
		entry->filename = malloc(sizeof(char)*(filename_length+1));
		entry->filename[filename_length] ='\0';
		fread(entry->filename,1,filename_length,fp);
	}
	fclose(fp);
	return 0;
}


void free_manifest(struct manifest *m){

	for(int i=0;i<m->no_of_entries;i++){
		free(m->entries[i].filename);
	}
	if(m->no_of_entries > 0){
		free(m->entries);
	}
}
int deserialize_manifest(const char *buffer,struct manifest *m){
	int offset=0;
	m->version = *(int *)(buffer+offset);
	offset+= sizeof(int);

	m->no_of_entries = *(int *)(buffer+offset);
	offset+= sizeof(int);

	m->entries = (struct file_entry *)malloc(sizeof(struct file_entry)*m->no_of_entries);
	for(int i=0;i < m->no_of_entries;i++){
		struct file_entry *entry = &m->entries[i];
		entry->version = *(int *)(buffer+offset);
		offset+= sizeof(int);

		memcpy(entry->sha256,buffer+offset,SHA256_DIGEST_LENGTH);
		offset+=SHA256_DIGEST_LENGTH;

		int filename_length;
		filename_length = *(int *)(buffer+offset);
		offset+= sizeof(int);

		entry->filename = malloc(sizeof(char)*(filename_length+1));
		memcpy(entry->filename,buffer+offset,filename_length);
		entry->filename[filename_length] ='\0';
		offset+= filename_length;
	}
	return offset;
}

int serialize_manifest(struct manifest *m,char *buffer){
	int offset=0;
	memcpy(buffer+offset,&m->version,sizeof(int));
	offset+=sizeof(int);

	memcpy(buffer+offset,&m->no_of_entries,sizeof(int));
	offset+=sizeof(int);

	for(int i=0;i < m->no_of_entries;i++){
		struct file_entry *entry = &m->entries[i];
		memcpy(buffer+offset,&entry->version,sizeof(int));
		offset+=sizeof(int);

		memcpy(buffer+offset,entry->sha256,SHA256_DIGEST_LENGTH);
		offset+=SHA256_DIGEST_LENGTH;


		int filename_length= strlen(entry->filename);
		memcpy(buffer+offset,&filename_length,sizeof(int));
		offset+=sizeof(int);

		memcpy(buffer+offset,entry->filename,filename_length);
		offset+=filename_length;
	}
	return offset;
}

void print_manifest(struct manifest *m){
	printf("version: %d\n",m->version);
	printf("no_of_files: %d\n",m->no_of_entries);
	for(int i=0;i < m->no_of_entries;i++){
		struct file_entry *entry = &m->entries[i];
		printf("{\n\tfilename: %s\n\tversion: %d  \n\tSHA256: ",entry->filename,entry->version);
		print_sha256(entry->sha256);
		printf("\n}\n");
	}
}

void write_manifest(const char *project_name, const struct manifest *m){
	char manifest_file[1024];
	sprintf(manifest_file,"%s/%s",project_name,MANIFEST_FILE_NAME);
	FILE *fp = fopen(manifest_file,"w");
	fwrite(&m->version,1,sizeof(int),fp);
	fwrite(&m->no_of_entries,1,sizeof(int),fp);
	for(int i=0;i < m->no_of_entries;i++){
		struct file_entry *entry = &m->entries[i];
		fwrite(&entry->version,1,sizeof(int),fp);
		fwrite(entry->sha256,1,sizeof(entry->sha256),fp);
		int filename_length = strlen(entry->filename);
		fwrite(&filename_length,1,sizeof(int),fp);
		fwrite(entry->filename,1,filename_length,fp);
	}
	fclose(fp);
}
void update_manifest_file_header(const struct manifest *m,const char *filename){
	FILE *fp = fopen(filename,"r+");
	if(fp == NULL){
	  printf("unable to open file = %s\n",filename);
	  return;
	}
	fseek(fp,0L,SEEK_SET);
	fwrite(&m->version,1,sizeof(int),fp);
	fwrite(&m->no_of_entries,1,sizeof(int),fp);
	fclose(fp);
}

void remove_file_from_manifest_buf(struct manifest *m,const char *filename){
	int i=0;
	while(i <m->no_of_entries){
		if(strcmp(m->entries[i].filename,filename) == 0){
			break;
		}
		i++;
	}
	if(i< m->no_of_entries){
		free(m->entries[i].filename);
		while(i< m->no_of_entries-1){
			m->entries[i].version = m->entries[i+1].version;
			memcpy(m->entries[i].sha256,m->entries[i+1].sha256,SHA256_DIGEST_LENGTH);
			m->entries[i].filename=m->entries[i+1].filename; // just pointers to allocated memory. so direct assignment
			i++;
		}
		--m->no_of_entries;
	}
}

struct file_entry * add_file_to_manifest_buf(struct manifest *m,const char *project_name,const char *filename){
	if ( m->no_of_entries > 0){
		if((m->entries = realloc(m->entries,sizeof(struct file_entry)*(m->no_of_entries+1)) )== NULL) {
			printf("realloc failed\n");
			return NULL;
		}
	} else {
		m->entries = malloc(sizeof(struct file_entry)); // first entry

	}
	struct file_entry *entry = &m->entries[m->no_of_entries]; // new entry
	entry->version = 1;
	entry->filename = strdup(filename);
       	int rc =get_sha256_for_file(project_name,filename,entry->sha256);
	++m->no_of_entries;
	return entry;
}

int add_file_to_manifest(const char *project_name, const char *filename){
	if(!valid_project(project_name)){
		printf("invalid project\n");
		return -1;
	}
	char manifest_file[1024];
	sprintf(manifest_file,"%s/%s",project_name,MANIFEST_FILE_NAME);
	struct file_entry entry;
	entry.version = 1;
       	int rc =get_sha256_for_file(project_name,filename,entry.sha256);
	if(rc < 0 ){
	   printf("SHA error\n");
	   return -1;
	}
	FILE *fp = fopen(manifest_file,"a");
	fwrite(&entry.version,1,sizeof(int),fp);
	fwrite(&entry.sha256,1,sizeof(entry.sha256),fp);
	int filename_length = strlen(filename);
	fwrite(&filename_length,1,sizeof(int),fp);
	fwrite(filename,1,filename_length,fp);
	fclose(fp);
	struct manifest m;
	read_manifest(project_name,&m);
	m.no_of_entries++;
	update_manifest_file_header(&m,manifest_file);
	m.no_of_entries--; // free will try to free new unexisting entry otherwise
	free_manifest(&m);
    return 0;
}

int remove_file_from_manifest(const char *project_name, const char *filename){
	char full_path[1024];
	sprintf(full_path,"%s/%s",project_name,filename);


	if(!valid_project(project_name)){
		printf("invalid project\n");
		return -1;
	}
	struct manifest m;
	read_manifest(project_name,&m);
	int i=0;
	while(i<m.no_of_entries){
		struct file_entry *entry = &m.entries[i];
		if(strcmp(entry->filename,filename) == 0){
			break;
		}
		i++;
	}
	if(i < m.no_of_entries){ // found entry
		struct file_entry *entry = &m.entries[i];
		free(entry->filename);
		while(i < m.no_of_entries-1){
			m.entries[i].version = m.entries[i+1].version;
			memcpy(m.entries[i].sha256,m.entries[i+1].sha256,SHA256_DIGEST_LENGTH);
			m.entries[i].filename=m.entries[i+1].filename; // just pointers to allocated memory. so direct assignment
			i++;
		}
		m.no_of_entries--;
	} else {
        free_manifest(&m);
        return -1;
    }
	char manifest_file[1024];
	sprintf(manifest_file,"%s/%s",project_name,MANIFEST_FILE_NAME);
	struct stat st;
	stat(manifest_file,&st);

	char *buffer = malloc(st.st_size);
	int bytes = serialize_manifest(&m,buffer);
	FILE *fp = fopen(manifest_file,"w");
	fwrite(buffer,1,bytes,fp);
	fclose(fp);
	free_manifest(&m);
	free(buffer);
    return 0;
}
#endif // WTF_MANIFEST_H

#ifndef WTF_ARCHIVE_ROUTINES_H
#define WTF_ARCHIVE_ROUTINES_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

char *mktemp(char *filename);

int execute_command(const char *command){
 //   printf("command=%s\n",command);
    return system(command);
}
size_t archive_to_file(char *outfile,const char *change_dir, int no_of_files,char **filename) {
    printf("archive_to_file\n");
	char command[10000];

	sprintf(command,"tar -C %s -czf ",change_dir);
	strcat(command,outfile);
	for(int i=0;i<no_of_files;i++){
		strcat(command," ");
		strcat(command,*filename);
		filename++;
	}

	if(execute_command(command)<0){
		return 0;
	}

	struct stat st;
	if(stat(outfile,&st)<0)
		return 0;

	return st.st_size;
}

size_t archive_to_buffer(int no_of_files,const char *change_dir,char **filename,char *buffer,size_t buf_size) {
	size_t written_size = 0;


	char command[10000];

	sprintf(command,"tar -C %s -czf ",change_dir);
	char temp[] = "/tmp/WTFXXXXXX";
	char *tarfilename = mktemp(temp);
	strcat(command,tarfilename);
    strcat(command,".tar.gz");
	for(int i=0;i<no_of_files;i++){
		strcat(command," ");
		strcat(command,*filename);
		filename++;
	}

	if(execute_command(command)<0){
		return 0;
	}


    char tgzfile[100];
    sprintf(tgzfile,"%s.tar.gz",tarfilename);
	struct stat st;
	if(stat(tgzfile,&st)< 0){
		return 0;
	}
	FILE *fp = fopen(tgzfile,"r");
	written_size = st.st_size;
	fread(buffer,1,st.st_size,fp);
	fclose(fp);
    unlink(tgzfile);
	return written_size;
}

int extract_from_buffer(const char *buffer,size_t buf_size,char *change_dir)
{

	char temp[] = "/tmp/WTFXXXXXX";
    char filename[100];
	char *tmp =  mktemp(temp);
    strcpy(filename,tmp);
    strcat(filename,".tar.gz");
	FILE *fp = fopen(filename,"w");

	fwrite(buffer,1,buf_size,fp);
	fclose(fp);

	char command[512];

	sprintf(command,"tar -C %s -xzf %s",change_dir,filename);
    int rc = execute_command(command);
    unlink(filename);
    return rc;
}

int extract_file(const char *filename,const char *change_dir)
{
	char command[512];
	sprintf(command,"tar -C %s -xzf %s",change_dir,filename);
	return execute_command(command);
}

#endif // WTF_ARCHIVE_ROUTINES_H

#include "acutest.h"
#include "../server/wtf_server.h"
#include "../client/wtf_client.h"

char tests_dir[1024];

void test_configure()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);
}

void print_cwd(){
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
       printf("Client Current working dir: %s\n", cwd);
    }

}

void remove_test_dirs(char *project){
    remove_dir(project);
    char server_dir[256];
    sprintf(server_dir,"projects/%s",project);
    remove_dir(server_dir);
}
void test_create()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }
    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_test_dirs(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_destroy()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }
    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_test_dirs(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"destroy");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_checkout_success()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_dir(project_name);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"checkout");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_checkout_failure()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }
    unlink(".configure");
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"checkout");
    strcpy(argv[2],"no_project");
    TEST_CHECK(wtf_client(argc,argv) == -1 );
}
void test_add_file()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_dir(project_name);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"checkout");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    char *filename = "test_file";
    char full_path[256];
    sprintf(full_path,"%s/%s",project_name,filename);
    FILE *fp = fopen(full_path,"w");
    fprintf(fp,"testfile\n");
    fclose(fp);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"add");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_remove_file()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_dir(project_name);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"checkout");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    char *filename = "test_file";
    char full_path[256];
    sprintf(full_path,"%s/%s",project_name,filename);
    FILE *fp = fopen(full_path,"w");
    fprintf(fp,"testfile\n");
    fclose(fp);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"add");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"remove");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_history()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_dir(project_name);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"history");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_currentversion()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_dir(project_name);

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"currenversion");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_commit()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    char *filename = "test_file";
    char full_path[256];
    sprintf(full_path,"%s/%s",project_name,filename);
    print_cwd();
    FILE *fp = fopen(full_path,"w");
    TEST_ASSERT(fp!=NULL);
    if(fp==NULL){
        printf("unable to open file =%s\n",full_path);
    } else {
        fprintf(fp,"testfile\n");
        fclose(fp);
    }

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"add");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"commit");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);

}

void test_push()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    char *filename = "test_file";
    char full_path[256];
    sprintf(full_path,"%s/%s",project_name,filename);
    print_cwd();
    FILE *fp = fopen(full_path,"w");
    TEST_ASSERT(fp!=NULL);
    if(fp==NULL){
        printf("unable to open file =%s\n",full_path);
    } else {
        fprintf(fp,"testfile\n");
        fclose(fp);
    }

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"add");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"commit");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"push");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);

}

void test_rollback()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    char *filename = "test_file";
    char full_path[256];
    sprintf(full_path,"%s/%s",project_name,filename);
    print_cwd();
    FILE *fp = fopen(full_path,"w");
    TEST_ASSERT(fp!=NULL);
    if(fp==NULL){
        printf("unable to open file =%s\n",full_path);
    } else {
        fprintf(fp,"testfile\n");
        fclose(fp);
    }

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"add");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"commit");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"push");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"rollback");
    strcpy(argv[2],project_name);
    strcpy(argv[3],"1");
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_update()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    char *filename = "test_file";
    char full_path[256];
    sprintf(full_path,"%s/%s",project_name,filename);
    print_cwd();
    FILE *fp = fopen(full_path,"w");
    TEST_ASSERT(fp!=NULL);
    if(fp==NULL){
        printf("unable to open file =%s\n",full_path);
    } else {
        fprintf(fp,"testfile\n");
        fclose(fp);
    }

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"add");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"commit");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"push");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"rollback");
    strcpy(argv[2],project_name);
    strcpy(argv[3],"1");
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"update");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    remove_test_dirs(project_name);
}

void test_upgrade()
{
    int argc =4 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }

    char *project_name = "project";
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"configure");
    strcpy(argv[2],"127.0.0.1");
    strcpy(argv[3],"34122");
    TEST_CHECK(wtf_client(argc,argv) == 0);

    remove_dir(project_name);
    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"create");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );
    char *filename = "test_file";
    char full_path[256];
    sprintf(full_path,"%s/%s",project_name,filename);
    print_cwd();
    FILE *fp = fopen(full_path,"w");
    TEST_ASSERT(fp!=NULL);
    if(fp==NULL){
        printf("unable to open file =%s\n",full_path);
    } else {
        fprintf(fp,"testfile\n");
        fclose(fp);
    }

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"add");
    strcpy(argv[2],project_name);
    strcpy(argv[3],filename);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"commit");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"push");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"rollback");
    strcpy(argv[2],project_name);
    strcpy(argv[3],"1");
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"update");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    strcpy(argv[0],"./WTF");
    strcpy(argv[1],"upgrade");
    strcpy(argv[2],project_name);
    TEST_CHECK(wtf_client(argc,argv) == 0 );

    remove_test_dirs(project_name);
}


void* test_start_server(void *n)
{
    int argc =2 ;
    char **argv;
    argv = malloc(sizeof(char*)*argc);
    for(int i=0;i<argc;i++){
        argv[i] = malloc(sizeof(char)*100);
    }
    strcpy(argv[0],"./WTFServer");
    strcpy(argv[1],"34122");
    wtf_server(argc,argv);
}


void init_tests() {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
    }
    sprintf(tests_dir,"%s/temp",cwd);
    mkdir(tests_dir,S_IRWXU|S_IRWXG|S_IROTH);
    chdir(tests_dir);
    pthread_t thread_id;

    if(pthread_create( &thread_id , NULL ,  test_start_server , NULL ) < 0){
        printf("unable to create thread\n");
    }
    pthread_detach(thread_id);
}

void cleanup_tests() {
    remove_dir(tests_dir);
}
TEST_LIST = {
    { "test_configure", test_configure},
    { "test_create", test_create},
    { "test_checkout_success",     test_checkout_success},
    { "test_checkout_failure",     test_checkout_failure},
    { "test_add_file",     test_add_file},
    { "test_remove_file",     test_remove_file},
    { "test_history",     test_history},
    { "test_currentversion",     test_currentversion},
    { "test_commit",     test_commit},
    { "test_push",     test_push},
    { "test_rollback",     test_rollback},
    { "test_update",     test_update},
    { "test_upgrade",     test_upgrade},
    { "test_destroy",     test_destroy},
    { NULL, NULL }
};

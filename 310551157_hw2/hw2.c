#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/wait.h>
#include "usage.h"

int main(int argc, char* argv[])
{
    // check command line exist
    if(argc==1)
    {
        printf("no command given.\n");
        return 0;
    }
    
    char* envp[]= {"LD_PRELOAD=./logger.so","O_FILE=NO" ,"tmp.txt", NULL};
    int begin = command_line_begin(argc, argv);
    pid_t pid;
    int status;

    // handle the arguments
    if(handel_flag(argc, argv, envp)==-1)
        return 0;

    // check if command exist
    if(check_o || check_p)
    {
        if(!command_line_exist(argc, argv))
        {
            printf("no command given.\n");
            return 0;
        }
    }

    // create a file to occupy fd "3"
    FILE* fp = fopen(envp[2], "w+");
    if(!fp)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // if no '-o' or '-o' has no argument, remove "tmp.txt"
    if(!check_of)
        remove("tmp.txt");

    // a real-path command 
    if( strstr(argv[begin], "/") != NULL )
    {
        if((pid=fork()) == 0)
            execve(argv[begin], argv+begin, envp);
        else
        {
            wait(&status);
            if(check_of)
            {
                fclose(fp);
                remove("tmp.txt");
            }
        }
    }
    // shell command
    else
    {
        if((pid=fork()) == 0)
        {
            int command_len = strlen(argv[begin]);
            char* command_path = (char*)malloc(sizeof(char)*(command_len+6));

            snprintf(command_path, command_len+6, "/bin/%s", argv[begin]);

            argv[begin] = command_path;
            execve(argv[begin], argv+begin, envp);
        }
        else
        {
            wait(&status);
            if(check_of)
            {
                fclose(fp);
                remove("tmp.txt");
            }
        }
    }
    
    return 0;
}

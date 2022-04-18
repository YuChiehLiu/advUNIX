#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include "usage.h"

char *p_flag;
int check_p=0, check_o=0, check_of=0;

int handel_flag(int argc, char* argv[], char* envp[])
{   
    int opt;

    while((opt = getopt(argc, argv, "p:o")) != -1)
    {
        switch( opt )
        {
            case 'p' :
                p_flag = optarg;
                check_p = 1;
                char *injso_path = (char*)malloc(sizeof(char)*(strlen(p_flag)+12));
                memset(injso_path, '\0', strlen(p_flag)+12);
                snprintf(injso_path, strlen(p_flag)+12, "LD_PRELOAD=%s", p_flag);
                envp[0]=injso_path;
                break;
            case 'o' :
                check_o=1;
                if(optind<argc)
                {
                    if(argv[optind][0] != '-')
                    {  
                        check_of=1;
                        envp[1]="O_FILE=YES";
                        envp[2] = argv[optind];              
                    }
                }
                break;
            case '?' :
                printf("usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
                printf("        -p: set the path to logger.so, default = ./logger.so\n");
                printf("        -o: print output to file, print to \"stderr\" if no file specified\n");
                printf("        --: separate the arguments for logger and for the command\n");
                return -1;
        }
    }

    return 1;
}

int command_line_exist(int argc, char* argv[])
{
    for(int i=0 ; i<argc ; i++)
    {        
        if( !strcmp(argv[i],"--") )
        {
           if(argv[i+1]!=NULL)
                return 1;
        }
    }
    return 0;
}

int command_line_begin(int argc, char* argv[])
{
    for(int i=0 ; i<argc ; i++)
    {        
        if( !strcmp(argv[i],"--") )
           return i+1;
    }

    return 1;
}

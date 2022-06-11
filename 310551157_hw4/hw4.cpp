#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <elf.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <capstone/capstone.h>
#include <iostream>

#include "ptools.h"
#include "command.h"

using namespace std;

int state=NOT_LOADED;
char path_name[100];
int wait_status;
int is_restart = 0;
Elf64_Ehdr ehdr;
Elf64_Shdr strshdr;
Elf64_Shdr textshdr;
char *s_file;
int is_script = 0, is_file = 0;
pid_t CHILD;
char *args[2];

int handel_flag(int argc, char* argv[]);

int main(int argc, char* argv[])
{
    char r_buf[100];
    FILE *fp;

    handel_flag(argc, argv);

    if (argc > optind)
    {
        int i = 0;
        for (i = optind; i < argc; i++) {
            args[0]=argv[i];
            args[1]=NULL;
            is_file = 1;
        }
    }

    /* NOT LAODED */
    if(is_script)
    {
        if((fp=fopen(s_file, "r")) == NULL) errquit("fopen");
        while(state==NOT_LOADED)
        {
            if(is_file  && state==NOT_LOADED)
            {
                strcpy(path_name, args[0]);
                parse_elf();
restart_s:      c_load();
                break;
            }
            fgets(r_buf, 100, fp);
            r_buf[strlen(r_buf)-1]='\0';
            if(strstr(r_buf, "load ")!=NULL)
            {
                sscanf(r_buf, "%*s %s", path_name);
                sscanf(r_buf, "%s %*s", r_buf);
                args[0] = path_name;
                args[1] = NULL;
                parse_elf();
            }
            sdb(0, r_buf);
        }
    }
    else
    {
        while(state==NOT_LOADED)
        {
            if(is_file && state==NOT_LOADED)
            {
                strcpy(path_name, args[0]);
                parse_elf();
restart_ns:     c_load();
                break;
            }
            fprintf(stderr, "sdb> ");
            cin.getline(r_buf, 100);
            if(strstr(r_buf, "load ")!=NULL)
            {
                sscanf(r_buf, "%*s %s", path_name);
                sscanf(r_buf, "%s %*s", r_buf);
                args[0] = path_name;
                args[1] = NULL;
                parse_elf();
            }
            sdb(0, r_buf);
        }
    }
  
    /* LAODED & RUNNING */
    if(is_script)
    {
        while(WIFSTOPPED(wait_status) || state==LOADED)
        {
            if((fgets(r_buf, 100, fp))!=NULL)
            {
                r_buf[strlen(r_buf)-1]='\0';
                sdb(CHILD, r_buf);
            }
            else
                exit(-1);

            if(WIFEXITED(wait_status) && CHILD!= 0)
            {
                fprintf(stderr, "** child process %d terminiated normally (code 0)\n", CHILD);
                CHILD = 0;
                state = NOT_LOADED;
                is_restart = 1;
                goto restart_s;   
            }
        }
    }
    else
    {
        while(WIFSTOPPED(wait_status) || state==LOADED)
        {
            fprintf(stderr, "sdb> ");
            cin.getline(r_buf, 100);
            sdb(CHILD, r_buf);
            if(WIFEXITED(wait_status) && CHILD!= 0)
            {
                fprintf(stderr, "** child process %d terminiated normally (code 0)\n", CHILD);
                CHILD = 0;
                state = NOT_LOADED;
                is_restart = 1;
                goto restart_ns;   
            }
        }
    }
    

    return 0;
}

int handel_flag(int argc, char* argv[])
{   
    int opt;

    while((opt = getopt(argc, argv, "s:")) != -1)
    {
        switch( opt )
        {
            case 's' :
                s_file = optarg;
                is_script = 1;
                break;
            case '?' :
                return -1;
        }
    }

    return 1;
}
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
int noinput = 0;
int is_restart = 0;
Elf64_Ehdr ehdr;
Elf64_Shdr strshdr;
Elf64_Shdr textshdr;
char *s_file;
int is_script = 0, is_file = 0;

int handel_flag(int argc, char* argv[]);

int main(int argc, char* argv[])
{
    char r_buf[100];
    char *args[2];
    pid_t child;
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

    if(is_script)
    {
        if((fp=fopen(s_file, "r")) == NULL) errquit("fopen");
        if(!is_file)
        {
            noinput = 1;        
            while(state==NOT_LOADED)
            {
                if((fgets(r_buf, 100, fp))!=NULL)
                {
                    r_buf[strlen(r_buf)-1]='\0';
                    if(strstr(r_buf, "load ")!=NULL)
                    {
                        sscanf(r_buf, "%*s %s", args[0]);
                        args[1] = NULL;
restart_ni_s:           child = c_load(args[0], args);
                        strcpy(path_name, args[0]);
                    }
                    else
                        sdb(child, r_buf);
                }
                
            }
        }
        else
        {
restart_i_s:   child = c_load(args[0], args);
            strcpy(path_name, args[0]);
        }

    }
    else
    {
        if(!is_file)
        {
            noinput = 1;        
            while(state==NOT_LOADED)
            {
                fprintf(stderr, "sdb> ");
                cin.getline(r_buf, 100);
                if(strstr(r_buf, "load ")!=NULL)
                {
                    sscanf(r_buf, "%*s %s", args[0]);
                    args[1] = NULL;
restart_ni_ns:         child = c_load(args[0], args);
                    strcpy(path_name, args[0]);
                }
                else
                    sdb(child, r_buf);
            }
        }
        else
        {
restart_i_ns:  child = c_load(args[0], args);
            strcpy(path_name, args[0]);
        }

    }

    parse_elf();
    
    struct user_regs_struct regs;
    
    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
    assert(WIFSTOPPED(wait_status));
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
    
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
	    errquit("ptrace(GETREGS)");
    
    if(!is_restart)
        fprintf(stderr, "** program '%s' loaded. entry point 0x%llx\n", path_name, regs.rip);
    else
        reset_bp(child);

    
    if(is_script)
    {
        while(WIFSTOPPED(wait_status))
        {
            if((fgets(r_buf, 100, fp))!=NULL)
            {
                r_buf[strlen(r_buf)-1]='\0';
                sdb(child, r_buf);
            }
            else
                exit(-1);

            if(WIFEXITED(wait_status))
            {
                fprintf(stderr, "** child process %d terminiated normally (code 0)\n", child);
                state = NOT_LOADED;
                is_restart = 1;
                if(noinput)
                    goto restart_ni_s;
                else
                    goto restart_i_s;   
            }
        }
    }
    else
    {
        while(WIFSTOPPED(wait_status))
        {
            fprintf(stderr, "sdb> ");
            cin.getline(r_buf, 100);
            sdb(child, r_buf);
            if(WIFEXITED(wait_status))
            {
                fprintf(stderr, "** child process %d terminiated normally (code 0)\n", child);
                state = NOT_LOADED;
                is_restart = 1;
                if(noinput)
                    goto restart_ni_ns;
                else
                    goto restart_i_ns;   
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
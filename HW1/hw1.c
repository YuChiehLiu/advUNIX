#include <dirent.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

#include "attr.h"
#include "format_print.h"
#include "filter.h"

int main(int argc, char *argv[])
{
    // initial regluar expression
    if( handel_flag(argc, argv) == -1 )
        return 0;


    DIR *dir_proc;
    struct dirent *entry;
    struct passwd *ppasswd;
    
    dir_proc = opendir("/proc");

    printf("%-16s%-16s%-16s%-16s%-16s%-16s%-s\n",
                "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");
       
    while((entry = readdir(dir_proc)) != NULL)
    {
        if( isdigit(*(entry->d_name)) )
        {
            // get command : read /proc/$PID/comm
            char comm[100];
            get_command(entry->d_name, comm);
            
            // get PID : entry->d_name
            // get username : using stat() get uid, and using getpwuid() get username
            ppasswd = get_username(entry->d_name);

            // read cwd, root exe 
            read_c_r_e(comm, entry->d_name, ppasswd->pw_name, "cwd");
            read_c_r_e(comm, entry->d_name, ppasswd->pw_name, "root");
            read_c_r_e(comm, entry->d_name, ppasswd->pw_name, "exe");

            //read mem
            read_maps(comm, entry->d_name, ppasswd->pw_name);
            
            //read fd
            read_fd(comm, entry->d_name, ppasswd->pw_name);
           
        }
    }
    return 0;
}
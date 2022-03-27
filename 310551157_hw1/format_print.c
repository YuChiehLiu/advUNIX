#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>

#include "attr.h"
#include "format_print.h"
#include "filter.h"

void output_in_REX(char* comm, char* pid, char* user, char* fd, char* type, long inode, char* name, int perflag)
{    
    // Chech if the flag is used. If used, whether match or not.
    if( check_comm == 1 )
    {
        if( !if_flag_match(comm, C_IS_MATCH) )
            return;
    }
    if( check_type == 1 )
    {
        if( !if_flag_match(type, T_IS_MATCH) )
            return;
    }
    if( check_fname == 1 )
    {
        if( !if_flag_match(name, F_IS_MATCH) )
            return;
    }

 
    // No flag used or pass all match test, then print the final result
    if( perflag == DENIED )
    {
        printf("%-16s%-16s%-16s%-16s%-16s%-16s%-s (Permission denied)\n"
                    , comm, pid, user, fd, type, " ", name);
    }
    else if( perflag == ADMITTED )
    {
        printf("%-16s%-16s%-16s%-16s%-16s%ld%-16s%-s \n"
                    , comm, pid, user, fd, type, inode, " ", name);
    }
}
#include <dirent.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <regex.h>

#include "attr.h"
#include "format_print.h"
#include "filter.h"

char *c_flag, *t_flag, *f_flag;
int check_comm = 0, check_type = 0, check_fname = 0;

int handel_flag(int argc, char* argv[])
{   
    int opt;

    while((opt = getopt(argc, argv, "c:t:f:")) != -1)
    {
        switch( opt )
        {
            case 'c' :
                c_flag = optarg;
                check_comm = 1;
                break;
            case 't' :
                t_flag = optarg;
                if( !is_type_valid() )
                {
                    printf("Invalid TYPE option.\n");
                    return -1;
                }
                check_type = 1;
                break;
            case 'f' :
                f_flag = optarg;
                check_fname = 1;
                break;
            case '?' :
                return -1;
        }
    }

    return 1;
}

int is_type_valid()
{
    regex_t preg;
    int match_flag;
    
    regcomp(&preg, TYPE_REGEX, REG_EXTENDED | REG_NEWLINE);
    match_flag = regexec(&preg, t_flag, 0, NULL, 0);

    return match_flag == 0 ; 

}

int if_flag_match(char* target, int CTF)
{
    regex_t preg;
    int match_flag;
    
    switch( CTF )
    {
        case C_IS_MATCH :
            regcomp(&preg, c_flag, REG_EXTENDED | REG_NEWLINE);
            break;
        case T_IS_MATCH :
            regcomp(&preg, t_flag, REG_EXTENDED | REG_NEWLINE);
            break;
        case F_IS_MATCH :
            regcomp(&preg, f_flag, REG_EXTENDED | REG_NEWLINE);
            break;
    }

    match_flag = regexec(&preg, target, 0, NULL, 0);

    return match_flag == 0;
}
    
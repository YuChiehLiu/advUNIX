#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>

#include "attr.h"
#include "format_print.h"

void get_command(char* pid, char* comm)
{
    char pathname[256+11];
	snprintf(pathname, sizeof(pathname), "/proc/%s/comm", pid);
	
	FILE *fp;
	
    fp = fopen(pathname, "r");
    fscanf(fp, "%s", comm);

    fclose(fp);
}

struct passwd *get_username(char* pid)
{
	char pathname[256+6];
	snprintf(pathname, sizeof(pathname), "/proc/%s", pid);

    // get uid
    struct stat pstat;
    stat(pathname, &pstat);

    // get username
    struct passwd *ppasswd;
    ppasswd = getpwuid( pstat.st_uid );

    return ppasswd;
}

void get_filetype(mode_t fmode, char* ftype)
{	
	switch(fmode & S_IFMT)
	{
		case S_IFREG :
			strcpy(ftype, "REG");
			break;
		case S_IFDIR :
			strcpy(ftype, "DIR");
			break;
		case S_IFCHR :
			strcpy(ftype, "CHR");
			break;
		case S_IFIFO :
			strcpy(ftype, "FIFO");
			break;
		case S_IFSOCK :
			strcpy(ftype, "SOCK");
			break;
		default :
			strcpy(ftype, "unknown");
			break;
	}
}

void read_c_r_e(char* comm, char* pid, char* user, char* fd)
{
	FILE *fp;
	char pathname[256+7+5];
	char pfd[4];
	
	if( !strcmp(fd, "cwd") )
		strcpy(pfd, "cwd");
	else if( !strcmp(fd, "root") )
		strcpy(pfd, "rtd");
	else if( !strcmp(fd, "exe") )
		strcpy(pfd, "txt");
	
	snprintf(pathname, sizeof(pathname), "/proc/%s/%s", pid, fd);

	fp = fopen(pathname, "r");

	if(fp == NULL)
	{
		output_in_REX(comm, pid, user, pfd, "unknown", 0, pathname, DENIED);
	}
	else
	{
		struct stat pstat;
		char name[100];
		char ftype[10];

		memset(name, '\0', 100);
		memset(ftype, '\0', 10);

		stat(pathname, &pstat);		
    	get_filetype(pstat.st_mode, ftype);
		readlink(pathname, name, sizeof(name)-1);
    			
		output_in_REX(comm, pid, user, pfd, ftype, pstat.st_ino, name, ADMITTED);
	}

	//fclose(fp);
}

void read_maps(char* comm, char* pid, char* user)
{
	FILE *fp;
	char pathname[256+11];
	char origin[200];
	char inode[20];
	char name[100];
	char delflag[10];
	struct stat pstat;
	char ftype[10];
	char temp[20];
	int begin_flag = 1;

	memset(temp, '\0', 20);

	snprintf(pathname, sizeof(pathname), "/proc/%s/maps", pid);

	fp = fopen(pathname, "r");

	if( fp == NULL );
	else
	{
		while( fgets(origin, 300, fp) != NULL )
		{
			memset(delflag, '\0', 10);

			sscanf(origin, "%*s %*s %*s %*s %s %s %s", inode, name, delflag);

			if( !strcmp(name, "[heap]") )
				begin_flag = 0;

			if( begin_flag || !strcmp(inode, "0") || !strcmp(inode, temp) );
			else
			{
				strcpy(temp, inode);

				stat(name, &pstat);
				get_filetype(pstat.st_mode, ftype);

				if( !strcmp(delflag, "(deleted)") )
					output_in_REX(comm, pid, user, "DEL", ftype, atol(inode), name, ADMITTED);
				else
					output_in_REX(comm, pid, user, "mem", ftype, atol(inode), name, ADMITTED);
			}
		}
	}
}

void read_fd(char* comm, char* pid, char* user)
{
	DIR *dir_fd;
	char pathname[256+9];
	
	snprintf(pathname, sizeof(pathname), "/proc/%s/fd", pid);

	dir_fd= opendir(pathname);

	if(dir_fd == NULL)
		output_in_REX(comm, pid, user, "NOFD", " ", 0, pathname, DENIED);
	else
	{
		struct dirent *entry;
		char name[100];
		char ftype[10];
		char modeflag[5];
		int flag=0;

		while((entry = readdir(dir_fd)) != NULL )
		{
			struct stat pstat;
			struct stat plstat;
			char pathname_in_fd[256+256+9];

			memset(name, '\0', 100);
			memset(ftype, '\0', 10);
			memset(modeflag, '\0', 5);

			snprintf(pathname_in_fd, sizeof(pathname_in_fd), "/proc/%s/fd/%s", pid, entry->d_name);
				
			stat(pathname_in_fd, &pstat);
			
			get_filetype(pstat.st_mode, ftype);

			strcpy(modeflag, entry->d_name);
			lstat(pathname_in_fd, &plstat);
			get_openmode(plstat.st_mode, modeflag);

    		readlink(pathname_in_fd, name, sizeof(name)-1);
			sscanf(name, "%s %*s", name);
			
			if( flag >= 2)
				output_in_REX(comm, pid, user, modeflag, ftype, pstat.st_ino, name, ADMITTED);

			flag++;
		}
	}

}

void get_openmode(mode_t fo_mode, char* modeflag)
{
	if( fo_mode & S_IRUSR && fo_mode & S_IWUSR)
		strcat(modeflag, "u");
	else if( fo_mode & S_IRUSR )
		strcat(modeflag, "r");
	else if( fo_mode & S_IWUSR )
		strcat(modeflag, "w");
}



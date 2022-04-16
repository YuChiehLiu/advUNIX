#include <dlfcn.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

int RDTD=0; // flag for checking if have redirected
FILE* old_stderr; // save the original stderr

/* function pointer */
static int (*old_chmod)(const char *pathname, mode_t mode) = NULL;
static int (*old_chown)(const char *pathname, uid_t owner, gid_t group) = NULL;
static int (*old_close)(int fd);
static int (*old_creat)(const char *pathname, mode_t mode);
static int (*old_fclose)(FILE* stream) = NULL;
static FILE* (*old_fopen)(const char *pathname, const char *mode) = NULL;
static size_t (*old_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*old_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*old_open)(const char *pathname, int flags, mode_t mode) = NULL;
static ssize_t (*old_read)(int fd, void *buf, size_t count);
static int (*old_remove)(const char *pathname);
static int (*old_rename)(const char *oldpath, const char *newpath);
static FILE* (*old_tmpfile)(void);
static ssize_t (*old_write)(int fd, const void *buf, size_t count);

void init_stderr() // check if using stderr or specified output file
{
    if(!strcmp(getenv("O_FILE"), "YES") && !RDTD)
    {
        old_stderr=stderr;
        FILE* o_fp;
        o_fp = fdopen(3, "w+");
        stderr = o_fp;
        RDTD = 1;
    }
}

int chmod(const char *pathname, mode_t mode)
{
    old_chmod = NULL;

    init_stderr();

    if(old_chmod == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_chmod = dlsym(handle, "chmod"); // return the addr. of the real func in C library
    }

    if(old_chmod != NULL)
    {
        int ret = old_chmod(pathname, mode);
        fprintf(stderr, "[logger] chmod(\"%s\", %o) = %d\n", realpath(pathname, NULL), mode, ret);

        return ret;
    }

}

int chown(const char *pathname, uid_t owner, gid_t group)
{
    old_chown = NULL;

    init_stderr();

    if(old_chown == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_chown = dlsym(handle, "chown"); // return the addr. of the real func in C library
    }

    if(old_chown != NULL)
    {
        int ret = old_chown(pathname, owner, group);
        fprintf(stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", realpath(pathname, NULL), owner, group, ret);

        return ret;
    }
}

int close(int fd)
{
    old_close = NULL;

    init_stderr();

    char pathname[256];
    char filename[256];

    memset(pathname, '\0', 256);
    memset(filename, '\0', 256);

    if(old_close == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_close = dlsym(handle, "close"); // return the addr. of the real func in C library
    }

    if(old_close != NULL)
    {
        pid_t pid = getpid();

        snprintf(pathname, 256, "/proc/%d/fd/%d", pid, fd);
        readlink(pathname, filename, sizeof(filename)-1);

        int ret = old_close(fd);

        fprintf(stderr, "[logger] close(\"%s\") = %d\n", filename, ret);

        return ret;
    }
}

int creat(const char *pathname, mode_t mode)
{
    old_creat = NULL;

    init_stderr();

    if(old_creat == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_creat = dlsym(handle, "creat"); // return the addr. of the real func in C library
    }

    if(old_creat != NULL)
    {
        int ret = old_creat(pathname, mode);
        fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", realpath(pathname, NULL), mode, ret);

        return ret;
    }
}

int fclose(FILE* stream)
{
    old_fclose = NULL;

    init_stderr();

    char pathname[256];
    char filename[256];

    memset(pathname, '\0', 256);
    memset(filename, '\0', 256);

    if(old_fclose == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fclose = dlsym(handle, "fclose");
    }

    if(old_fclose != NULL)
    {
        int fd = fileno(stream);
        pid_t pid = getpid();

        snprintf(pathname, 256, "/proc/%d/fd/%d", pid, fd);
        readlink(pathname, filename, sizeof(filename)-1);
        
        int ret;
        
        if(fd==3) // if using specified output file, fclose stderr
        {
            memset(pathname, '\0', 256);
            memset(filename, '\0', 256);

            fd = fileno(old_stderr);
            snprintf(pathname, 256, "/proc/%d/fd/%d", pid, fd);
            readlink(pathname, filename, sizeof(filename)-1);

            ret = old_fclose(old_stderr);
            fprintf(stderr,"[logger] fclose(\"%s\") = %d\n", filename, ret);
        }
        else if(fd==2) // if using stderr, need to reopen stderr for printing the message
        {
            ret = old_fclose(stream);
            FILE* my_stderr=freopen(filename, "w+", stderr);
            fprintf(my_stderr,"[logger] fclose(\"%s\") = %d\n", filename, ret);
            old_fclose(my_stderr);
        }
        else
        {
            ret = old_fclose(stream);
            fprintf(stderr,"[logger] fclose(\"%s\") = %d\n", filename, ret);
        }
        return ret;
    }
}

FILE* fopen(const char *pathname, const char *mode)
{
    old_fopen = NULL;

    init_stderr();

    if(old_fopen == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_fopen = dlsym(handle, "fopen"); // return the addr. of the real func in C library
    }

    if(old_fopen != NULL)
    {
        FILE *fp;
        fp = old_fopen(pathname, mode);
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", realpath(pathname, NULL), mode, fp);

        return fp;
    }
     
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    old_fread = NULL;

    init_stderr();

    char pathname[256];
    char filename[256];

    memset(pathname, '\0', 256);
    memset(filename, '\0', 256);

    if(old_fread == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_fread = dlsym(handle, "fread"); // return the addr. of the real func in C library
    }

    if(old_fread != NULL)
    {
        size_t ret;
        int fd = fileno(stream);
        pid_t pid = getpid();

        snprintf(pathname, 256, "/proc/%d/fd/%d", pid, fd);
        readlink(pathname, filename, sizeof(filename)-1);

        ret = old_fread(ptr, size, nmemb, stream);
        fprintf(stderr, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char*)ptr, size, nmemb, filename, ret);

        return ret;
    }
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    old_fwrite = NULL;

    init_stderr();

    char pathname[256];
    char filename[256];

    memset(pathname, '\0', 256);
    memset(filename, '\0', 256);

    if(old_fwrite == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_fwrite = dlsym(handle, "fwrite"); // return the addr. of the real func in C library
    }

    if(old_fwrite != NULL)
    {
        size_t ret;
        int fd = fileno(stream);
        pid_t pid = getpid();

        snprintf(pathname, 256, "/proc/%d/fd/%d", pid, fd);
        readlink(pathname, filename, sizeof(filename)-1);

        ret = old_fwrite(ptr, size, nmemb, stream);
        fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char*)ptr, size, nmemb, filename, ret);

        return ret;
    }
}

int open(const char *pathname, int flags, mode_t mode)
{
    old_open = NULL;

    init_stderr();

    if(old_open == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_open = dlsym(handle, "open");
    }

    if(old_open != NULL)
    {
        int ret = old_open(pathname, flags, mode);
        fprintf(stderr,"[logger] open(\"%s\", %03o, %03o) = %d\n", realpath(pathname, NULL), flags, mode, ret);

        return ret;
    }
}

ssize_t read(int fd, void *buf, size_t count)
{
    old_read = NULL;

    init_stderr();

    char pathname[256];
    char filename[256];

    memset(pathname, '\0', 256);
    memset(filename, '\0', 256);

    if(old_read == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_read = dlsym(handle, "read"); // return the addr. of the real func in C library
    }

    if(old_read != NULL)
    {
        ssize_t ret;
        pid_t pid = getpid();

        snprintf(pathname, 256, "/proc/%d/fd/%d", pid, fd);
        readlink(pathname, filename, sizeof(filename)-1);

        char content[33];

        ret = old_read(fd, buf, count);

        strncpy(content, buf, 33);
        content[32]='\0';

        for(int i=0 ; i< strlen(content) ; i++)
            if(isprint(content[i])==0)
                content[i]='.';

        fprintf(stderr, "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", filename, content, count, ret);

        return ret;
    }
}

int remove(const char *pathname)
{
    old_remove = NULL;

    init_stderr();

    if(old_remove == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_remove = dlsym(handle, "remove"); // return the addr. of the real func in C library
    }

    if(old_remove != NULL)
    {
        int ret;
        ret = old_remove(pathname);
        fprintf(stderr, "[logger] remove(\"%s\") = %d\n", pathname, ret);

        return ret;
    }
}

int rename(const char *oldpath, const char *newpath)
{
    old_rename = NULL;

    init_stderr();

    if(old_rename == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_rename = dlsym(handle, "rename"); // return the addr. of the real func in C library
    }

    if(old_rename != NULL)
    {
        int ret;
        ret = old_rename(oldpath, newpath);
        fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", oldpath, realpath(newpath, NULL), ret);

        return ret;
    }
}

FILE *tmpfile(void)
{
    old_tmpfile = NULL;

    init_stderr();

    if(old_tmpfile == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_tmpfile = dlsym(handle, "tmpfile"); // return the addr. of the real func in C library
    }

    if(old_tmpfile != NULL)
    {
        FILE *fp;
        fp = old_tmpfile();
        fprintf(stderr, "[logger] tmpfile() = %p\n", fp);

        return fp;
    }
}

ssize_t write(int fd, const void *buf, size_t count)
{
    old_write = NULL;

    init_stderr();

    char pathname[256];
    char filename[256];

    memset(pathname, '\0', 256);
    memset(filename, '\0', 256);

    if(old_write == NULL)
    {
        void *handle = dlopen("libc.so.6", RTLD_LAZY); // open C dynamic library
        if(handle != NULL)
            old_write = dlsym(handle, "write"); // return the addr. of the real func in C library
    }

    if(old_write != NULL)
    {
        ssize_t ret;
        pid_t pid = getpid();

        snprintf(pathname, 256, "/proc/%d/fd/%d", pid, fd);
        readlink(pathname, filename, sizeof(filename)-1);

        char content[33];

        strncpy(content, buf, 33);
        content[32]='\0';

        for(int i=0 ; i< strlen(content) ; i++)
            if(isprint(content[i])==0)
                content[i]='.';

        ret = old_write(fd, buf, count);
        fprintf(stderr, "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", filename, content, count, ret);

        return ret;
    }
}
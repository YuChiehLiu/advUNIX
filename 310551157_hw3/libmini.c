#include "libmini.h"

long errno;

#define WRAPPER_RETval(type)    errno = 0; if(ret < 0) { errno = -ret; return -1; } return ((type) ret);
#define WRAPPER_RETptr(type)    errno = 0; if(ret < 0) { errno = -ret; return NULL; } return ((type) ret);

size_t strlen(const char *s)
{
    size_t count=0;
    while(*(s+count)!='\0')
        count++;

    return count;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    long ret = sys_write(fd, buf, count);
    WRAPPER_RETval(ssize_t);
}


sighandler_t signal(int signum, sighandler_t handler)
{
    struct sigaction act, oact;
    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (signum == SIGALRM) {
    #ifdef SA_INTERRUPT
    act.sa_flags |= SA_INTERRUPT;
    #endif
    } else {
    #ifdef SA_RESTART
    act.sa_flags |= SA_RESTART;
    #endif
    }
    if (sigaction(signum, &act, &oact) < 0)
        return(SIG_ERR);
    return(oact.sa_handler);
}

int sigaction(int signum, struct sigaction *act, struct sigaction *oldact)
{
    act->sa_flags |= SA_RESTORER;
	act->sa_restorer = __myrt;
    long ret = sys_rt_sigaction(signum, act, oldact, SIGSETSIZE);
    WRAPPER_RETval(int);
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    long ret = sys_rt_sigprocmask(how, set, oldset, SIGSETSIZE);
    WRAPPER_RETval(int);
}

int sigpending(sigset_t *set)
{
    long ret = sys_rt_sigpending(set, SIGSETSIZE);
    WRAPPER_RETval(int);
}

unsigned int sleep(unsigned int s)
{
    long ret;
    struct timespec req = { s, 0 }, rem;
    ret = sys_nanosleep(&req, &rem);
    if(ret >= 0) return ret;
    if(ret == -EINTR) return rem.tv_sec;
    return 0;
}

unsigned int alarm(unsigned int seconds)
{
    long ret = sys_alarm(seconds);
    return ret;
}

int pause()
{
    long ret = sys_pause();
    WRAPPER_RETval(int);
}

/* perror terms */
static const char *errmsg[] = {
     "Success",
     "Operation not permitted",
     "No such file or directory",
     "No such process",
     "Interrupted system call",
     "I/O error",
     "No such device or address",
     "Argument list too long",
     "Exec format error",
     "Bad file number",
     "No child processes",
     "Try again",
     "Out of memory",
     "Permission denied",
     "Bad address",
     "Block device required",
     "Device or resource busy",
     "File exists",
     "Cross-device link",
     "No such device",
     "Not a directory",
     "Is a directory",
     "Invalid argument",
     "File table overflow",
     "Too many open files",
     "Not a typewriter",
     "Text file busy",
     "File too large",
     "No space left on device",
     "Illegal seek",
     "Read-only file system",
     "Too many links",
     "Broken pipe",
     "Math argument out of domain of func",
     "Math result not representable"
};

void perror(const char *prefix) {
    const char *unknown = "Unknown";
    long backup = errno;
    if(prefix) {
        write(2, prefix, strlen(prefix));
        write(2, ": ", 2);
    }
    if(errno < PERRMSG_MIN || errno > PERRMSG_MAX) write(2, unknown, strlen(unknown));
    else write(2, errmsg[backup], strlen(errmsg[backup]));
    write(2, "\n", 1);
    return;
}

void exit(int error_code)
{
    sys_exit(error_code);
}


/* operations for signal set */
int sigemptyset(sigset_t *set)
{
    if(set==NULL)
        return -1;

    set->sig = 0x0;
    return 0;
}

int sigfillset(sigset_t *set)
{
    if(set==NULL)
        return -1;

    set->sig = ~(0x0);
    return 0;
}

int sigaddset(sigset_t *set, int signo)
{
    if(set==NULL)
        return -1;

    long chgbit = (1<<(signo-1));
    set->sig |= chgbit; 
    return 0;
}

int sigdelset(sigset_t *set, int signo)
{
    if(set==NULL)
        return -1;

    long chgbit = ~(1<<(signo-1));
    set->sig &= chgbit; 
    return 0;
}

int sigismember(const sigset_t *set, int signo)
{
    if(set==NULL)
        return -1;

    long chgbit = (1<<(signo-1));
    int ret = set->sig & chgbit;
    return ret;
}
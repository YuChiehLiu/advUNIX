#include "libmini.h"

static jmp_buf jb;

int main()
{
    int i=0;
    setjmp(jb);
    if(i==0)
    {
        sigset_t act, oact;
        sigemptyset(&act);
        sigaddset(&act ,SIGALRM);
        sigprocmask(SIG_BLOCK, &act, &oact);
    }
    else
        signal(SIGALRM, SIG_DFL);

    alarm(3);
    sleep(5);

    i++;
    if(i==1)
    {
        signal(SIGALRM, SIG_IGN);
        longjmp(jb, 1);
    }
    
    return 0;
}
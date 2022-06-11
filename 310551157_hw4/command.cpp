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

#include "command.h"
#include "ptools.h"

using namespace std;

unsigned int bp_count = 0;
breakpoint_t bp[100];

void errquit(const char *msg)
{
	perror(msg);
	exit(-1);
}

void sdb(pid_t child, char *comm)
{ 
    if(!strcmp(comm, "exit") || !strcmp(comm, "q"))
        c_exit(child);
    else if(!strcmp(comm, "help") || !strcmp(comm, "h"))
        c_help();
    else if(!strcmp(comm, "list") || !strcmp(comm, "l"))
        c_list();
    else if(state==NOT_LOADED)
    {
        if((strstr(comm, "load")!=NULL))
            c_load();
        else
            fprintf(stderr, "** Command not found or can not be used in this state.\n");  
    }
    else if(state==LOADED)
    {
        if(!strcmp(comm, "start"))
            c_start();
        else if(!strcmp(comm, "run") || !strcmp(comm, "r"))
            c_run();
        else
            fprintf(stderr, "** Command not found or can not be used in this state.\n");
    }
    else if(state==RUNNING)
    {
        if(!strcmp(comm, "cont") || !strcmp(comm, "c"))
            c_cont(child);
        else if(!strcmp(comm, "run") || !strcmp(comm, "r"))
            c_run();
        else if(!strcmp(comm, "si"))
            c_si(child);
        else if(!strcmp(comm, "vmmap") || !strcmp(comm, "m"))
            c_vmmap(child);
        else if((strstr(comm, "get ")!=NULL) || (strstr(comm, "g ")!=NULL))
        {
            char reg_name[6];
            sscanf(comm, "%*s %s", reg_name);
            c_getreg(child, reg_name);
        }
        else if(!strcmp(comm, "getregs"))
            c_getregs(child);
        else if((strstr(comm, "set ")!=NULL) || (strstr(comm, "s ")!=NULL))
        {
            char reg_name[6];
            char val_c[30];
            sscanf(comm, "%*s %s %s", reg_name, val_c);

            unsigned long long val=str2ULL(val_c);

            c_set(child, reg_name, val);
        }
        else if((strstr(comm, "break ")!=NULL) || (strstr(comm, "b ")!=NULL))
        {
            char addr[20];
            unsigned long target;

            sscanf(comm, "%*s %s", addr);
            target = str2ULL(addr);

            if(target<textshdr.sh_addr || target>=textshdr.sh_addr+textshdr.sh_size || target==ehdr.e_entry)
            {
                fprintf(stderr, "** illegal address.\n");
                return;
            }

            c_break(child, target);
        }
        else if((strstr(comm, "delete ")!=NULL) || (strstr(comm, "del ")!=NULL))
        {
            char id_c[4];
            int del_id;

            sscanf(comm, "%*s %s", id_c);
            del_id = str2ULL(id_c);

            if(del_id>=(int)bp_count || bp[del_id].status==DELETED)
            {
                fprintf(stderr, "** NOnexist break point!\n");
                return;
            }

            c_delete(child ,del_id);
        }
        else if((strstr(comm, "dump ")!=NULL) || (strstr(comm, "x ")!=NULL))
        {
            char addr[20];
            unsigned long target;

            if(strstr(comm, "0x")==NULL)
            {
                fprintf(stderr, "** no addr is given.\n");
                return;
            }

            sscanf(comm, "%*s %s", addr);
            target = str2ULL(addr);

            c_dump(path_name, target);
        }
        else if((strstr(comm, "disasm")!=NULL) || (strstr(comm, "d ")!=NULL))
        {
            char addr[20];
            unsigned long target;

            if(strstr(comm, "0x")==NULL)
            {
                fprintf(stderr, "** no addr is given.\n");
                return;
            }

            sscanf(comm, "%*s %s", addr);

            target = str2ULL(addr);

            if(target<textshdr.sh_addr || target>=textshdr.sh_addr+textshdr.sh_size)
            {
                fprintf(stderr, "** illegal address.\n");
                return;
            }
                

            c_disam(target, 10);
        }
        else
            fprintf(stderr, "** Command not found or can not be used in this state.\n");

    }
    else
        fprintf(stderr, "** Command not found or can not be used in this state.\n");
}

void c_exit(pid_t child)
{
    kill(child, SIGKILL);
    exit(-1);
}

void c_help()
{
    fprintf(stderr, "- break {instruction-address}: add a break point\n"
                    "- cont: continue execution\n"
                    "- delete {break-point-id}: remove a break point\n"
                    "- disasm addr: disassemble instructions in a file or a memory region\n"
                    "- dump addr: dump memory content\n"
                    "- exit: terminate the debugger\n"
                    "- get reg: get a single value from a register\n"
                    "- getregs: show registers\n"
                    "- help: show this message\n"
                    "- list: list break points\n"
                    "- load {path/to/a/program}: load a program\n"
                    "- run: run the program\n"
                    "- vmmap: show memory layout\n"
                    "- set reg val: get a single value to a register\n"
                    "- si: step into instruction\n"
                    "- start: start the program and stop at the first instruction\n");
}

void c_list()
{
    if(bp_count==0)
        fprintf(stderr, "** no breakpoints!!\n");
    for(unsigned long i=0 ; i<bp_count ; i++)
    {
        if(bp[i].status == EXIST)
            fprintf(stderr, "%3d:\t%lx\n", bp[i].id, bp[i].address);
    }
}

void c_load()
{
    state = LOADED;
    if(!is_restart)
        fprintf(stderr, "** program '%s' loaded. entry point %#lx\n", path_name, textshdr.sh_addr);
}

void c_start()
{
    if((CHILD = fork()) < 0) errquit("fork");
        
    if(CHILD==0)
    {                
        if(ptrace(PTRACE_TRACEME, 0, 0, 0)) errquit("ptrace");
        execv(path_name, args);
        errquit("execv");
    }

    if(waitpid(CHILD, &wait_status, 0) < 0) errquit("waitpid");
    assert(WIFSTOPPED(wait_status));
    ptrace(PTRACE_SETOPTIONS, CHILD, 0, PTRACE_O_EXITKILL);
    
    if(is_restart) reset_bp(CHILD);
    
    fprintf(stderr, "** pid %d\n", CHILD);
        
    state = RUNNING;
}

void c_run()
{
    if(state == RUNNING)
        fprintf(stderr, "** program sample/hello64 is already running\n");
    else
        c_start();

    c_cont(CHILD);
}

void c_cont(pid_t child)
{
    struct user_regs_struct regs;

    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
		errquit("ptrace(GETREGS)");

    for(unsigned int i=0 ; i<bp_count ; i++)
    {
        if(bp[i].status==EXIST && regs.rip == bp[i].address)
        {
            if(ptrace(PTRACE_POKETEXT, child, bp[i].address, bp[i].orig_word) != 0)
			    errquit("ptrace(POKETEXT1)");

            ptrace(PTRACE_SINGLESTEP, child, 0, 0);

            if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

            if(ptrace(PTRACE_POKETEXT, child, bp[i].address, (bp[i].orig_word & 0xffffffffffffff00) | 0xcc) != 0)
			    errquit("ptrace(POKETEXT2)");

            break;
        }
    }

    ptrace(PTRACE_CONT, child, 0, 0);

    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

    if(WIFSTOPPED(wait_status))
    {
        if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
	    	errquit("ptrace(GETREGS)");

        for(unsigned int i=0 ; i<bp_count ; i++)
        {
            if(bp[i].status==EXIST && regs.rip-1 == bp[i].address)
            {
                fprintf(stderr, "** breakpoint @");
                if(!is_script)
                    c_disam(bp[i].address, 1);
                else
                    fprintf(stderr, "\n");
            
                regs.rip--;

                if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0)
                    errquit("ptrace(SETREGS)");
            }
        }
    }


}

void c_si(pid_t child)
{
    struct user_regs_struct regs;

    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
	    errquit("ptrace(GETREGS)");
    
    for(unsigned int i=0 ; i<bp_count ; i++)
    {
        if(bp[i].status==EXIST && regs.rip == bp[i].address)
        {
            if(ptrace(PTRACE_POKETEXT, child, bp[i].address, bp[i].orig_word) != 0)
			    errquit("ptrace(POKETEXT1)");

            ptrace(PTRACE_SINGLESTEP, child, 0, 0);

            if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

            if(WIFSTOPPED(wait_status))
            {
                if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
	            	errquit("ptrace(GETREGS)");

                for(unsigned int i=0 ; i<bp_count ; i++)
                {
                    if(bp[i].status==EXIST && regs.rip == bp[i].address)
                    {
                        fprintf(stderr, "** breakpoint @");
                        if(!is_script)
                            c_disam(bp[i].address, 1);
                        else
                            fprintf(stderr, "\n");
                        break;
                    }
                }
            }
            
            if(ptrace(PTRACE_POKETEXT, child, bp[i].address, (bp[i].orig_word & 0xffffffffffffff00) | 0xcc) != 0)
			    errquit("ptrace(POKETEXT2)");

            return;
        }
    }

    ptrace(PTRACE_SINGLESTEP, child, 0, 0);
    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

    if(WIFSTOPPED(wait_status))
    {
        for(unsigned int i=0 ; i<bp_count ; i++)
        {
            if(bp[i].status==EXIST && regs.rip-1 == bp[i].address)
            {
                fprintf(stderr, "** breakpoint @");
                if(!is_script)
                    c_disam(bp[i].address, 1);
                else
                    fprintf(stderr, "\n");
            }
        }
    }
}

int c_vmmap(pid_t child)
{
	map<range_t, map_entry_t> vmmap;
	map<range_t, map_entry_t>::iterator vi;

    if(load_maps(child, vmmap) <= 0)
    {
		fprintf(stderr, "** cannot load memory mappings.\n");
		return -1;
    }

    return 0;
}

void c_getregs(pid_t child)
{
    struct user_regs_struct regs;

    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
		errquit("ptrace(GETREGS)");
    fprintf(stderr, "RAX %llx\t\t\tRBX %llx\t\t\tRCX %llx\t\t\tRDX %llx\n",
        regs.rax, regs.rbx, regs.rcx, regs.rdx);
    fprintf(stderr, "R8  %llx\t\t\tR9  %llx\t\t\tR10 %llx\t\t\tR11 %llx\n",
        regs.r8, regs.r9, regs.r10, regs.r11);
    fprintf(stderr, "R12 %llx\t\t\tR13 %llx\t\t\tR14 %llx\t\t\tR15 %llx\n",
        regs.r12, regs.r13, regs.r14, regs.r15);
    fprintf(stderr, "RDI %llx\t\t\tRSI %llx\t\t\tRBP %llx\t\t\tRSP %llx\n",
        regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    fprintf(stderr, "RIP %llx\t\tFLAGS %016llx\n",
        regs.rip, regs.eflags);    
}

void c_getreg(pid_t child, char *reg_name)
{
    struct user_regs_struct regs;

    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
		errquit("ptrace(GETREGS)");

    if(!strcmp(reg_name, "rax"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rax, regs.rax);
    else if(!strcmp(reg_name, "rbx"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rbx, regs.rbx);
    else if(!strcmp(reg_name, "rcx"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rcx, regs.rcx);
    else if(!strcmp(reg_name, "rdx"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rdx, regs.rdx);
    else if(!strcmp(reg_name, "r8"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r8, regs.r8);
    else if(!strcmp(reg_name, "r9"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r9, regs.r9);
    else if(!strcmp(reg_name, "r10"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r10, regs.r10);
    else if(!strcmp(reg_name, "r11"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r11, regs.r11);
    else if(!strcmp(reg_name, "r12"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r12, regs.r12);
    else if(!strcmp(reg_name, "r13"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r13, regs.r13);
    else if(!strcmp(reg_name, "r14"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r14, regs.r14);
    else if(!strcmp(reg_name, "r15"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.r15, regs.r15);
    else if(!strcmp(reg_name, "rdi"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rdi, regs.rdi);
    else if(!strcmp(reg_name, "rsi"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rsi, regs.rsi);
    else if(!strcmp(reg_name, "rbp"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rbp, regs.rbp);
    else if(!strcmp(reg_name, "rsp"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rsp, regs.rsp);
    else if(!strcmp(reg_name, "rip"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.rip, regs.rip);
    else if(!strcmp(reg_name, "flags"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.eflags, regs.eflags);
    else if(!strcmp(reg_name, "cs"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.cs, regs.cs);
    else if(!strcmp(reg_name, "ds"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.ds, regs.ds);
    else if(!strcmp(reg_name, "es"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.es, regs.es);
    else if(!strcmp(reg_name, "fs"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.fs, regs.fs);
    else if(!strcmp(reg_name, "gs"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.gs, regs.gs);
    else if(!strcmp(reg_name, "ss"))
        fprintf(stderr, "%s = %lld (%#llx)\n", reg_name, regs.ss, regs.ss);
    else
        fprintf(stderr, "** Nonexist register!!");
}

void c_set(pid_t child, char *reg_name, unsigned long long val)
{
    struct user_regs_struct regs;
    
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
		errquit("ptrace(GETREGS)");

    if(!strcmp(reg_name, "rax"))
        regs.rax=val;
    else if(!strcmp(reg_name, "rbx"))
        regs.rbx=val;
    else if(!strcmp(reg_name, "rcx"))
        regs.rcx=val;
    else if(!strcmp(reg_name, "rdx"))
        regs.rdx=val;
    else if(!strcmp(reg_name, "r8"))
        regs.r8=val;
    else if(!strcmp(reg_name, "r9"))
        regs.r9=val;
    else if(!strcmp(reg_name, "r10"))
        regs.r10=val;
    else if(!strcmp(reg_name, "r11"))
        regs.r11=val;
    else if(!strcmp(reg_name, "r12"))
        regs.r12=val;
    else if(!strcmp(reg_name, "r13"))
        regs.r13=val;
    else if(!strcmp(reg_name, "r14"))
        regs.r14=val;
    else if(!strcmp(reg_name, "r15"))
        regs.r15=val;
    else if(!strcmp(reg_name, "rdi"))
        regs.rdi=val;
    else if(!strcmp(reg_name, "rsi"))
        regs.rsi=val;
    else if(!strcmp(reg_name, "rbp"))
        regs.rbp=val;
    else if(!strcmp(reg_name, "rsp"))
        regs.rsp=val;
    else if(!strcmp(reg_name, "rip"))
        regs.rip=val;
    else if(!strcmp(reg_name, "flags"))
        regs.eflags=val;
    else if(!strcmp(reg_name, "cs"))
        regs.cs=val;
    else if(!strcmp(reg_name, "ds"))
        regs.ds=val;
    else if(!strcmp(reg_name, "es"))
        regs.es=val;
    else if(!strcmp(reg_name, "fs"))
        regs.fs=val;
    else if(!strcmp(reg_name, "gs"))
        regs.gs=val;
    else if(!strcmp(reg_name, "ss"))
        regs.ss=val;
    else
        fprintf(stderr, "** Nonexist register!!");

    if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0)
        errquit("ptrace(SETREGS)"); 
}

void c_break(pid_t child, unsigned long target)
{
    unsigned long code;

    for(unsigned int i=0 ; i<bp_count ; i++)
    {
        if(bp[i].status==EXIST && target>=bp[i].address && target<bp[i].address+8)
        {
            unsigned long offset = target - bp[i].address;
            bp[i].orig_word = (bp[i].orig_word & (0xffffffffffffffff-(0xffULL<<(offset*8)))) | (0xccULL<<(offset*8));
        }
    }
    
    code = ptrace(PTRACE_PEEKTEXT, child, target, 0);

    bp[bp_count].id = bp_count;
    bp[bp_count].orig_word = code;
    bp[bp_count].address = target;
    bp[bp_count].status = EXIST;
    bp_count++;

    if(ptrace(PTRACE_POKETEXT, child, target, (code & 0xffffffffffffff00) | 0xcc) != 0)
			errquit("ptrace(POKETEXT)");
}

void c_delete(pid_t child, int del_id)
{
    bp[del_id].status = DELETED;

    for(unsigned int i=0 ; i<bp_count ; i++)
    {
        if(bp[i].status==EXIST && bp[del_id].address>=bp[i].address && bp[del_id].address<bp[i].address+8)
        {
            unsigned long offset = bp[del_id].address - bp[i].address;
            unsigned long patch = bp[del_id].orig_word;
            patch = (patch << 7*8) >> ((8-(offset+1))*8);
            bp[i].orig_word = (bp[i].orig_word & (0xffffffffffffffff-(0xffULL<<(offset*8)))) | patch;
        }
    }


    if(ptrace(PTRACE_POKETEXT, child, bp[del_id].address, bp[del_id].orig_word) != 0)
			errquit("ptrace(POKETEXT)");
    
    for(unsigned int i=del_id+1 ; i<bp_count ; i++)
    {
        bp[i-1].id = bp[i].id - 1;
        bp[i-1].orig_word = bp[i].orig_word;
        bp[i-1].address = bp[i].address;
        bp[i-1].status = bp[i].status;
    }

    bp_count--;
}

void c_dump(char* path, unsigned long target)
{
    FILE *fp;
    int byte=0, line=0, count=80;
    char buf[17];

    unsigned long dump_offset = target - (textshdr.sh_addr - textshdr.sh_offset);
    
    if((fp=fopen(path, "r")) == NULL) errquit("fopen");

    fseek(fp, dump_offset, SEEK_SET);

    while(count>0)
    {
        if(fread(buf+byte, sizeof(char), 1, fp) == 0)
            break;

        for(unsigned int i=0 ; i<bp_count ; i++)
        {
            if(bp[i].status==EXIST)
                if(dump_offset == (bp[i].address - (textshdr.sh_addr - textshdr.sh_offset)))
                    buf[byte] = 0xcc;
        }
       
        if(byte == 0)
            fprintf(stderr, "%12lx: ", target + line*16);

        if(byte == 15)
        {
            for(int i=0 ; i<16 ; i++)
                fprintf(stderr, "%02x ", (unsigned char)buf[i]);

            fprintf(stderr, " |");
            for(int i=0 ; i<16 ; i++)
            {
                if(buf[i]>=32 && buf[i]<=126)
                    fprintf(stderr, "%c", buf[i]);
                else
                    fprintf(stderr, ".");
            }
            fprintf(stderr, "|\n");
            byte = 0;
            line++;
        }
        else
            byte++;

        count--;
        dump_offset++;
    }

    fclose(fp);

}

void c_disam(unsigned long target, int times)
{
    FILE *fp;

    if((fp=fopen(path_name, "r")) == NULL) errquit("fopen");

    char *text_content = (char*)malloc(sizeof(char)*textshdr.sh_size);
    fseek(fp, textshdr.sh_offset, SEEK_SET);
    fread(text_content, sizeof(char), textshdr.sh_size, fp);

    disassemble(text_content, textshdr.sh_size, textshdr.sh_addr, target, times);    

    fclose(fp);
}

void reset_bp(pid_t child)
{
    for(unsigned long i=0 ; i<bp_count ; i++)
    {
        if(bp[i].status == EXIST)
        {
            if(ptrace(PTRACE_POKETEXT, child, bp[i].address, (bp[i].orig_word & 0xffffffffffffff00) | 0xcc) != 0)
			    errquit("ptrace(POKETEXT)");
        }
    }
}

void parse_elf()
{
    FILE *fp;

    if((fp=fopen(path_name, "r")) == NULL) errquit("fopen");

    fread(&ehdr, sizeof(Elf64_Ehdr), 1, fp);

    fseek(fp, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);

    fread(&strshdr, sizeof(Elf64_Shdr), 1, fp);

    char name[10];
    for(int i=0 ; i<ehdr.e_shnum ; i++)
    {
        fseek(fp, ehdr.e_shoff + ehdr.e_shentsize * i, SEEK_SET);
        fread(&textshdr, sizeof(Elf64_Shdr), 1, fp);
        fseek(fp, strshdr.sh_offset + textshdr.sh_name, SEEK_SET);
        fread(name, sizeof(char), 10, fp);
        if(!strcmp(name, ".text"))
            break;
    }

    fclose(fp);
}
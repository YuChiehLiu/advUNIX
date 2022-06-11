#define NOT_LOADED 0
#define LOADED 2
#define RUNNING 4
#define EXIST 0
#define DELETED 2

extern int state;
extern char path_name[100];
extern int wait_status;
extern int is_script;
extern int is_file;
extern int is_restart;
extern Elf64_Ehdr ehdr;
extern Elf64_Shdr strshdr;
extern Elf64_Shdr textshdr;
extern pid_t CHILD;
extern char *args[2];

typedef struct breakpoint_struct
{
    unsigned int id;
    unsigned long orig_word;
    unsigned long address;
    unsigned int status;
}breakpoint_t;

void errquit(const char *msg);

void sdb(pid_t child, char *comm);

/* any */
void c_exit(pid_t child);
void c_help();
void c_list();


/* not loaded*/
void c_load();

/* loaded */
void c_start();

/* running*/
void c_run();
void c_cont(pid_t child);
void c_si(pid_t child);
int c_vmmap(pid_t child);
void c_getregs(pid_t child);
void c_getreg(pid_t child, char *reg_name);
void c_set(pid_t child, char *reg_name, unsigned long long val);
void c_break(pid_t child, unsigned long target);
void c_delete(pid_t child, int del_id);
void c_dump(char* path, unsigned long target);
void c_disam(unsigned long target, int times);

/* other */
void reset_bp(pid_t child);
void parse_elf();

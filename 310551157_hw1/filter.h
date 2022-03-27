#define TYPE_REGEX "^REG$|^DIR$|^CHR$|^FIFO$|^SOCK$|^unknown$"
#define C_IS_MATCH 1
#define T_IS_MATCH 2
#define F_IS_MATCH 3

extern char *c_flag, *t_flag, *f_flag;
extern int check_comm, check_type, check_fname;

int handel_flag(int argc, char* argv[]);
int is_type_valid();
int if_flag_match(char* target, int CTF);

void get_command(char* pid, char* comm);
struct passwd *get_username(char* pid);
void get_filetype(mode_t fmode, char* ftype);
void read_c_r_e(char* comm, char* pid, char* user, char* fd);
void read_maps(char* comm, char* pid, char* user);
void read_fd(char* comm, char* pid, char* user);
void get_openmode(mode_t fo_mode, char* modeflag);
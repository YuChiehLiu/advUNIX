#ifndef __PTOOLS_H__
#define __PTOOLS_H__

#include <sys/types.h>
#include <map>

typedef struct range_s {
	unsigned long begin, end;
}	range_t;

typedef struct map_entry_s {
	range_t range;
	int perm;
	long offset;
	std::string name;
}	map_entry_t;

bool operator<(range_t r1, range_t r2);
int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);
int disassemble(char* code, long unsigned int size, long unsigned int entry, unsigned long target, int print_times);
unsigned long long str2ULL(char *s);
int char2int(char c);

#endif /* __PTOOLS_H__ */

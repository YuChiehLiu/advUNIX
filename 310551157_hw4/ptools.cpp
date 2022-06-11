#include <stdio.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <inttypes.h>
#include <elf.h>

#include <sys/types.h>
#include <capstone/capstone.h>

#include <map>

#include "ptools.h"
#include "command.h"

using namespace std;

bool operator<(range_t r1, range_t r2) {
	if(r1.begin < r2.begin && r1.end < r2.end) return true;
	return false;
}

int load_maps(pid_t pid, map<range_t, map_entry_t>& loaded)
{
	char fn[128];
	char buf[256];
	FILE *fp;
	snprintf(fn, sizeof(fn), "/proc/%u/maps", pid);
	if((fp = fopen(fn, "rt")) == NULL) return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		int nargs = 0;
		char *token, *saveptr, *args[8], *ptr = buf;
		map_entry_t m;
		while(nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
			args[nargs++] = token;
			ptr = NULL;
		}
		if(nargs < 6) continue;
		if((ptr = strchr(args[0], '-')) != NULL) {
			*ptr = '\0';
			m.range.begin = strtol(args[0], NULL, 16);
			m.range.end = strtol(ptr+1, NULL, 16);
		}
		// m.name = basename(args[5]);
		m.name = args[5];
		m.perm = 0;
		if(args[1][0] == 'r') m.perm |= 0x04;
		if(args[1][1] == 'w') m.perm |= 0x02;
		if(args[1][2] == 'x') m.perm |= 0x01;
		m.offset = strtol(args[2], NULL, 16);
		fprintf(stderr, "%016lx-%016lx %c%c%c %lx\t%s\n", m.range.begin, m.range.end,args[1][0], args[1][1], args[1][2], m.offset, m.name.c_str());
		loaded[m.range] = m;
	}
	return (int) loaded.size();
}

int disassemble(char* code, long unsigned int size, long unsigned int entry, unsigned long target, int print_times)
{
	csh handle;
	cs_insn *insn;
	size_t count;
	int print_flag = 0;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, (unsigned char*)code, size, entry, 0, &insn);
	if (count > 0) {
		size_t j;
		int times=0;
		int intrs_begin=0, intrs_end=0, intrs_byte;
		for (j = 0; j < count; j++)
		{
			if(insn[j].address == target)
				print_flag = 1;
			if(print_flag && times < print_times)
			{
				intrs_end += insn[j+1].address - insn[j].address;

				fprintf(stderr, "%12lx: ", insn[j].address);

				if(j==count-1)
				{
					intrs_byte = size - intrs_begin;
					while(intrs_begin<(int)size)
					{
						fprintf(stderr, "%02x ", (unsigned char)code[intrs_begin]);
						intrs_begin++;
					}
					for(int i=0 ; i<5-intrs_byte ; i++)
					{
						fprintf(stderr, "   ");
					}
				}
				else
				{
					intrs_byte = intrs_end - intrs_begin;
					while(intrs_begin<intrs_end)
					{
						fprintf(stderr, "%02x ", (unsigned char)code[intrs_begin]);
						intrs_begin++;
					}
					for(int i=0 ; i<5-intrs_byte ; i++)
					{
						fprintf(stderr, "   ");
					}
				}

				fprintf(stderr, "\t\t\t%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
				times++;
				if(times==print_times)
					break;
			}
			else
			{
				intrs_begin += insn[j+1].address - insn[j].address;
				intrs_end = intrs_begin;
			}
		}
		if(j==count)
			fprintf(stderr, "** the address is out of the range of the text segment\n");
		
		cs_free(insn, count);
	} else
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

   return 0;
}

unsigned long long str2ULL(char *s)
{
	unsigned long long ret=0;
	int digits=strlen(s);
	if(strstr(s, "0x")!=NULL)
	{
		digits -= 2;
		for(unsigned long i=2 ; i<strlen(s) ; i++, digits--)
			ret += char2int(*(s+i)) * pow(16, digits-1);
	}
	else
	{
		for(unsigned long i=0 ; i<strlen(s) ; i++, digits--)
			ret += char2int(*(s+i)) * pow(10, digits-1);
	}

	return ret;
}

int char2int(char c)
{
    if(c>=48 && c<=57)
        return c-'0';
    else if(c>=97 && c<=102)
        return c-'a'+10;
	else if(c>=65 && c<=70)
        return c-'A'+10;
	else
		return -1;
}
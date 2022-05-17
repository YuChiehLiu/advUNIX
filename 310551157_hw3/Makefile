CC = gcc
ASM = yasm
LINKER = ld

AFLAGS = -f elf64 -DYASM -D__x86_64__ -DPIC
CFLAGS = -c -g -Wall -fno-stack-protector -fPIC -nostdlib
LFLAGS = -shared -o

ASRC = libmini64.asm
CSRC = libmini.c

AOBJ = libmini64.o
COBJ = libmini.o

LDOBJ = libmini.so

all : $(LDOBJ)

$(AOBJ): $(ASRC)
	$(ASM) $(AFLAGS) $< -o $@

$(COBJ): $(CSRC)
	$(CC) $(CFLAGS) $<

$(LDOBJ): $(AOBJ) $(COBJ)
	$(LINKER) $(LFLAGS) $@ $^

testcase/%1.o: testcase/%1.c
	$(CC) -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI $< -o $@

testcase/start.o: testcase/start.asm
	$(ASM) $(AFLAGS) $< -o $@

%1: testcase/%1.o testcase/start.o
	$(LINKER) -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o $@ $^ -L. -L.. -lmini	
	rm $^

.PHONY: clean
clean:
	rm *.o *.so 2>/dev/null

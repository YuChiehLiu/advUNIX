
CC	= gcc
CXX	= g++
CFLAGS	= -O3 -Wall -lcapstone
LDFLAGS =

ASM64	= yasm -f elf64 -DYASM -D__x86_64__
#ASM64	= nasm -f elf64 -DNASM -D__x86_64__

SRC_C = $(wildcard *.c)
SRC_CPP = $(wildcard *.cpp)
OBJS_t = $(patsubst %.c, %.o, $(SRC_C))
OBJS_t += $(patsubst %.cpp, %.o, $(SRC_CPP))
OBJS = $(filter-out autodbg.o, $(OBJS_t))

PROGS	= hw4

all: $(OBJS)
	$(CXX) $^ $(CFLAGS) -o $(PROGS)

%.o: %.c
	$(CC) -c -Wall -g $<

%.o: %.cpp
	$(CXX) -c -Wall -g $<

%.o: %.asm
	$(ASM64) $< -o $@

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(PROGS)

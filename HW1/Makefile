CC = gcc
CFLAGS = -g -Wall -Wextra -Werror

SRC = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRC))

EXE = hw1

all: $(OBJS)
	$(CC) $(OBJS) -o $(EXE)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

run:
	./$(EXE) | head -n 20

clean:
	rm $(EXE) *.o
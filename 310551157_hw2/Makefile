CC = gcc
CFLAGS = -g -Wall -Wextra
INJ_CFLAGS = -shared -fPIC

SRC = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRC))

EXE = logger
INJ = logger.so

all: $(filter-out injection.o, $(OBJS)) $(INJ)
	$(CC) $(CFLAGS) $(filter-out injection.o, $(OBJS)) -o $(EXE)
	
$(INJ): injection.c
	$(CC) $(INJ_CFLAGS) injection.c -ldl -o $(INJ)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: run
run:
	./$(EXE)

.PHONY: clean
clean:
	rm $(EXE) *.o $(INJ) 2>/dev/null
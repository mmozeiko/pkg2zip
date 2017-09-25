ifeq ($(OS),Windows_NT)
  RM := del /q
  EXE := .exe
else
  EXE :=
endif

BIN=pkg2zip${EXE}
SRC=${wildcard pkg2zip*.c} puff.c
OBJ=${SRC:.c=.o}
DEP=${SRC:.c=.d}

CFLAGS=-pipe -fvisibility=hidden -Wall -Wextra -DNDEBUG -O2
LDFLAGS=-s

.PHONY: all clean

all: ${BIN}

clean:
	@${RM} ${BIN} ${OBJ} ${DEP}

${BIN}: ${OBJ}
	@echo [L] $@
	@${CC} ${LDFLAGS} -o $@ $^

%_x86.o: %_x86.c
	@echo [C] $<
	@${CC} ${CFLAGS} -maes -mssse3 -MMD -c -o $@ $<

%.o: %.c
	@echo [C] $<
	@${CC} ${CFLAGS} -MMD -c -o $@ $<

-include ${DEP}

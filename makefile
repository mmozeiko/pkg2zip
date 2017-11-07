ifeq ($(OS),Windows_NT)
  RM := del /q
  EXE := .exe
else
  EXE :=
endif

BIN=pkg2zip${EXE}
SRC=${wildcard pkg2zip*.c} miniz_tdef.c puff.c
OBJ=${SRC:.c=.o}
DEP=${SRC:.c=.d}

CFLAGS=-std=c99 -pipe -fvisibility=hidden -Wall -Wextra -Werror -DNDEBUG -D_GNU_SOURCE -O2
LDFLAGS=-s

.PHONY: all clean

all: ${BIN}

clean:
	@${RM} ${BIN} ${OBJ} ${DEP}

${BIN}: ${OBJ}
	@echo [L] $@
	@${CC} ${LDFLAGS} -o $@ $^

%aes_x86.o: %aes_x86.c
	@echo [C] $<
	@${CC} ${CFLAGS} -maes -mssse3 -MMD -c -o $@ $<

%crc32_x86.o: %crc32_x86.c
	@echo [C] $<
	@${CC} ${CFLAGS} -mpclmul -msse4 -MMD -c -o $@ $<

%.o: %.c
	@echo [C] $<
	@${CC} ${CFLAGS} -MMD -c -o $@ $<

-include ${DEP}

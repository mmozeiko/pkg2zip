ifeq ($(OS),Windows_NT)
  RM := del /q
  EXE := .exe
else
  EXE :=
endif

DESTDIR =
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

BIN = pkg2zip${EXE}
SRC = ${wildcard pkg2zip*.c} miniz_tdef.c puff.c
OBJ = ${SRC:.c=.o}
DEP = ${SRC:.c=.d}

CFLAGS = -std=c99 -pipe -fvisibility=hidden -Wall -Wextra -Werror -DNDEBUG -D_GNU_SOURCE -O2
${BIN}: LDFLAGS += -s
debug: CFLAGS += -g
debug: LDFLAGS += -g

.PHONY: all clean

all: ${BIN}

install:
	install -o root -g root -m 0755 ${BIN} $(DESTDIR)$(BINDIR)/${BIN}
	install -o root -g root -m 0755 rif2zrif.py $(DESTDIR)$(BINDIR)/rif2zrif
	install -o root -g root -m 0755 zrif2rif.py $(DESTDIR)$(BINDIR)/zrif2rif

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/${BIN}
	rm -f $(DESTDIR)$(BINDIR)/rif2zrif
	rm -f $(DESTDIR)$(BINDIR)/zrif2rif

clean:
	@${RM} ${BIN} ${OBJ} ${DEP}

${BIN}: ${OBJ}
	@echo [L] $@
	@${CC} ${LDFLAGS} -o $@ $^

debug: ${OBJ}
	@echo [L] ${BIN}
	@${CC} ${LDFLAGS} -o ${BIN} $^

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

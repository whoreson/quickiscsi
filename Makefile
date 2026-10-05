# Makefile for quickiscsi
#
# POSIX (Linux, macOS, BSD, Solaris, AIX, OpenVMS POSIX kit):
#   make
#   make CC=cc        (use system cc)
#   make DEBUG=1      (add -g -O0)
#
# Cross-compile for Windows with MinGW:
#   make CC=x86_64-w64-mingw32-gcc LDFLAGS="-lws2_32"
#
# MSVC (Developer Command Prompt):
#   nmake /f Makefile.msvc    (see Makefile.msvc)
#
# OpenVMS (with DEC C / POSIX kit):
#   Compile each .c manually with CC /STANDARD=VAXC or equivalent.
#
# The binary is called 'quickiscsi' (or quickiscsi.exe on Windows).

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -ansi -pedantic -O2
LDFLAGS ?=

ifeq ($(DEBUG),1)
CFLAGS  += -g -O0 -DDEBUG
endif

# Large file support on Linux/glibc (needed for >2GB file images)
UNAME := $(shell uname -s 2>/dev/null || echo unknown)
ifneq ($(filter Linux GNU,$(UNAME)),)
CFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_DEFAULT_SOURCE
endif
ifneq ($(filter SunOS,$(UNAME)),)
CFLAGS += -D_FILE_OFFSET_BITS=64
endif

SRCS = server.c session.c backend.c config.c compat.c
OBJS = $(SRCS:.c=.o)
BIN  = quickiscsi

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Header dependencies (minimal, explicit)
server.o:  server.c  compat.h iscsi.h config.h session.h
session.o: session.c compat.h iscsi.h config.h session.h backend.h
backend.o: backend.c compat.h backend.h
config.o:  config.c  compat.h config.h backend.h
compat.o:  compat.c  compat.h

clean:
	rm -f $(OBJS) $(BIN) $(BIN).exe

install: $(BIN)
	install -m 755 $(BIN) /usr/local/sbin/$(BIN)
	@if [ ! -f /etc/quickiscsi.conf ]; then \
	    install -m 644 quickiscsi.conf.example /etc/quickiscsi.conf; \
	    echo "Installed example config to /etc/quickiscsi.conf"; \
	fi

.PHONY: all clean install

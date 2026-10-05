# quickiscsi

A lightweight, portable iSCSI target daemon written in C, designed for simplicity and cross-platform compatibility.

## Overview

`quickiscsi` implements the iSCSI Target Protocol (RFC 3720/3721) with minimal dependencies. It supports multiple storage backends:

- **file**: Regular file with sparse allocation (lazy allocation on creation)
- **block**: Raw block device (/dev/sdX, /dev/rdiskN) via pread/pwrite
- **ramdisk**: Volatile RAM buffer (malloc'd, lost on exit)

## Features

- **Multi-platform**
- **C89 compliant**: No C99/C++ features, portable integer types
- **Large file support**: 64-bit file offsets via _FILE_OFFSET_BITS=64
- **Clean shutdown**: SIGINT/SIGTERM handling (POSIX) / Ctrl+C (Windows)
- **iSCSI compliance**: Full login, logout, SCSI commands, ERL=1 StatSN tracking
- **Configurable**: Simple INI-style config file

## Building

### POSIX systems (Linux, BSD, macOS)

```bash
make
```

Options:
- `make DEBUG=1` - add debug symbols, no optimization
- `make CC=cc` - use system C compiler
- `make CC=x86_64-w64-mingw32-gcc LDFLAGS="-lws2_32"` - cross-compile for Windows (MinGW)

## Usage

```bash
./quickiscsi [-c config_file] [-v]
```

- `-c` : Specify config file (default: ./quickiscsi.conf or /etc/quickiscsi.conf)
- `-v` : Verbose output

## Configuration

Edit `quickiscsi.conf.example` for format reference.

### Components

- **server.c**: Main daemon loop, select() event loop, signal handling
- **session.c**: iSCSI state machine, login negotiation, SCSI command handling
- **backend.c/backend.h**: Storage backend abstraction (file/block/ramdisk)
- **config.c/config.h**: Configuration parsing
- **iscsi.h**: iSCSI protocol definitions, PDU structures, constants
- **compat.h**: Platform portability shims (types, sockets, etc.)

### iSCSI Stack

All I/O uses 512-byte blocks. The daemon handles:

- Login/Logout phases (security, login-op, full-feature)
- SCSI commands (READ, WRITE, INQUIRY, etc.)
- Data transfer sequencing (R2T, DATA-OUT)
- Error recovery with ERL=1 StatSN tracking

## Portability

Uses fixed-width types (`qd_u8`, `qd_u16`, `qd_u32`, etc.) instead of `stdint.h` for maximum C89 compatibility. Socket handling adapts to Winsock 1.x, Winsock 2, or POSIX.

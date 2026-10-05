/*
 * compat.h -- platform portability shims for quickdns
 *
 * Supports: POSIX (Linux, macOS, BSD, OpenVMS with POSIX kit),
 *           Win32/Win64 (MSVC, MinGW), Winsock 1.x (Windows 3.1 + win32s),
 *           DOS with packet drivers (Waterloo TCP), ancient UNIX.
 *
 * C89 only: no // comments, no C99 VLAs, no stdint.h assumed universal.
 * We define our own fixed-width types from first principles.
 */

#ifndef QUICKDNS_COMPAT_H
#define QUICKDNS_COMPAT_H

/* -------------------------------------------------------------------------
 * 1. Fixed-width integer types
 *    We cannot assume <stdint.h> (C99). Roll our own based on known sizes
 *    for the platforms we care about. If your platform is weird, fix here.
 * ---------------------------------------------------------------------- */

#if defined(_MSC_VER) && (_MSC_VER < 1600)
    /* MSVC before 2010 has no stdint.h */
    typedef unsigned char      qd_u8;
    typedef signed   char      qd_s8;
    typedef unsigned short     qd_u16;
    typedef signed   short     qd_s16;
    typedef unsigned int       qd_u32;
    typedef signed   int       qd_s32;
#elif defined(__WATCOMC__) || defined(__TURBOC__) || defined(__BORLANDC__)
    /* DOS-era compilers */
    typedef unsigned char      qd_u8;
    typedef signed   char      qd_s8;
    typedef unsigned short     qd_u16;
    typedef signed   short     qd_s16;
    typedef unsigned long      qd_u32;
    typedef signed   long      qd_s32;
#else
    /* Modern or POSIX — stdint.h likely available, but use our own names
     * to keep headers clean and avoid collisions. */
    typedef unsigned char      qd_u8;
    typedef signed   char      qd_s8;
    typedef unsigned short     qd_u16;
    typedef signed   short     qd_s16;
    typedef unsigned int       qd_u32;
    typedef signed   int       qd_s32;
#endif

/* Compile-time size assertions — will fail with negative array size trick */
typedef char assert_u8_is_1  [ sizeof(qd_u8)  == 1 ? 1 : -1];
typedef char assert_u16_is_2 [ sizeof(qd_u16) == 2 ? 1 : -1];
typedef char assert_u32_is_4 [ sizeof(qd_u32) == 4 ? 1 : -1];

/* -------------------------------------------------------------------------
 * 2. Socket portability
 * ---------------------------------------------------------------------- */

#if defined(_WIN32) || defined(_WIN16) || defined(__WINDOWS__)

#   if defined(_WIN32) || defined(_WIN64)
#       include <winsock2.h>
#       include <ws2tcpip.h>
        /* Link with: ws2_32.lib */
#       pragma comment(lib, "ws2_32.lib")
#   else
        /* Windows 3.x / Winsock 1.1 */
#       include <winsock.h>
#   endif

    typedef SOCKET          qd_sock_t;
    typedef int             qd_socklen_t;

#   define QD_INVALID_SOCK  INVALID_SOCKET
#   define QD_SOCK_ERROR    SOCKET_ERROR
#   define qd_close_sock(s) closesocket(s)
#   define qd_would_block() (WSAGetLastError() == WSAEWOULDBLOCK)
#   define qd_sock_errno()  WSAGetLastError()

    /* Make socket non-blocking */
#   define QD_SET_NONBLOCK(s) do { \
        u_long _nb = 1; \
        ioctlsocket((s), FIONBIO, &_nb); \
    } while(0)

    /* Winsock init/cleanup */
#   define QD_SOCK_INIT() do { \
        WSADATA _wsa; \
        WSAStartup(MAKEWORD(2,2), &_wsa); \
    } while(0)
#   define QD_SOCK_CLEANUP() WSACleanup()

    /* snprintf is _snprintf on old MSVC */
#   if defined(_MSC_VER) && (_MSC_VER < 1900)
#       define snprintf _snprintf
#   endif

#else
    /* POSIX: Linux, macOS, BSD, Solaris, AIX, OpenVMS POSIX kit, etc. */
#   include <sys/types.h>
#   include <sys/socket.h>
#   include <sys/select.h>
#ifndef __APPLE__
/* also defined in select.h on OS/X 10.4 */
#   include <sys/time.h>
#endif
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <netdb.h>
#   include <unistd.h>
#   include <fcntl.h>
#   include <errno.h>

    typedef int             qd_sock_t;
    typedef socklen_t       qd_socklen_t;

#   define QD_INVALID_SOCK  (-1)
#   define QD_SOCK_ERROR    (-1)
#   define qd_close_sock(s) close(s)
#   define qd_would_block() (errno == EAGAIN || errno == EWOULDBLOCK)
#   define qd_sock_errno()  errno

#   define QD_SET_NONBLOCK(s) do { \
        int _flags = fcntl((s), F_GETFL, 0); \
        fcntl((s), F_SETFL, _flags | O_NONBLOCK); \
    } while(0)

#   define QD_SOCK_INIT()    /* nothing */
#   define QD_SOCK_CLEANUP() /* nothing */

#endif /* socket portability */

/* -------------------------------------------------------------------------
 * 3. Time portability
 *    time_t is C89 standard. For sub-second precision we use struct timeval
 *    which is available everywhere we target (POSIX + Winsock).
 * ---------------------------------------------------------------------- */

#include <time.h>

#if defined(_WIN32) || defined(_WIN16) || defined(__WINDOWS__)
    /* gettimeofday is not available on Windows natively */
    int qd_gettimeofday(struct timeval *tv);
#else
    /* POSIX: gettimeofday is in sys/time.h already included above */
#   define qd_gettimeofday(tv) gettimeofday((tv), NULL)
#endif

/* Monotonic "seconds since some epoch" — used for TTL deadlines.
 * Just use time(NULL); it's good enough and universally available. */
#define qd_now() time(NULL)

/* -------------------------------------------------------------------------
 * 4. String / stdio portability
 * ---------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* snprintf is C99 / POSIX; hidden under strict -ansi with some compilers.
 * The MSVC shim is already above. For GCC/Clang in strict mode, declare it.
 * On any platform where compat.h is included, this declaration is safe:
 * the actual implementation comes from libc or from our own stub. */
#if defined(__STRICT_ANSI__) && !defined(_WIN32)
#   include <stdarg.h>
    extern int snprintf(char *str, size_t size, const char *fmt, ...);
#endif
char *qd_strdup(const char *s);

/* strlcpy-style safe copy: always NUL-terminates, returns src len */
size_t qd_strlcpy(char *dst, const char *src, size_t size);

/* Case-insensitive string compare (DNS names are case-insensitive) */
int qd_strcasecmp(const char *a, const char *b);
int qd_strncasecmp(const char *a, const char *b, size_t n);

/* -------------------------------------------------------------------------
 * 5. Byte-order macros
 *    htons/htonl/ntohs/ntohl are available everywhere (Winsock + POSIX).
 *    We add explicit big-endian read/write helpers for DNS wire format.
 * ---------------------------------------------------------------------- */

/* Read/write 16-bit big-endian from/to a byte buffer */
#define QD_READ_U16(p)  ((qd_u16)(((qd_u8*)(p))[0] << 8 | ((qd_u8*)(p))[1]))
#define QD_READ_U32(p)  ((qd_u32)(((qd_u8*)(p))[0] << 24 | \
                                   ((qd_u8*)(p))[1] << 16 | \
                                   ((qd_u8*)(p))[2] <<  8 | \
                                   ((qd_u8*)(p))[3]))

#define QD_WRITE_U16(p, v) do { \
    ((qd_u8*)(p))[0] = (qd_u8)(((v) >> 8) & 0xFF); \
    ((qd_u8*)(p))[1] = (qd_u8)(((v)     ) & 0xFF); \
} while(0)

#define QD_WRITE_U32(p, v) do { \
    ((qd_u8*)(p))[0] = (qd_u8)(((v) >> 24) & 0xFF); \
    ((qd_u8*)(p))[1] = (qd_u8)(((v) >> 16) & 0xFF); \
    ((qd_u8*)(p))[2] = (qd_u8)(((v) >>  8) & 0xFF); \
    ((qd_u8*)(p))[3] = (qd_u8)(((v)      ) & 0xFF); \
} while(0)

/* -------------------------------------------------------------------------
 * 6. Misc portability helpers
 * ---------------------------------------------------------------------- */

/* Silence "unused parameter" warnings portably */
#define QD_UNUSED(x) ((void)(x))

/* Branch prediction hints — degrade gracefully where unsupported */
#if defined(__GNUC__) && (__GNUC__ >= 3)
#   define QD_LIKELY(x)   __builtin_expect(!!(x), 1)
#   define QD_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#   define QD_LIKELY(x)   (x)
#   define QD_UNLIKELY(x) (x)
#endif

/* NULL definition safety */
#ifndef NULL
#   define NULL ((void*)0)
#endif

/* Boolean */
#ifndef __cplusplus
    typedef int qd_bool;
#   define QD_TRUE  1
#   define QD_FALSE 0
#else
    typedef bool qd_bool;
#   define QD_TRUE  true
#   define QD_FALSE false
#endif

/* Maximum sizes */
#define QD_MAX_DNAME      256   /* max DNS name in wire format (RFC 1035) */
#define QD_MAX_LABEL      64    /* max single label length                 */
#define QD_MAX_UDP        512   /* classic DNS UDP payload max             */
#define QD_MAX_EDNS_UDP   4096  /* EDNS0 extended UDP size                 */
#define QD_MAX_PATH       1024  /* filesystem path                         */
#define QD_MAX_LINE       2048  /* config file line                        */

/* -------------------------------------------------------------------------
 * 7. Platform detection string (for logging)
 * ---------------------------------------------------------------------- */

#if defined(_WIN64)
#   define QD_PLATFORM "win64"
#elif defined(_WIN32)
#   define QD_PLATFORM "win32"
#elif defined(_WIN16) || defined(__WINDOWS__)
#   define QD_PLATFORM "win16"
#elif defined(__linux__)
#   define QD_PLATFORM "linux"
#elif defined(__APPLE__)
#   define QD_PLATFORM "macos"
#elif defined(__FreeBSD__)
#   define QD_PLATFORM "freebsd"
#elif defined(__OpenBSD__)
#   define QD_PLATFORM "openbsd"
#elif defined(__NetBSD__)
#   define QD_PLATFORM "netbsd"
#elif defined(__sun)
#   define QD_PLATFORM "solaris"
#elif defined(_AIX)
#   define QD_PLATFORM "aix"
#elif defined(__VMS)
#   define QD_PLATFORM "openvms"
#else
#   define QD_PLATFORM "unknown"
#endif

#endif /* QUICKDNS_COMPAT_H */

/*
 * compat.c -- implementations of platform portability helpers
 *
 * Provides the function bodies declared in compat.h.
 * C89 clean.
 */

#include "compat.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * qd_strdup: portable strdup (POSIX not C89)
 * ---------------------------------------------------------------------- */

char *qd_strdup(const char *s)
{
    size_t len;
    char  *p;
    if (!s) return NULL;
    len = strlen(s) + 1;
    p = (char *)malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

/* -------------------------------------------------------------------------
 * qd_strlcpy: safe string copy, always NUL-terminates
 * Returns strlen(src).
 * ---------------------------------------------------------------------- */

size_t qd_strlcpy(char *dst, const char *src, size_t size)
{
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t copylen = srclen < size - 1 ? srclen : size - 1;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}

/* -------------------------------------------------------------------------
 * qd_strcasecmp / qd_strncasecmp
 * POSIX has strcasecmp, Windows has _stricmp — provide our own.
 * ---------------------------------------------------------------------- */

int qd_strcasecmp(const char *a, const char *b)
{
    unsigned char ca, cb;
    for (;;) {
        ca = (unsigned char)tolower((unsigned char)*a);
        cb = (unsigned char)tolower((unsigned char)*b);
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == '\0') return 0;
        a++; b++;
    }
}

int qd_strncasecmp(const char *a, const char *b, size_t n)
{
    unsigned char ca, cb;
    if (n == 0) return 0;
    for (; n > 0; n--, a++, b++) {
        ca = (unsigned char)tolower((unsigned char)*a);
        cb = (unsigned char)tolower((unsigned char)*b);
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * qd_gettimeofday for Windows
 * ---------------------------------------------------------------------- */

#if defined(_WIN32) || defined(_WIN16) || defined(__WINDOWS__)
#include <windows.h>

int qd_gettimeofday(struct timeval *tv)
{
    /*
     * Windows FILETIME is 100-nanosecond intervals since 1601-01-01.
     * Unix epoch offset: 116444736000000000 hundred-nanoseconds.
     */
    FILETIME        ft;
    ULARGE_INTEGER  li;
    unsigned __int64 t;

    if (!tv) return -1;

    GetSystemTimeAsFileTime(&ft);
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    t = li.QuadPart;
    t -= 116444736000000000ULL;  /* offset to Unix epoch */
    t /= 10;                      /* 100-ns -> microseconds */

    tv->tv_sec  = (long)(t / 1000000UL);
    tv->tv_usec = (long)(t % 1000000UL);
    return 0;
}
#endif /* Windows */

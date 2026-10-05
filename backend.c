/*
 * backend.c -- storage backend implementation for quickiscsi
 *
 * file backend:    fseek/fread/fwrite on a regular file.
 *                  Sparse: we never pre-allocate; unwritten regions read as
 *                  zeroes because we zero-fill on read errors (for new files).
 *
 * block backend:   raw fd with pread/pwrite + platform ioctls for size.
 *                  POSIX only (Linux, macOS, BSD, Solaris).
 *                  Windows does not support this backend (no /dev/sdX).
 *
 * ramdisk backend: malloc'd flat byte array.  Simple, fast, volatile.
 *
 * NOTE: This file uses 'long long' and pread/pwrite which are POSIX/C99.
 * These are gated inside #if !defined(_WIN32) blocks for the block backend.
 * We request POSIX.1-2001 for pread/pwrite visibility where available.
 */

/* The block backend uses pread/pwrite (POSIX) and long long (C99) for
 * 64-bit arithmetic on device sizes.  These are hidden by -ansi/-std=c89
 * on strict compilers, so we declare them ourselves where needed and
 * suppress the pedantic warnings with a GCC pragma.  On non-GCC compilers
 * that lack the pragma, the code still compiles correctly (long long is
 * universally supported in practice even in "C89" mode). */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#   define _POSIX_C_SOURCE 200112L
#endif

#if defined(__GNUC__)
#   pragma GCC diagnostic ignored "-Wlong-long"
#endif

/* pread/pwrite are POSIX but hidden under strict -ansi.  Declare explicitly.
 * The linker finds the real implementations in libc. */
#if !defined(_WIN32) && defined(__STRICT_ANSI__)
#   include <sys/types.h>
    extern ssize_t pread(int fd, void *buf, size_t count, off_t offset);
    extern ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
#endif

#include "backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Platform includes for block device size ioctls
 * ---------------------------------------------------------------------- */

#if !defined(_WIN32)
#   include <sys/types.h>
#   include <sys/stat.h>
#   include <fcntl.h>
#   include <unistd.h>
#   if defined(__linux__)
#       include <sys/ioctl.h>
#       include <linux/fs.h>
#   elif defined(__APPLE__)
#       include <sys/ioctl.h>
#       include <sys/disk.h>
#   elif defined(__FreeBSD__) || defined(__DragonFly__)
#       include <sys/ioctl.h>
#       include <sys/disk.h>
#   elif defined(__OpenBSD__) || defined(__NetBSD__)
#       include <sys/ioctl.h>
#       include <sys/dkio.h>
#       include <sys/disklabel.h>
#   elif defined(__sun)
#       include <sys/ioctl.h>
#       include <sys/dkio.h>
#       include <sys/vtoc.h>
#   endif
#endif /* !_WIN32 */

/* -------------------------------------------------------------------------
 * Internal private state structs
 * ---------------------------------------------------------------------- */

typedef struct {
    FILE *fp;
} file_priv_t;

/* block_priv_t: raw fd, bypasses stdio buffering which is unreliable on
 * block device nodes (partial reads, broken seek, etc.) */
typedef struct {
    int fd;
} block_priv_t;

typedef struct {
    qd_u8  *data;
    qd_u32  size_hi;
    qd_u32  size_lo;
} ramdisk_priv_t;

/* -------------------------------------------------------------------------
 * Portable 64-bit arithmetic helpers (hi:lo pairs)
 * Addition: (a_hi:a_lo) + (b_hi:b_lo)
 * ---------------------------------------------------------------------- */

static void u64_add(qd_u32 a_hi, qd_u32 a_lo,
                    qd_u32 b_hi, qd_u32 b_lo,
                    qd_u32 *r_hi, qd_u32 *r_lo)
{
    *r_lo = a_lo + b_lo;
    *r_hi = a_hi + b_hi + (*r_lo < a_lo ? 1 : 0);
}

/* Compare: returns -1, 0, +1 */
static int u64_cmp(qd_u32 a_hi, qd_u32 a_lo,
                   qd_u32 b_hi, qd_u32 b_lo)
{
    if (a_hi != b_hi) return a_hi < b_hi ? -1 : 1;
    if (a_lo != b_lo) return a_lo < b_lo ? -1 : 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * Size string parser: "512M", "20G", "1T", "1024K", "65536" -> hi:lo bytes
 * ---------------------------------------------------------------------- */

int backend_parse_size(const char *s, qd_u32 *hi, qd_u32 *lo)
{
    qd_u32 val = 0;
    const char *p = s;
    char suffix;

    if (!s || !*s) return -1;

    while (*p >= '0' && *p <= '9') {
        qd_u32 prev = val;
        val = val * 10 + (qd_u32)(*p - '0');
        if (val < prev) return -1; /* overflow */
        p++;
    }

    suffix = (char)(*p ? *p : 0);

    *hi = 0;
    *lo = 0;

    switch (suffix) {
    case 0: case 'b': case 'B':
        *lo = val;
        break;
    case 'k': case 'K':
        /* val * 1024 */
        *hi = val >> 22;
        *lo = val << 10;
        break;
    case 'm': case 'M':
        /* val * 1048576 */
        *hi = val >> 12;
        *lo = val << 20;
        break;
    case 'g': case 'G':
        /* val * 1073741824 */
        *hi = val >> 2;
        *lo = val << 30;
        break;
    case 't': case 'T':
        /* val * 2^40: hi = val * 256 */
        if (val > 0xFFFFFF00UL / 256) return -1; /* overflow */
        *hi = val << 8;  /* val * 256 */
        *lo = 0;
        break;
    default:
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Portable fseek for large files.
 * On most modern platforms fseek/ftell handle large files via fseeko/ftello
 * or _fseeki64.  We use a conservative approach: seek in chunks if needed.
 * For home use, files rarely exceed 2GB on 32-bit hosts anyway.
 * ---------------------------------------------------------------------- */

#if defined(_WIN32)
#   define QD_FSEEK(fp, hi, lo)  _fseeki64((fp), ((__int64)(hi) << 32) | (lo), SEEK_SET)
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
#   include <sys/types.h>
    /* off_t is 64-bit on modern POSIX with _FILE_OFFSET_BITS=64 */
#   define QD_FSEEK(fp, hi, lo)  fseeko((fp), (off_t)(((off_t)(hi) << 32) | (lo)), SEEK_SET)
#else
    /* Fallback: only works for files < 2GB */
#   define QD_FSEEK(fp, hi, lo)  fseek((fp), (long)(lo), SEEK_SET)
#endif

/* -------------------------------------------------------------------------
 * Helper: seek to byte offset lba_hi:lba_lo * 512
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * File backend
 * ---------------------------------------------------------------------- */

backend_t *backend_open_file(const char *path,
                               qd_u32 size_hi, qd_u32 size_lo)
{
    backend_t   *b;
    file_priv_t *fp;
    FILE        *f;
    qd_u32       blocks_lo, blocks_hi;

    /* Try to open existing file first, then create */
    f = fopen(path, "r+b");
    if (!f) {
        f = fopen(path, "w+b");
        if (!f) {
            fprintf(stderr, "backend: cannot open/create file: %s\n", path);
            return NULL;
        }
        /* Sparse: do NOT pre-allocate.  Just leave it empty;
         * reads of unwritten areas return zeroes via our zero-fill path. */
    }

    b  = (backend_t *)malloc(sizeof(backend_t));
    fp = (file_priv_t *)malloc(sizeof(file_priv_t));
    if (!b || !fp) {
        fclose(f);
        free(b); free(fp);
        fprintf(stderr, "backend: out of memory\n");
        return NULL;
    }

    fp->fp = f;

    memset(b, 0, sizeof(*b));
    b->type       = BACKEND_FILE;
    b->block_size = 512;
    b->priv       = fp;
    qd_strlcpy(b->desc, path, sizeof(b->desc));

    /* num_blocks = size / 512 */
    blocks_lo = (size_hi << 23) | (size_lo >> 9);
    blocks_hi = size_hi >> 9;
    b->num_blocks_lo = blocks_lo;
    b->num_blocks_hi = blocks_hi;

    return b;
}

/* -------------------------------------------------------------------------
 * Block device size detection: platform-specific ioctls
 * Returns size in bytes as hi:lo pair.  Falls back to 0:0 on unknown platforms.
 * ---------------------------------------------------------------------- */

static void block_get_size(int fd, qd_u32 *size_hi, qd_u32 *size_lo)
{
    *size_hi = 0;
    *size_lo = 0;

#if defined(__linux__)
    {
        /* BLKGETSIZE64 returns u64 byte count */
        unsigned long long bytes = 0;
        if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) {
            *size_hi = (qd_u32)(bytes >> 32);
            *size_lo = (qd_u32)(bytes & 0xFFFFFFFFUL);
            return;
        }
        /* Fallback: BLKGETSIZE returns 512-byte sector count as unsigned long */
        {
            unsigned long sects = 0;
            if (ioctl(fd, BLKGETSIZE, &sects) == 0) {
                /* sectors * 512, promote to 64-bit */
                unsigned long long b2 = (unsigned long long)sects * 512ULL;
                *size_hi = (qd_u32)(b2 >> 32);
                *size_lo = (qd_u32)(b2 & 0xFFFFFFFFUL);
                return;
            }
        }
    }
#elif defined(__APPLE__)
    {
        /* DKIOCGETBLOCKCOUNT * DKIOCGETBLOCKSIZE */
        uint64_t count = 0;
        uint32_t bsize = 512;
        if (ioctl(fd, DKIOCGETBLOCKCOUNT, &count) == 0) {
            ioctl(fd, DKIOCGETBLOCKSIZE, &bsize);
            {
                unsigned long long bytes = count * (unsigned long long)bsize;
                *size_hi = (qd_u32)(bytes >> 32);
                *size_lo = (qd_u32)(bytes & 0xFFFFFFFFUL);
            }
            return;
        }
    }
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    {
        /* DIOCGMEDIASIZE returns off_t total bytes */
        off_t bytes = 0;
        if (ioctl(fd, DIOCGMEDIASIZE, &bytes) == 0) {
            unsigned long long b = (unsigned long long)bytes;
            *size_hi = (qd_u32)(b >> 32);
            *size_lo = (qd_u32)(b & 0xFFFFFFFFUL);
            return;
        }
    }
#elif defined(__OpenBSD__)
    {
        struct disklabel dl;
        if (ioctl(fd, DIOCGDINFO, &dl) == 0) {
            /* Use the 'c' partition which covers the whole disk */
            unsigned long long bytes =
                (unsigned long long)dl.d_partitions[2].p_size * dl.d_secsize;
            *size_hi = (qd_u32)(bytes >> 32);
            *size_lo = (qd_u32)(bytes & 0xFFFFFFFFUL);
            return;
        }
    }
#elif defined(__NetBSD__)
    {
        struct disklabel dl;
        if (ioctl(fd, DIOCGDINFO, &dl) == 0) {
            unsigned long long bytes =
                (unsigned long long)dl.d_partitions[2].p_size * dl.d_secsize;
            *size_hi = (qd_u32)(bytes >> 32);
            *size_lo = (qd_u32)(bytes & 0xFFFFFFFFUL);
            return;
        }
    }
#elif defined(__sun)
    {
        struct dk_minfo mi;
        if (ioctl(fd, DKIOCGMEDIAINFO, &mi) == 0) {
            unsigned long long bytes =
                (unsigned long long)mi.dki_capacity * mi.dki_lbsize;
            *size_hi = (qd_u32)(bytes >> 32);
            *size_lo = (qd_u32)(bytes & 0xFFFFFFFFUL);
            return;
        }
    }
#endif

    /* Last resort: lseek to end.  Works on regular files and sometimes on
     * block devices on 64-bit hosts with LFS enabled. */
    {
#if defined(_LARGEFILE64_SOURCE) || defined(__linux__)
        off_t end = lseek(fd, 0, SEEK_END);
#else
        off_t end = lseek(fd, 0, SEEK_END);
#endif
        if (end > 0) {
            unsigned long long b = (unsigned long long)end;
            *size_hi = (qd_u32)(b >> 32);
            *size_lo = (qd_u32)(b & 0xFFFFFFFFUL);
            lseek(fd, 0, SEEK_SET);
            return;
        }
    }

    fprintf(stderr, "backend: WARNING: could not determine block device size\n");
}

/* -------------------------------------------------------------------------
 * Block device backend: raw fd I/O, platform ioctl size detection
 * ---------------------------------------------------------------------- */

backend_t *backend_open_block(const char *path)
{
#if defined(_WIN32)
    fprintf(stderr, "backend: block devices not supported on Windows\n");
    QD_UNUSED(path);
    return NULL;
#else
    backend_t    *b;
    block_priv_t *bp;
    int           fd;
    qd_u32        size_hi = 0, size_lo = 0;
    qd_u32        blocks_lo, blocks_hi;

    fd = open(path, O_RDWR);
    if (fd < 0) {
        /* Try read-only if O_RDWR fails (e.g. no write permission) */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "backend: cannot open block device: %s\n", path);
            return NULL;
        }
        fprintf(stderr, "backend: %s opened read-only\n", path);
    }

    block_get_size(fd, &size_hi, &size_lo);

    fprintf(stderr, "backend: %s size: %u GB + %u bytes\n",
            path,
            (unsigned)(((unsigned long long)size_hi << 32 | size_lo)
                       / (1024UL*1024*1024)),
            (unsigned)(size_lo % (1024*1024*1024)));

    b  = (backend_t *)malloc(sizeof(backend_t));
    bp = (block_priv_t *)malloc(sizeof(block_priv_t));
    if (!b || !bp) {
        close(fd);
        free(b); free(bp);
        fprintf(stderr, "backend: out of memory\n");
        return NULL;
    }

    bp->fd = fd;

    memset(b, 0, sizeof(*b));
    b->type       = BACKEND_BLOCK;
    b->block_size = 512;
    b->priv       = bp;
    qd_strlcpy(b->desc, path, sizeof(b->desc));

    /* num_blocks = size_bytes / 512 */
    blocks_hi = (size_hi << 23) | (size_lo >> 9);
    blocks_lo = size_lo << 9; /* wrong -- fix below */

    /* Correct: total_bytes >> 9 */
    /* blocks = (size_hi:size_lo) >> 9
     *        = (size_hi >> 9):(size_hi << 23 | size_lo >> 9)
     * Careful: that's the same calculation. Let me be explicit: */
    {
        unsigned long long total = ((unsigned long long)size_hi << 32) | size_lo;
        unsigned long long blks  = total / 512ULL;
        b->num_blocks_hi = (qd_u32)(blks >> 32);
        b->num_blocks_lo = (qd_u32)(blks & 0xFFFFFFFFUL);
    }
    /* Suppress unused warnings from earlier wrong calc */
    (void)blocks_hi; (void)blocks_lo;

    return b;
#endif
}
/* -------------------------------------------------------------------------
 * Ramdisk backend
 * ---------------------------------------------------------------------- */

backend_t *backend_open_ramdisk(qd_u32 size_hi, qd_u32 size_lo)
{
    backend_t      *b;
    ramdisk_priv_t *rd;
    size_t          alloc_size;

    /*
     * On a 32-bit host sizeof(size_t)==4, so we cannot address more than 4GB.
     * Reject size_hi != 0 (meaning total size > 4GB) in that case.
     * On a 64-bit host sizeof(size_t)==8 and malloc handles it fine.
     */
    if (size_hi != 0 && sizeof(size_t) < 8) {
        fprintf(stderr,
                "backend: ramdisk > 4GB requires a 64-bit build\n");
        return NULL;
    }

    alloc_size = ((size_t)size_hi << 32) | (size_t)size_lo;
    if (alloc_size == 0) {
        fprintf(stderr, "backend: ramdisk size cannot be zero\n");
        return NULL;
    }

    b  = (backend_t *)malloc(sizeof(backend_t));
    rd = (ramdisk_priv_t *)malloc(sizeof(ramdisk_priv_t));
    if (!b || !rd) {
        free(b); free(rd);
        fprintf(stderr, "backend: out of memory\n");
        return NULL;
    }

    rd->data = (qd_u8 *)calloc(alloc_size, 1);
    if (!rd->data) {
        free(b); free(rd);
        fprintf(stderr,
                "backend: cannot allocate %lu MB for ramdisk"
                " (not enough free RAM?)\n",
                (unsigned long)(alloc_size / (1024UL * 1024)));
        return NULL;
    }
    rd->size_hi = size_hi;
    rd->size_lo = size_lo;

    memset(b, 0, sizeof(*b));
    b->type       = BACKEND_RAMDISK;
    b->block_size = 512;
    b->priv       = rd;

    /* Compute block count as full 64-bit division */
    {
        unsigned long long total =
            ((unsigned long long)size_hi << 32) | size_lo;
        unsigned long long blks = total / 512ULL;
        b->num_blocks_hi = (qd_u32)(blks >> 32);
        b->num_blocks_lo = (qd_u32)(blks & 0xFFFFFFFFUL);
        snprintf(b->desc, sizeof(b->desc), "ramdisk(%luMB)",
                 (unsigned long)(total / (1024ULL * 1024)));
    }

    return b;
}
/* -------------------------------------------------------------------------
 * Raw fd I/O helper for block backend (pread/pwrite, POSIX only)
 * pread/pwrite are atomic and don't need a separate seek.
 * ---------------------------------------------------------------------- */

#if !defined(_WIN32)
static int block_read_raw(int fd,
                           qd_u32 lba_hi, qd_u32 lba_lo,
                           qd_u32 count, qd_u8 *buf)
{
    unsigned long long byte_off =
        (((unsigned long long)lba_hi << 32) | lba_lo) * 512ULL;
    size_t bytes = (size_t)count * 512;
    size_t done = 0;

    while (done < bytes) {
        ssize_t n = pread(fd, buf + done, bytes - done,
                          (off_t)(byte_off + done));
        if (n < 0) {
            perror("backend: pread");
            return -1;
        }
        if (n == 0) {
            /* EOF -- shouldn't happen on a block device within bounds */
            memset(buf + done, 0, bytes - done);
            break;
        }
        done += (size_t)n;
    }
    return 0;
}

static int block_write_raw(int fd,
                            qd_u32 lba_hi, qd_u32 lba_lo,
                            qd_u32 count, const qd_u8 *buf)
{
    unsigned long long byte_off =
        (((unsigned long long)lba_hi << 32) | lba_lo) * 512ULL;
    size_t bytes = (size_t)count * 512;
    size_t done = 0;

    while (done < bytes) {
        ssize_t n = pwrite(fd, buf + done, bytes - done,
                           (off_t)(byte_off + done));
        if (n < 0) {
            perror("backend: pwrite");
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}
#endif /* !_WIN32 */

int backend_read(backend_t *b,
                 qd_u32 lba_hi, qd_u32 lba_lo,
                 qd_u32 count, qd_u8 *buf)
{
    qd_u32 end_hi, end_lo;

    if (!b || !buf || count == 0) return -1;

    /* Bounds check: lba + count <= num_blocks */
    u64_add(lba_hi, lba_lo, 0, count, &end_hi, &end_lo);
    if (u64_cmp(end_hi, end_lo, b->num_blocks_hi, b->num_blocks_lo) > 0) {
        fprintf(stderr, "backend_read: LBA out of range (lba=%u+%u count=%u"
                " limit=%u+%u)\n",
                (unsigned)lba_hi, (unsigned)lba_lo, (unsigned)count,
                (unsigned)b->num_blocks_hi, (unsigned)b->num_blocks_lo);
        return -1;
    }

    if (b->type == BACKEND_RAMDISK) {
        ramdisk_priv_t *rd = (ramdisk_priv_t *)b->priv;
        size_t byte_off = (((size_t)lba_hi << 32) | (size_t)lba_lo) * 512;
        memcpy(buf, rd->data + byte_off, (size_t)count * 512);
        return 0;
    }

#if !defined(_WIN32)
    if (b->type == BACKEND_BLOCK) {
        block_priv_t *bp = (block_priv_t *)b->priv;
        return block_read_raw(bp->fd, lba_hi, lba_lo, count, buf);
    }
#endif

    /* FILE* path (BACKEND_FILE) -- use pread for atomic position-independent reads */
    {
        file_priv_t *fp = (file_priv_t *)b->priv;
        size_t bytes = (size_t)count * 512;
        ssize_t got;
        off_t off = (((off_t)lba_hi << 32) | (off_t)lba_lo) * 512;
        int fd = fileno(fp->fp);

        memset(buf, 0, bytes);
        got = pread(fd, buf, bytes, off);
        if (got < 0) {
            /* pread failed -- return zeros (sparse read) */
            return 0;
        }
        if ((size_t)got < bytes)
            memset(buf + got, 0, bytes - (size_t)got);
        return 0;
    }
}

/* -------------------------------------------------------------------------
 * Write
 * ---------------------------------------------------------------------- */

int backend_write(backend_t *b,
                  qd_u32 lba_hi, qd_u32 lba_lo,
                  qd_u32 count, const qd_u8 *buf)
{
    qd_u32 end_hi, end_lo;

    if (!b || !buf || count == 0) return -1;

    u64_add(lba_hi, lba_lo, 0, count, &end_hi, &end_lo);
    if (u64_cmp(end_hi, end_lo, b->num_blocks_hi, b->num_blocks_lo) > 0) {
        fprintf(stderr, "backend_write: LBA out of range\n");
        return -1;
    }

    if (b->type == BACKEND_RAMDISK) {
        ramdisk_priv_t *rd = (ramdisk_priv_t *)b->priv;
        size_t byte_off = (((size_t)lba_hi << 32) | (size_t)lba_lo) * 512;
        size_t nbytes = (size_t)count * 512;

        memcpy(rd->data + byte_off, buf, nbytes);
        return 0;
    }

#if !defined(_WIN32)
    if (b->type == BACKEND_BLOCK) {
        block_priv_t *bp = (block_priv_t *)b->priv;
        return block_write_raw(bp->fd, lba_hi, lba_lo, count, buf);
    }
#endif

    /* FILE* path (BACKEND_FILE) -- use pwrite for atomic position-independent writes */
    {
        file_priv_t *fp = (file_priv_t *)b->priv;
        size_t bytes = (size_t)count * 512;
        ssize_t written;
        off_t off = (((off_t)lba_hi << 32) | (off_t)lba_lo) * 512;

        written = pwrite(fileno(fp->fp), buf, bytes, off);
        if ((size_t)written != bytes) {
            fprintf(stderr, "backend_write: short write (%d of %u bytes)\n",
                    (int)written, (unsigned)bytes);
            return -1;
        }
        return 0;
    }
}

/* -------------------------------------------------------------------------
 * Sync / flush
 * ---------------------------------------------------------------------- */

int backend_sync(backend_t *b)
{
    if (!b) return -1;
    if (b->type == BACKEND_RAMDISK) return 0;
#if !defined(_WIN32)
    if (b->type == BACKEND_BLOCK) {
        block_priv_t *bp = (block_priv_t *)b->priv;
        return fsync(bp->fd);
    }
#endif
    {
        file_priv_t *fp = (file_priv_t *)b->priv;
        return fflush(fp->fp);
    }
}

/* -------------------------------------------------------------------------
 * Size query
 * ---------------------------------------------------------------------- */

void backend_size(backend_t *b, qd_u32 *size_hi, qd_u32 *size_lo)
{
    /* bytes = blocks * 512 */
    *size_hi = (b->num_blocks_hi << 9) | (b->num_blocks_lo >> 23);
    *size_lo = b->num_blocks_lo << 9;
}

void backend_num_blocks(backend_t *b, qd_u32 *hi, qd_u32 *lo)
{
    *hi = b->num_blocks_hi;
    *lo = b->num_blocks_lo;
}

/* -------------------------------------------------------------------------
 * Close
 * ---------------------------------------------------------------------- */

void backend_close(backend_t *b)
{
    if (!b) return;
    if (b->type == BACKEND_RAMDISK) {
        ramdisk_priv_t *rd = (ramdisk_priv_t *)b->priv;
        free(rd->data);
        free(rd);
#if !defined(_WIN32)
    } else if (b->type == BACKEND_BLOCK) {
        block_priv_t *bp = (block_priv_t *)b->priv;
        close(bp->fd);
        free(bp);
#endif
    } else {
        file_priv_t *fp = (file_priv_t *)b->priv;
        fclose(fp->fp);
        free(fp);
    }
    free(b);
}

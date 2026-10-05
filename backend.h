/*
 * backend.h -- storage backend abstraction for quickiscsi
 *
 * Three backends share a common interface:
 *   - file:    regular file (sparse, created on first use)
 *   - block:   raw block device (e.g. /dev/sda)  [POSIX only]
 *   - ramdisk: malloc'd byte array, size from config
 *
 * All I/O is synchronous. For a home server, this is fine.
 * C89 clean.
 */

#ifndef QUICKISCSI_BACKEND_H
#define QUICKISCSI_BACKEND_H

#include "compat.h"

/* Backend type tag */
typedef enum {
    BACKEND_FILE = 0,
    BACKEND_BLOCK,
    BACKEND_RAMDISK
} backend_type_t;

/*
 * backend_t: opaque handle passed to all I/O calls.
 * Callers should treat this as opaque; use the functions below.
 */
typedef struct backend_s backend_t;

struct backend_s {
    backend_type_t  type;

    /* Human-readable description for logging */
    char            desc[QD_MAX_PATH];

    /* Geometry */
    qd_u32          block_size;     /* always 512 for us          */
    qd_u32          num_blocks_hi;  /* high 32 bits of block count */
    qd_u32          num_blocks_lo;  /* low  32 bits of block count */

    /* Private state -- do not access directly */
    void           *priv;
};

/*
 * Parse a size string like "512M", "20G", "1T", "1024K", "65536".
 * Returns size in bytes split across *hi and *lo (for >4GB on 32-bit).
 * Returns 0 on success, -1 on parse error.
 */
int backend_parse_size(const char *s, qd_u32 *hi, qd_u32 *lo);

/*
 * Open / create backends.
 * On error, returns NULL and writes a message to stderr.
 */
backend_t *backend_open_file(const char *path,
                              qd_u32 size_hi, qd_u32 size_lo);

backend_t *backend_open_block(const char *path);

backend_t *backend_open_ramdisk(qd_u32 size_hi, qd_u32 size_lo);

/*
 * Read/write: lba is 64-bit (passed as hi+lo for C89 compat on 32-bit hosts).
 * count is number of 512-byte blocks.
 * buf must be at least count*512 bytes.
 * Returns 0 on success, -1 on error.
 */
int backend_read (backend_t *b,
                  qd_u32 lba_hi, qd_u32 lba_lo,
                  qd_u32 count, qd_u8 *buf);

int backend_write(backend_t *b,
                  qd_u32 lba_hi, qd_u32 lba_lo,
                  qd_u32 count, const qd_u8 *buf);

/* Flush (no-op for ramdisk/file in sync mode, kept for interface completeness) */
int backend_sync(backend_t *b);

/* Get total size in bytes (hi+lo for >4GB) */
void backend_size(backend_t *b, qd_u32 *size_hi, qd_u32 *size_lo);

/* Get total block count */
void backend_num_blocks(backend_t *b, qd_u32 *hi, qd_u32 *lo);

/* Close and free */
void backend_close(backend_t *b);

#endif /* QUICKISCSI_BACKEND_H */

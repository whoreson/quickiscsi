/*
 * config.c -- INI-style config parser for quickiscsi
 * C89 clean.
 */

#include "config.h"
#include <stdio.h>

#if defined(__GNUC__)
#   pragma GCC diagnostic ignored "-Wlong-long"
#endif
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* -------------------------------------------------------------------------
 * String helpers (can't assume strdup, strlcpy etc. from system)
 * ---------------------------------------------------------------------- */

/* Trim leading whitespace in place, return new start pointer */
static char *ltrim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

/* Trim trailing whitespace in place */
static void rtrim(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) {
        s[--len] = '\0';
    }
}

static void trim(char *s)
{
    /* shift left to trim leading, then rtrim */
    char *p = ltrim(s);
    if (p != s) memmove(s, p, strlen(p) + 1);
    rtrim(s);
}

/* -------------------------------------------------------------------------
 * Section/key parsing state machine
 * ---------------------------------------------------------------------- */

typedef enum {
    SEC_NONE = 0,
    SEC_GLOBAL,
    SEC_TARGET
} section_t;

/*
 * Parse a section header line like:
 *   [global]
 *   [target "myname"]
 * Returns SEC_GLOBAL or SEC_TARGET; fills name[64] for target sections.
 */
static section_t parse_section(const char *line, char *name, size_t namesz)
{
    const char *p = line;
    const char *end;
    size_t len;

    /* Skip '[' */
    if (*p != '[') return SEC_NONE;
    p++;

    /* Find ']' */
    end = strchr(p, ']');
    if (!end) return SEC_NONE;

    /* Check for "global" */
    if (strncmp(p, "global", 6) == 0 && (p[6] == ']' || isspace((unsigned char)p[6])))
        return SEC_GLOBAL;

    /* Check for target "name" */
    if (strncmp(p, "target", 6) == 0) {
        p += 6;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '"') {
            p++;
            end = strchr(p, '"');
            if (!end) return SEC_NONE;
            len = (size_t)(end - p);
            if (len >= namesz) len = namesz - 1;
            memcpy(name, p, len);
            name[len] = '\0';
            return SEC_TARGET;
        }
    }
    return SEC_NONE;
}

/* -------------------------------------------------------------------------
 * config_parse
 * ---------------------------------------------------------------------- */

int config_parse(const char *path, config_t *cfg)
{
    FILE      *f;
    char       line[QD_MAX_LINE];
    int        lineno = 0;
    section_t  cur_sec = SEC_NONE;
    target_cfg_t *cur_target = NULL;
    char       secname[64];

    memset(cfg, 0, sizeof(*cfg));

    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "config: cannot open '%s'\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *eq;
        char  key[64];
        char  val[QD_MAX_PATH];

        lineno++;

        /* Strip newline */
        {
            size_t len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = '\0';
        }

        p = ltrim(line);

        /* Blank line */
        if (!*p) continue;

        /* Comment */
        if (*p == ';' || *p == '#') continue;

        /* Section header */
        if (*p == '[') {
            memset(secname, 0, sizeof(secname));
            cur_sec = parse_section(p, secname, sizeof(secname));
            cur_target = NULL;

            if (cur_sec == SEC_TARGET) {
                if (cfg->num_targets >= CONFIG_MAX_TARGETS) {
                    fprintf(stderr, "config:%d: too many targets (max %d)\n",
                            lineno, CONFIG_MAX_TARGETS);
                    fclose(f);
                    return -1;
                }
                cur_target = &cfg->targets[cfg->num_targets++];
                memset(cur_target, 0, sizeof(*cur_target));
                qd_strlcpy(cur_target->name, secname, sizeof(cur_target->name));
                /* Default IQN: iqn.quickiscsi:<name> */
                snprintf(cur_target->iqn, sizeof(cur_target->iqn),
                         "iqn.quickiscsi:%s", secname);
            } else if (cur_sec == SEC_NONE) {
                fprintf(stderr, "config:%d: unrecognized section: %s\n",
                        lineno, p);
            }
            continue;
        }

        /* Key = value */
        eq = strchr(p, '=');
        if (!eq) {
            /* Could be a bare key; ignore */
            continue;
        }

        {
            size_t klen = (size_t)(eq - p);
            if (klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, p, klen);
            key[klen] = '\0';
            trim(key);

            qd_strlcpy(val, eq + 1, sizeof(val));
            trim(val);
        }

        if (!*key) continue;

        /* Global section keys */
        if (cur_sec == SEC_GLOBAL) {
            /* Currently no global keys; reserved for future use */
            /* (port is hardcoded, no auth, nothing else) */
            continue;
        }

        /* Target section keys */
        if (cur_sec == SEC_TARGET && cur_target) {
            if (strcmp(key, "iqn") == 0) {
                qd_strlcpy(cur_target->iqn, val, sizeof(cur_target->iqn));

            } else if (strcmp(key, "backend") == 0) {
                if (strcmp(val, "file") == 0)
                    cur_target->backend_type = BACKEND_FILE;
                else if (strcmp(val, "block") == 0)
                    cur_target->backend_type = BACKEND_BLOCK;
                else if (strcmp(val, "ramdisk") == 0)
                    cur_target->backend_type = BACKEND_RAMDISK;
                else
                    fprintf(stderr, "config:%d: unknown backend '%s'\n",
                            lineno, val);

            } else if (strcmp(key, "path") == 0) {
                qd_strlcpy(cur_target->path, val, sizeof(cur_target->path));

            } else if (strcmp(key, "size") == 0) {
                if (backend_parse_size(val,
                                       &cur_target->size_hi,
                                       &cur_target->size_lo) != 0) {
                    fprintf(stderr, "config:%d: invalid size '%s'\n",
                            lineno, val);
                }

            } else if (strcmp(key, "readonly") == 0) {
                cur_target->readonly = (strcmp(val, "yes") == 0 ||
                                        strcmp(val, "true") == 0 ||
                                        strcmp(val, "1") == 0)
                                       ? QD_TRUE : QD_FALSE;
            }
            /* Unrecognized keys silently ignored */
        }
    }

    fclose(f);
    return 0;
}

/* -------------------------------------------------------------------------
 * config_open_backends
 * ---------------------------------------------------------------------- */

int config_open_backends(config_t *cfg)
{
    int i, ok = 0;

    for (i = 0; i < cfg->num_targets; i++) {
        target_cfg_t *t = &cfg->targets[i];

        switch (t->backend_type) {
        case BACKEND_FILE:
            if (!t->path[0]) {
                fprintf(stderr, "config: target '%s': file backend needs path\n",
                        t->name);
                break;
            }
            t->backend = backend_open_file(t->path, t->size_hi, t->size_lo);
            break;

        case BACKEND_BLOCK:
            if (!t->path[0]) {
                fprintf(stderr, "config: target '%s': block backend needs path\n",
                        t->name);
                break;
            }
            t->backend = backend_open_block(t->path);
            break;

        case BACKEND_RAMDISK:
            if (t->size_lo == 0 && t->size_hi == 0) {
                fprintf(stderr, "config: target '%s': ramdisk needs size\n",
                        t->name);
                break;
            }
            t->backend = backend_open_ramdisk(t->size_hi, t->size_lo);
            break;
        }

        if (t->backend) {
            ok++;
            fprintf(stderr, "config: target '%s' [%s] -> %s\n",
                    t->name, t->iqn, t->backend->desc);
        } else {
            fprintf(stderr, "config: target '%s': FAILED to open backend\n",
                    t->name);
        }
    }

    return ok;
}

/* -------------------------------------------------------------------------
 * config_find_target
 * ---------------------------------------------------------------------- */

target_cfg_t *config_find_target(config_t *cfg, const char *iqn)
{
    int i;
    for (i = 0; i < cfg->num_targets; i++) {
        if (qd_strcasecmp(cfg->targets[i].iqn, iqn) == 0)
            return &cfg->targets[i];
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * config_free
 * ---------------------------------------------------------------------- */

void config_free(config_t *cfg)
{
    int i;
    for (i = 0; i < cfg->num_targets; i++) {
        if (cfg->targets[i].backend) {
            backend_close(cfg->targets[i].backend);
            cfg->targets[i].backend = NULL;
        }
    }
    memset(cfg, 0, sizeof(*cfg));
}

/* -------------------------------------------------------------------------
 * config_dump
 * ---------------------------------------------------------------------- */

void config_dump(const config_t *cfg)
{
    int i;
    printf("quickiscsi: %d target(s) configured\n", cfg->num_targets);
    for (i = 0; i < cfg->num_targets; i++) {
        const target_cfg_t *t = &cfg->targets[i];
        const char *btname = "unknown";
        if (t->backend_type == BACKEND_FILE)    btname = "file";
        if (t->backend_type == BACKEND_BLOCK)   btname = "block";
        if (t->backend_type == BACKEND_RAMDISK) btname = "ramdisk";
        printf("  [%d] name=%-20s iqn=%s\n", i, t->name, t->iqn);
        printf("       backend=%-8s", btname);
        if (t->path[0]) printf(" path=%s", t->path);
        if (t->size_lo || t->size_hi)
            {
                unsigned long long sz =
                    ((unsigned long long)t->size_hi << 32) | t->size_lo;
                printf(" size=%luMB", (unsigned long)(sz / (1024UL*1024)));
            }
        printf(" %s\n", t->backend ? "(open)" : "(FAILED)");
    }
}
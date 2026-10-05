/*
 * config.h -- INI-style config file parser for quickiscsi
 *
 * Format:
 *
 *   [global]
 *   ; comment lines start with ; or #
 *
 *   [target "mytarget"]
 *   iqn     = iqn.homelab:mytarget
 *   backend = file
 *   path    = /var/iscsi/mytarget.img
 *   size    = 20G
 *
 *   [target "ram0"]
 *   iqn     = iqn.homelab:ram0
 *   backend = ramdisk
 *   size    = 512M
 *
 *   [target "rawdisk"]
 *   iqn     = iqn.homelab:rawdisk
 *   backend = block
 *   path    = /dev/sdb
 *
 * Rules:
 *   - Sections are [global] or [target "name"]
 *   - Keys and values are separated by '='
 *   - Leading/trailing whitespace is stripped from keys and values
 *   - Comments: lines starting with ; or # (after stripping whitespace)
 *   - Blank lines are ignored
 *   - Unrecognized keys are silently ignored (forward compat)
 *
 * C89 clean.
 */

#ifndef QUICKISCSI_CONFIG_H
#define QUICKISCSI_CONFIG_H

#include "compat.h"
#include "iscsi.h"
#include "backend.h"

#define CONFIG_MAX_TARGETS  ISCSI_MAX_TARGETS

/* Target config entry */
typedef struct {
    char            name[64];               /* section name, e.g. "mytarget" */
    char            iqn[ISCSI_MAX_IQN];     /* IQN string                    */
    backend_type_t  backend_type;
    char            path[QD_MAX_PATH];      /* for file/block backends        */
    qd_u32          size_hi;                /* for file/ramdisk: size in bytes*/
    qd_u32          size_lo;
    backend_t      *backend;                /* opened at startup              */
    qd_bool         readonly;               /* future use                     */
} target_cfg_t;

/* Global config */
typedef struct {
    target_cfg_t    targets[CONFIG_MAX_TARGETS];
    int             num_targets;
} config_t;

/*
 * Parse config file at `path`.
 * Fills in *cfg.  Returns 0 on success, -1 on fatal error.
 * Warnings are printed to stderr but do not cause failure.
 */
int config_parse(const char *path, config_t *cfg);

/*
 * Open all backends referenced by the config.
 * Call after config_parse().
 * Returns number of successfully opened backends (should equal num_targets).
 */
int config_open_backends(config_t *cfg);

/*
 * Close all backends and free resources.
 */
void config_free(config_t *cfg);

/*
 * Find a target by IQN (case-insensitive).
 * Returns pointer into cfg->targets or NULL.
 */
target_cfg_t *config_find_target(config_t *cfg, const char *iqn);

/*
 * Print config summary to stdout (for -v / startup logging).
 */
void config_dump(const config_t *cfg);

#endif /* QUICKISCSI_CONFIG_H */

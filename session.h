/*
 * session.h -- per-connection iSCSI session state for quickiscsi
 *
 * One session_t per accepted TCP connection.
 * Handles login negotiation, full-feature phase PDU dispatch,
 * SCSI command emulation, and ERL=1 sequencing.
 *
 * C89 clean.
 *
 * Define QD_DEBUG before including this header to enable per-PDU
 * logging (BHS dumps, login key parsing, SCSI command traces).
 * Without QD_DEBUG, only errors and session lifecycle events log.
 */

#ifndef QD_DEBUG
#define QD_LOG(fmt, args...) ((void)0)
#else
#define QD_LOG(fmt, args...) fprintf(stderr, fmt, ##args)
#endif

#ifndef QUICKISCSI_SESSION_H
#define QUICKISCSI_SESSION_H

#include "compat.h"
#include "iscsi.h"
#include "config.h"

/* -------------------------------------------------------------------------
 * Session state
 * ---------------------------------------------------------------------- */

typedef enum sess_state_e {
    SESS_LOGIN_SECURITY  = 0,
    SESS_LOGIN_OP        = 1,
    SESS_FULL_FEATURE    = 2,
    SESS_LOGOUT          = 3,
    SESS_CLOSED          = 4
} sess_state_t;

/* Negotiated parameters (ERL=1 relevant ones) */
typedef struct {
    qd_u32  max_recv_data_seg;  /* initiator's MaxRecvDataSegmentLength     */
    qd_u32  max_burst;          /* MaxBurstLength                           */
    qd_u32  first_burst;        /* FirstBurstLength                         */
    qd_bool initial_r2t;        /* InitialR2T                               */
    qd_bool immediate_data;     /* ImmediateData                            */
    int     erl;                /* ErrorRecoveryLevel (0 or 1)              */
    qd_bool header_digest;      /* always false (we don't implement CRC)    */
    qd_bool data_digest;        /* always false                             */
    int     session_type;       /* 0=Normal, 1=Discovery                    */
    int     tpgt_sent;          /* TargetPortalGroupTag already sent        */
    qd_u32  time2wait;          /* negotiated DefaultTime2Wait (min)        */
    qd_u32  time2retain;        /* negotiated DefaultTime2Retain (min)      */
    qd_u32  max_outstanding_r2t;/* negotiated MaxOutstandingR2T             */
} sess_params_t;

/*
 * Pending write (DATA-OUT) tracker.
 * When InitialR2T=Yes and we receive a SCSI WRITE command,
 * we send an R2T and buffer state here until all DATA-OUT PDUs arrive.
 */
#define SESS_MAX_PENDING_WRITES  32

typedef struct {
    qd_bool  active;
    qd_u32   itt;            /* Initiator Task Tag                          */
    qd_u32   ttt;            /* Target Transfer Tag (our key)               */
    qd_u32   lba_hi;
    qd_u32   lba_lo;
    qd_u32   total_bytes;    /* total bytes expected                        */
    qd_u32   received;       /* bytes received so far                       */
    qd_u32   r2t_sn;         /* next R2T sequence number                    */
    qd_u32   r2ts_outstanding; /* R2Ts sent but not yet answered            */
    qd_u32   r2t_bytes;      /* bytes for which R2Ts have been sent         */
    qd_u8   *buf;            /* accumulation buffer (malloc'd)              */
    qd_u32   buf_size;
    target_cfg_t *target;    /* which target this write goes to             */
    qd_u8    lun;            /* LUN                                         */
    qd_u32   cmd_sn;         /* CmdSN of the originating command            */
} pending_write_t;

/* Per-session state */
typedef struct session_s {
    qd_sock_t       sock;
    sess_state_t    state;
    sess_params_t   params;

    /* Sequence numbers */
    qd_u32          stat_sn;       /* next StatSN to send                   */
    qd_u32          exp_cmd_sn;    /* next CmdSN expected from initiator    */
    qd_u32          max_cmd_sn;    /* max CmdSN we'll accept                */

    /* ERL=1: last StatSN sent (for retransmit detection) */
    qd_u32          last_stat_sn;
    qd_u32          cur_edtl;      /* EDTL of the SCSI command in progress */

    
    /* Login state */
    qd_u8           isid[6];        /* initiator session ID                 */
    qd_u16          tsih;           /* target session identifying handle    */
    char            initiator_name[ISCSI_MAX_IQN];

    /* Target this session is bound to (set during login) */
    target_cfg_t   *target;

    /* The config (for SendTargets discovery) */
    config_t       *cfg;

    /* Our local IP address (for SendTargets TargetAddress) */
    char            local_addr[64];

    /* Receive buffer for incoming PDU assembly */
    qd_u8           bhs[ISCSI_BHS_SIZE];
    qd_u8          *data_buf;       /* malloc'd, ISCSI_MAX_DATA_SEG         */
    qd_u32          data_buf_size;

    /* Pending writes (DATA-OUT accumulation) */
    pending_write_t pending_writes[SESS_MAX_PENDING_WRITES];

    /* TTT counter for R2T */
    qd_u32          next_ttt;

    /* Linked list for server's session pool */
    struct session_s *next;
} session_t;

/* -------------------------------------------------------------------------
 * API
 * ---------------------------------------------------------------------- */

/*
 * Allocate and initialise a new session for a just-accepted socket.
 * cfg is the global config (for target lookup and SendTargets).
 * initial_stat_sn must come from a global monotone counter in the caller
 * (see server.c g_next_stat_sn) so that open-iscsi's cross-reconnect
 * ExpStatSN tracking never sees a repeated StatSN value.
 */
session_t *session_new(qd_sock_t sock, config_t *cfg, qd_u32 initial_stat_sn, const char *local_addr);

/*
 * Drive the session: called by the main select() loop when the socket
 * is readable (or on initial call).
 *
 * Reads one complete PDU (BHS + data segment) and processes it.
 * Returns:
 *   0  -- PDU processed OK, keep going
 *  -1  -- session should be closed (error or logout complete)
 *   1  -- would-block (no full PDU available yet), try again later
 */
int session_drive(session_t *s);

/*
 * Free all resources.  Does NOT close the socket (caller does that).
 */
void session_free(session_t *s);

#endif /* QUICKISCSI_SESSION_H */

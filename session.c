/*
 * session.c -- iSCSI session state machine for quickiscsi
 *
 * Covers:
 *   - PDU recv/send helpers
 *   - Login negotiation (text key/value handling)
 *   - Full-feature phase dispatch
 *   - SCSI command emulation (READ, WRITE, INQUIRY, etc.)
 *   - R2T / DATA-OUT sequencing
 *   - ERL=1 StatSN tracking
 *   - Logout
 *
 * C89 clean.  Big file by necessity: the iSCSI state machine is not small.
 */

#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

/* =========================================================================
 * Forward declarations
 * ====================================================================== */

static int  recv_pdu(session_t *s, qd_u32 *dsl_out);
static int  send_raw(session_t *s, const qd_u8 *bhs,
                     const qd_u8 *data, qd_u32 dsl);

static int  login_parse_keys(session_t *s, qd_u32 dsl, int csg);
static qd_u32 build_op_keys(session_t *s, char *buf, qd_u32 pos, qd_u32 maxlen,
                            const char *req, qd_u32 req_len);
static qd_u32 add_tpgt(session_t *s, char *buf, qd_u32 pos, qd_u32 maxlen);
static int  handle_login(session_t *s, qd_u32 dsl);
static int  handle_full_feature(session_t *s, qd_u32 dsl);
static int  handle_scsi_cmd(session_t *s, qd_u32 dsl);
static int  handle_data_out(session_t *s, qd_u32 dsl);
static int  handle_nop_out(session_t *s, qd_u32 dsl);
static int  handle_logout(session_t *s, qd_u32 dsl);
static int  handle_text_req(session_t *s, qd_u32 dsl);
static int  handle_tmfunc(session_t *s, qd_u32 dsl);

static int  send_login_rsp(session_t *s, int transit,
                           int csg, int nsg,
                           qd_u8 status_class, qd_u8 status_detail,
                           const char *text, qd_u32 text_len);
static int  send_scsi_rsp(session_t *s, qd_u32 itt, qd_u32 cmd_sn,
                           qd_u8 scsi_status,
                           const qd_u8 *sense, qd_u16 sense_len,
                           qd_u32 residual, qd_bool underflow);
static int  send_data_in(session_t *s, qd_u32 itt, qd_u32 lun,
                          qd_u32 data_sn, qd_u32 buf_offset,
                          const qd_u8 *data, qd_u32 len,
                          qd_bool final, qd_u32 cmd_sn,
                          qd_u8 scsi_status, qd_bool status_in_last);
static int  send_r2t(session_t *s, pending_write_t *pw,
                     qd_u32 offset, qd_u32 desired);
static int  send_nop_in(session_t *s, qd_u32 itt, qd_u32 ttt);

static void build_sense(qd_u8 *buf, qd_u16 *len,
                         qd_u8 key, qd_u8 asc, qd_u8 ascq);

static int  scsi_dispatch(session_t *s, qd_u8 lun,
                           const qd_u8 *cdb, qd_u8 cdb_len,
                           qd_u32 edtl, qd_u32 itt, qd_u32 cmd_sn,
                           qd_bool is_write,
                           const qd_u8 *imm_data, qd_u32 imm_len);

static pending_write_t *find_pending_write_by_ttt(session_t *s, qd_u32 ttt);
static pending_write_t *alloc_pending_write(session_t *s);

/* =========================================================================
 * Text key/value helpers for login negotiation
 * ====================================================================== */

/*
 * Find value for key in NUL-separated key=value pairs.
 * iSCSI text segments are NUL-delimited "Key=Value\0Key=Value\0..." blobs.
 */
static const char *text_find(const char *buf, qd_u32 len, const char *key)
{
    qd_u32 pos = 0;
    size_t klen = strlen(key);

    while (pos < len) {
        const char *p = buf + pos;
        size_t plen = strlen(p);

        if (plen > klen + 1 &&
            qd_strncasecmp(p, key, klen) == 0 &&
            p[klen] == '=') {
            return p + klen + 1;
        }
        pos += (qd_u32)(plen + 1);
        if (pos >= len) break;
    }
    return NULL;
}

/* Append "Key=Value\0" to a text buffer.  Returns new length. */
static qd_u32 text_append(char *buf, qd_u32 pos, qd_u32 maxlen,
                            const char *key, const char *val)
{
    qd_u32 needed = (qd_u32)(strlen(key) + 1 + strlen(val) + 1);
    if (pos + needed > maxlen) return pos;
    memcpy(buf + pos, key, strlen(key));
    pos += (qd_u32)strlen(key);
    buf[pos++] = '=';
    memcpy(buf + pos, val, strlen(val));
    pos += (qd_u32)strlen(val);
    buf[pos++] = '\0';
    return pos;
}

/* =========================================================================
 * session_new / session_free
 * ====================================================================== */

session_t *session_new(qd_sock_t sock, config_t *cfg, qd_u32 initial_stat_sn, const char *local_addr)
{
    session_t *s = (session_t *)calloc(1, sizeof(session_t));
    if (!s) return NULL;

    s->sock            = sock;
    s->state           = SESS_LOGIN_SECURITY;
    s->cfg             = cfg;
    s->stat_sn         = initial_stat_sn;
    if (local_addr) {
        strncpy(s->local_addr, local_addr, sizeof(s->local_addr) - 1);
        s->local_addr[sizeof(s->local_addr) - 1] = '\0';
    } else {
        strcpy(s->local_addr, "0.0.0.0");
    }
    s->exp_cmd_sn      = 0;   /* seeded from initiator's CmdSN in handle_login */
    s->max_cmd_sn      = 32;  /* window of 32 outstanding commands */
    s->next_ttt        = 1;

    /* Default negotiated parameters */
    s->params.max_recv_data_seg = ISCSI_MAX_DATA_SEG;
    s->params.max_burst         = ISCSI_MAX_BURST;
    s->params.first_burst       = 65536;
    s->params.initial_r2t       = QD_TRUE;
    s->params.immediate_data    = QD_FALSE;
    s->params.erl               = 0;   /* ERL=0 only (no SNACK/recovery) */
    s->params.header_digest     = QD_FALSE;
    s->params.data_digest       = QD_FALSE;
    s->params.time2wait         = 2;
    s->params.time2retain       = 0;   /* 0 because ERL=0 */
    s->params.max_outstanding_r2t = 16;

    s->data_buf = (qd_u8 *)malloc(ISCSI_MAX_DATA_SEG + 4); /* +4 for pad */
    if (!s->data_buf) {
        free(s);
        return NULL;
    }
    s->data_buf_size = ISCSI_MAX_DATA_SEG;

    /* Assign a TSIH (1-based, just use low 16 bits of pointer for uniqueness) */
    s->tsih = (qd_u16)((size_t)s & 0xFFFF);
    if (s->tsih == 0) s->tsih = 1;

    return s;
}

void session_free(session_t *s)
{
    int i;
    if (!s) return;

    for (i = 0; i < SESS_MAX_PENDING_WRITES; i++) {
        if (s->pending_writes[i].buf) {
            free(s->pending_writes[i].buf);
            s->pending_writes[i].buf = NULL;
        }
    }
    if (s->data_buf) {
        free(s->data_buf);
        s->data_buf = NULL;
    }
    free(s);
}

/* =========================================================================
 * Low-level recv/send
 * ====================================================================== */

/*
 * Blocking recv of exactly `len` bytes.
 *
 * The socket is non-blocking (set by QD_SET_NONBLOCK in server.c), but we
 * are called only after select() reports the socket readable, so the first
 * recv() will always return at least one byte.  For subsequent bytes that
 * are not yet in the kernel buffer we must spin-wait rather than returning
 * a partial read: a partial BHS read would corrupt all subsequent framing
 * because recv_pdu() would try to parse the leftover bytes as the next BHS.
 *
 * The spin is safe here because:
 *   - PDUs are small (48-byte BHS + up to 64 KB data).
 *   - TCP will deliver the rest of the PDU within microseconds on a LAN.
 *   - We are single-threaded; there is no other work to do on this fd anyway.
 *
 * Returns 0 on success, -1 on error or peer close.
 * Never returns 1 (would-block) -- that would break framing.
 */
static int recv_exact(qd_sock_t sock, qd_u8 *buf, qd_u32 len)
{
    qd_u32 got = 0;
    while (got < len) {
        int n;
#if defined(_WIN32)
        n = recv(sock, (char *)(buf + got), (int)(len - got), 0);
        if (n == SOCKET_ERROR) {
            if (qd_would_block()) {
                /* Spin: yield the CPU briefly, then retry. */
                Sleep(0);
                continue;
            }
            return -1;
        }
#else
        n = (int)recv(sock, (char *)(buf + got), (size_t)(len - got), 0);
        if (n < 0) {
            if (qd_would_block()) {
                /* Wait briefly for more data.  Use a short timeout to avoid
                 * blocking the event loop for too long.  On a LAN, TCP segments
                 * arrive within milliseconds. */
                {
                    struct pollfd pfd;
                    pfd.fd = (int)sock;
                    pfd.events = POLLIN;
                    pfd.revents = 0;
                    if (poll(&pfd, 1, 1000) <= 0)  /* 1 second timeout */
                        return -1; /* timeout or error: give up */
                }
                continue;
            }
            if (errno == EINTR) continue;
            return -1;
        }
#endif
        if (n == 0) return -1; /* peer closed */
        got += (qd_u32)n;
    }
    return 0;
}

/*
 * Read a complete PDU: 48-byte BHS, then data segment (+ padding).
 * Data is stored in s->data_buf.
 * *dsl_out receives the data segment length.
 *
 * Returns 0 on success, -1 on error/close.
 * Does NOT return 1 (would-block): recv_exact() now spins until complete.
 * Returning a partial read would corrupt all subsequent PDU framing.
 */
static int recv_pdu(session_t *s, qd_u32 *dsl_out)
{
    int rc;
    qd_u32 dsl;
    qd_u32 padded;

    rc = recv_exact(s->sock, s->bhs, ISCSI_BHS_SIZE);
    if (rc != 0) return rc;

    dsl = BHS_DSL(s->bhs);
    *dsl_out = dsl;

    QD_LOG(
        "recv_pdu: opcode=0x%02x flags=0x%02x dsl=%u "
        "itt=0x%08x cmdsn=%u statsn=%u\n"
        "  BHS: %02x %02x %02x %02x  %02x %02x %02x %02x  "
              "%02x %02x %02x %02x  %02x %02x %02x %02x\n"
        "       %02x %02x %02x %02x  %02x %02x %02x %02x  "
              "%02x %02x %02x %02x  %02x %02x %02x %02x\n"
        "       %02x %02x %02x %02x  %02x %02x %02x %02x  "
              "%02x %02x %02x %02x  %02x %02x %02x %02x\n",
        (unsigned)(s->bhs[0] & 0x3f), (unsigned)s->bhs[1],
        (unsigned)dsl,
        (unsigned)BHS_ITT(s->bhs),
        (unsigned)BHS_CMDSN(s->bhs),
        (unsigned)BHS_EXPSTSN(s->bhs),
        s->bhs[0],s->bhs[1],s->bhs[2],s->bhs[3],
        s->bhs[4],s->bhs[5],s->bhs[6],s->bhs[7],
        s->bhs[8],s->bhs[9],s->bhs[10],s->bhs[11],
        s->bhs[12],s->bhs[13],s->bhs[14],s->bhs[15],
        s->bhs[16],s->bhs[17],s->bhs[18],s->bhs[19],
        s->bhs[20],s->bhs[21],s->bhs[22],s->bhs[23],
        s->bhs[24],s->bhs[25],s->bhs[26],s->bhs[27],
        s->bhs[28],s->bhs[29],s->bhs[30],s->bhs[31],
        s->bhs[32],s->bhs[33],s->bhs[34],s->bhs[35],
        s->bhs[36],s->bhs[37],s->bhs[38],s->bhs[39],
        s->bhs[40],s->bhs[41],s->bhs[42],s->bhs[43],
        s->bhs[44],s->bhs[45],s->bhs[46],s->bhs[47]);

    if (dsl == 0) return 0;

    padded = ISCSI_PAD4(dsl);

    if (padded > s->data_buf_size) {
        fprintf(stderr, "session: data segment too large: %u\n", dsl);
        return -1;
    }

    rc = recv_exact(s->sock, s->data_buf, padded);
    return rc;
}

/*
 * Send BHS + optional data (padded to 4 bytes).
 */
static int send_raw(session_t *s, const qd_u8 *bhs,
                    const qd_u8 *data, qd_u32 dsl)
{
    qd_u32 padded = ISCSI_PAD4(dsl);
    qd_u32 pad_len = padded - dsl;
    static const qd_u8 zeros[4] = {0,0,0,0};
    int n;

#define SEND_ALL(sock, buf, len) do {                               \
     qd_u32 _sent = 0;                                               \
     while (_sent < (len)) {                                         \
         n = (int)send((sock), (const char *)((buf) + _sent),        \
                       (size_t)((len) - _sent), MSG_NOSIGNAL);       \
        if (n < 0) {                                                \
            if (qd_would_block()) {                                 \
                /* Don't block: let the TCP stack buffer what it can. */ \
                break;                                              \
            }                                                       \
            perror("send_raw: send failed");                        \
            return -1;                                              \
        } else if (n == 0) {                                        \
            return -1;                                              \
        }                                                           \
         _sent += (qd_u32)n;                                         \
    } \
} while(0)

    SEND_ALL(s->sock, bhs, ISCSI_BHS_SIZE);
    if (dsl > 0 && data) {
        SEND_ALL(s->sock, data, dsl);
        if (pad_len > 0) {
            SEND_ALL(s->sock, zeros, pad_len);
        }
    }
#undef SEND_ALL
    return 0;
}

/* =========================================================================
 * session_drive -- main entry point called by select() loop
 * ====================================================================== */

int session_drive(session_t *s)
{
    qd_u32 dsl;
    int    rc;
    int    opcode;

    if (s->state == SESS_CLOSED) return -1;

    rc = recv_pdu(s, &dsl);
    if (rc != 0) {
        fprintf(stderr, "session_drive: recv_pdu returned %d (state=%d)\n", rc, (int)s->state);
        return rc;
    }

    opcode = BHS_OPCODE(s->bhs);

    if (s->state == SESS_LOGIN_SECURITY || s->state == SESS_LOGIN_OP) {
        if (opcode != ISCSI_OP_LOGIN_REQ) {
            fprintf(stderr, "session: expected LOGIN, got opcode 0x%02x\n",
                    opcode);
            return -1;
        }
        return handle_login(s, dsl);
    }

    return handle_full_feature(s, dsl);
}

/* =========================================================================
 * Login phase handler
 * ====================================================================== */

/*
 * login_parse_keys: scan a NUL-delimited text block and update negotiated
 * parameters.  Safe to call with dsl==0 (no-op).
 * Also handles target lookup and initiator name capture.
 * Returns 0 on success, -1 if target not found (error already sent).
 */
static int login_parse_keys(session_t *s, qd_u32 dsl, int csg)
{
    const char *text = (const char *)s->data_buf;
    const char *v;

    if (dsl == 0) return 0;

    /* DEBUG: dump all key=value pairs received from initiator */
    {
        qd_u32 pos = 0;
        QD_LOG( "login_parse_keys: CSG=%d dsl=%u keys from initiator:\n",
                csg, (unsigned)dsl);
        while (pos < dsl) {
            const char *p = text + pos;
            size_t plen = strlen(p);
            if (plen > 0)
                QD_LOG( "  [%u] '%s'\n", (unsigned)pos, p);
            pos += (qd_u32)(plen + 1);
            if (pos >= dsl) break;
        }
    }

    /* Initiator name */
    v = text_find(text, dsl, "InitiatorName");
    if (v && !s->initiator_name[0])
        qd_strlcpy(s->initiator_name, v, sizeof(s->initiator_name));

    /* Session type: remember for echoing in login response */
    {
        const char *st = text_find(text, dsl, "SessionType");
        if (st) {
            s->params.session_type = (qd_strcasecmp(st, "Discovery") == 0) ? 1 : 0;
        }
    }

    /* Target name: only meaningful for Normal sessions */
    v = text_find(text, dsl, "TargetName");
    if (v && !s->target) {
        s->target = config_find_target(s->cfg, v);
        if (!s->target) {
            fprintf(stderr, "session: login: target '%s' not found\n", v);
            send_login_rsp(s, 1, csg, csg,
                           ISCSI_LOGIN_INITIATOR_ERR, 0x04, NULL, 0);
            return -1;
        }
    }

    /* Operational parameters - enforce our limits but be more flexible */
    v = text_find(text, dsl, "InitialR2T");
    if (v) {
        /* Allow ImmediateData if requested but still require InitialR2T */
        if (qd_strcasecmp(v, "No") == 0)
            s->params.initial_r2t = QD_TRUE; /* Still requires R2T */
    }

    v = text_find(text, dsl, "ImmediateData");
    if (v) {
        /* Linux initiators often request ImmediateData=Yes */
        if (qd_strcasecmp(v, "Yes") == 0)
            s->params.immediate_data = QD_FALSE; /* Our backend doesn't support */
    }

    v = text_find(text, dsl, "MaxRecvDataSegmentLength");
    if (v) {
        qd_u32 req = (qd_u32)strtoul(v, NULL, 10);
        if (req > 0) {
            /* Cap at our buffer size but don't reject entirely */
            s->params.max_recv_data_seg =
                (req < ISCSI_MAX_DATA_SEG) ? req : ISCSI_MAX_DATA_SEG;
        }
    }
    v = text_find(text, dsl, "MaxBurstLength");
    if (v) {
        qd_u32 req = (qd_u32)strtoul(v, NULL, 10);
        if (req > 0 && req < s->params.max_burst)
            s->params.max_burst = req;
    }
    v = text_find(text, dsl, "FirstBurstLength");
    if (v) {
        qd_u32 req = (qd_u32)strtoul(v, NULL, 10);
        if (req > 0 && req < s->params.first_burst)
            s->params.first_burst = req;
    }
    v = text_find(text, dsl, "ErrorRecoveryLevel");
    if (v) {
        /* We only implement ERL=0 (no SNACK, no connection recovery). */
        s->params.erl = 0;
    }

    /* DefaultTime2Wait: RFC 3720 12.14 - target MUST NOT return value > requested. */
    v = text_find(text, dsl, "DefaultTime2Wait");
    if (v) {
        qd_u32 req = (qd_u32)strtoul(v, NULL, 10);
        s->params.time2wait = (req < 2) ? req : 2;
    }

    /* DefaultTime2Retain: RFC 3720 12.15 - same rule. MUST be 0 when ERL=0. */
    v = text_find(text, dsl, "DefaultTime2Retain");
    if (v) {
        qd_u32 req = (qd_u32)strtoul(v, NULL, 10);
        s->params.time2retain = (s->params.erl == 0) ? 0 : ((req < 20) ? req : 20);
    }

    /* MaxOutstandingR2T: RFC 3720 12.17 - result is min(ours, theirs).
     * We want 16 for pipelined writes. */
    v = text_find(text, dsl, "MaxOutstandingR2T");
    if (v) {
        qd_u32 req = (qd_u32)strtoul(v, NULL, 10);
        qd_u32 ours = 16;
        s->params.max_outstanding_r2t = (req < ours) ? req : ours;
    }

    /*
     * InitialR2T negotiation: RFC 3720 §12.11, result is OR (either side
     * can force Yes).  We always want Yes (simpler state machine), so the
     * result is always Yes regardless of what the initiator requests.
     * s->params.initial_r2t is already QD_TRUE from session_new().
     *
     * ImmediateData negotiation: RFC 3720 §12.12, result is AND (both must
     * agree Yes).  We advertise No, so result is No regardless of initiator.
     * s->params.immediate_data is already QD_FALSE from session_new().
     *
     * We don't need to read these from the PDU: our values are fixed and
     * the negotiation rules mean we always win (InitialR2T=Yes, ImmediateData=No).
     * We do however need to correctly ECHO back the negotiated result in
     * build_op_keys so the initiator knows what was agreed.
     */

    return 0;
}

/*
 * add_tpgt: append TargetPortalGroupTag once, for Normal sessions only.
 * RFC 3720 12.9: the target returns this key to a Normal session.
 * A Discovery session must not get it.
 */
static qd_u32 add_tpgt(session_t *s, char *buf, qd_u32 pos, qd_u32 maxlen)
{
    if (s->params.session_type || !s->target || s->params.tpgt_sent)
        return pos;
    s->params.tpgt_sent = 1;
    return text_append(buf, pos, maxlen, "TargetPortalGroupTag", "1");
}

/*
 * build_op_keys: answer the operational keys that the initiator sent.
 *
 * RULE: the target answers only keys that are in the request (req).
 * A key that the initiator did not send is a new proposal from the target.
 * The initiator must answer it in its next Login PDU. In a final response
 * (T=1) that makes the initiator send more Login PDUs. Windows does this:
 * it sends SessionType=NotUnderstood and <key>=Irrelevant, and then the
 * login sequence does not end.
 *
 * SessionType is an initiator-only key. The target must never send it.
 *
 * MaxRecvDataSegmentLength is declarative: we send our own receive limit
 * (ISCSI_MAX_DATA_SEG), not the value that the initiator declared.
 */
static qd_u32 build_op_keys(session_t *s, char *buf, qd_u32 pos, qd_u32 maxlen,
                            const char *req, qd_u32 req_len)
{
    char tmp[32];

#define IF_ASKED(k)  (text_find(req, req_len, (k)) != NULL)
#define ANSWER(k, v) \
    do { if (IF_ASKED(k)) pos = text_append(buf, pos, maxlen, (k), (v)); } while (0)

    pos = add_tpgt(s, buf, pos, maxlen);

    ANSWER("HeaderDigest",        "None");
    ANSWER("DataDigest",          "None");

    snprintf(tmp, sizeof(tmp), "%u", (unsigned)ISCSI_MAX_DATA_SEG);
    ANSWER("MaxRecvDataSegmentLength", tmp);

    /* All other keys are not relevant to a Discovery session. */
    if (s->params.session_type)
        return pos;

    ANSWER("InitialR2T",          "Yes");
    ANSWER("ImmediateData",       "No");
    ANSWER("OFMarker",            "No");
    ANSWER("IFMarker",            "No");
    ANSWER("MaxConnections",      "1");
    ANSWER("DataPDUInOrder",      "Yes");
    ANSWER("DataSequenceInOrder", "Yes");
    snprintf(tmp, sizeof(tmp), "%u", (unsigned)s->params.time2wait);
    ANSWER("DefaultTime2Wait", tmp);
    snprintf(tmp, sizeof(tmp), "%u", (unsigned)s->params.time2retain);
    ANSWER("DefaultTime2Retain", tmp);
    snprintf(tmp, sizeof(tmp), "%u", (unsigned)s->params.max_outstanding_r2t);
    ANSWER("MaxOutstandingR2T", tmp);

    snprintf(tmp, sizeof(tmp), "%u", (unsigned)s->params.max_burst);
    ANSWER("MaxBurstLength", tmp);

    snprintf(tmp, sizeof(tmp), "%u", (unsigned)s->params.first_burst);
    ANSWER("FirstBurstLength", tmp);

    snprintf(tmp, sizeof(tmp), "%d", s->params.erl);
    ANSWER("ErrorRecoveryLevel", tmp);

#undef ANSWER
#undef IF_ASKED
    return pos;
}

static int handle_login(session_t *s, qd_u32 dsl)
{
    int     transit = BHS_LOGIN_T(s->bhs);
    int     csg     = BHS_LOGIN_CSG(s->bhs);
    int     nsg     = BHS_LOGIN_NSG(s->bhs);
    char    rsp_text[ISCSI_MAX_TEXT_BUF];
    qd_u32  rsp_len = 0;

    QD_LOG( "login: state=%d T=%d CSG=%d NSG=%d dsl=%u\n",
            (int)s->state, transit, csg, nsg, (unsigned)dsl);

    /*
     * Sync our internal state to what the initiator says CSG is.
     * Some initiators (open-iscsi on reconnect, after a discovery session)
     * skip the security stage entirely and open with CSG=1 directly.
     * RFC 3720 permits this when the initiator already knows AuthMethod=None
     * is acceptable.  We must not lie about our current stage in the response.
     */
    if (csg == ISCSI_STAGE_LOGIN_OP && s->state == SESS_LOGIN_SECURITY) {
        /* Advance our state silently -- we'll skip sending AuthMethod */
        s->state = SESS_LOGIN_OP;
    }

    /* Capture ISID on every login PDU -- harmless to repeat since ISID
     * does not change within a login sequence. */
    memcpy(s->isid, BHS_ISID(s->bhs), 6);

    /* Seed ExpCmdSN from the initiator's opening CmdSN, but only once.
     *
     * session_new() initialises exp_cmd_sn=0 (calloc).  The first login
     * PDU carries the initiator's chosen opening CmdSN (typically 0, but
     * arbitrary per RFC).  We record it here so our login response
     * advertises the correct ExpCmdSN window from the start.
     *
     * We must NOT re-seed on subsequent PDUs within the same login exchange
     * (e.g. a multi-PDU login sequence) because the initiator increments
     * CmdSN between PDUs and re-seeding would reset our window counter.
     * The guard on exp_cmd_sn==0 is safe: the initiator's opening CmdSN is
     * always 0 on a brand-new session (RFC 3720 §10.12.1 says the first
     * CmdSN after login is ExpCmdSN from our response, so if we advertise
     * the right value here the subsequent commands will be in sequence).
     *
     * Note: handle_scsi_cmd does `s->exp_cmd_sn = cmd_sn + 1`, so we seed
     * to cmd_sn (not +1) here; the +1 happens when the first command lands.
     */
    if (s->exp_cmd_sn == 0)
        s->exp_cmd_sn = BHS_CMDSN(s->bhs) + 1;

    /* StatSN: sync from the initiator's ExpStatSN when appropriate.
     *
     * This follows the istgt approach: on a new session, adopt the
     * initiator's ExpStatSN so we start from where the initiator expects.
     *
     *   - open-iscsi: carries its persistent ExpStatSN (last StatSN seen + 1).
     *     If the server restarted, this value is higher than our starting
     *     counter, so we adopt it and avoid the "duplicate StatSN" drop.
     *   - FreeBSD iscontrol: sends ExpStatSN=0 for new sessions.  We keep
     *     our starting value (1) which is compatible.
     *
     * Only sync on the first login PDU (before stat_sn has been sent).
     * Only adopt if ExpStatSN > stat_sn (never go backwards).
     */
    {
        qd_u32 exp_stat_sn = BHS_EXPSTSN(s->bhs);

        if (exp_stat_sn > s->stat_sn) {
            s->stat_sn = exp_stat_sn;
        }
    }

    /* Parse all key=value pairs regardless of stage */
    if (login_parse_keys(s, dsl, csg) != 0)
        return -1;

    /*
     * State machine -- driven by CSG from the PDU (which we just synced to
     * s->state above), not by our internal state alone:
     *
     * Security stage (CSG=0):
     *   Respond AuthMethod=None.
     *   T=1,NSG=1 -> advance to operational.
     *   T=1,NSG=3 -> skip operational, go straight to full-feature
     *                (valid per RFC 3720 when no op params need negotiating).
     *
     * Operational stage (CSG=1):
     *   Respond with our negotiated op params.
     *   T=1,NSG=3 -> advance to full-feature.
     *   T=0       -> more exchanges; keep going.
     */

    if (csg == ISCSI_STAGE_SECURITY) {
        if (text_find((const char *)s->data_buf, dsl, "AuthMethod"))
            rsp_len = text_append(rsp_text, rsp_len, sizeof(rsp_text),
                                  "AuthMethod", "None");
        /* RFC 3720 12.9: TPGT goes in the first response to a Normal login */
        rsp_len = add_tpgt(s, rsp_text, rsp_len, sizeof(rsp_text));

        if (!transit) {
            return send_login_rsp(s, 0,
                                  ISCSI_STAGE_SECURITY, ISCSI_STAGE_SECURITY,
                                  ISCSI_LOGIN_SUCCESS, 0,
                                  rsp_text, rsp_len);
        }

        if (nsg == ISCSI_STAGE_FULL) {
            /* sec->full skip: include op params in this response */
            rsp_len = build_op_keys(s, rsp_text, rsp_len, sizeof(rsp_text),
                                    (const char *)s->data_buf, dsl);
            s->state = SESS_FULL_FEATURE;
            fprintf(stderr, "login: complete (sec->full), "
                    "initiator='%s' target='%s'\n",
                    s->initiator_name,
                    s->target ? s->target->iqn : "(discovery)");
            return send_login_rsp(s, 1,
                                  ISCSI_STAGE_SECURITY, ISCSI_STAGE_FULL,
                                  ISCSI_LOGIN_SUCCESS, 0,
                                  rsp_text, rsp_len);
        }

        /* NSG=1: advance to operational stage */
        s->state = SESS_LOGIN_OP;
        return send_login_rsp(s, 1,
                              ISCSI_STAGE_SECURITY, ISCSI_STAGE_LOGIN_OP,
                              ISCSI_LOGIN_SUCCESS, 0,
                              rsp_text, rsp_len);
    }

    if (csg == ISCSI_STAGE_LOGIN_OP) {
        rsp_len = build_op_keys(s, rsp_text, rsp_len, sizeof(rsp_text),
                                    (const char *)s->data_buf, dsl);

        if (!transit || nsg != ISCSI_STAGE_FULL) {
            return send_login_rsp(s, 0,
                                  ISCSI_STAGE_LOGIN_OP, ISCSI_STAGE_LOGIN_OP,
                                  ISCSI_LOGIN_SUCCESS, 0,
                                  rsp_text, rsp_len);
        }

        s->state = SESS_FULL_FEATURE;
        fprintf(stderr, "login: complete (op->full), "
                "initiator='%s' target='%s'\n",
                s->initiator_name,
                s->target ? s->target->iqn : "(discovery)");
        return send_login_rsp(s, 1,
                              ISCSI_STAGE_LOGIN_OP, ISCSI_STAGE_FULL,
                              ISCSI_LOGIN_SUCCESS, 0,
                              rsp_text, rsp_len);
    }

    fprintf(stderr, "login: unexpected CSG=%d\n", csg);
    return -1;
}

/* =========================================================================
 * send_login_rsp
 * ====================================================================== */

static int send_login_rsp(session_t *s, int transit,
                           int csg, int nsg,
                           qd_u8 status_class, qd_u8 status_detail,
                           const char *text, qd_u32 text_len)
{
    qd_u8 bhs[ISCSI_BHS_SIZE];
    memset(bhs, 0, sizeof(bhs));

    BHS_SET_OPCODE(bhs, ISCSI_OP_LOGIN_RSP);

    /* Byte 1: T|C|CSG|NSG.  C (continue) bit is 0 -- we never split. */
    bhs[1] = (qd_u8)(
        (transit ? 0x80 : 0) |
        ((csg & 3) << 2)     |
        (nsg & 3)
    );

    /* Version: active=0, min=0 (RFC 3720 §5.3) */
    BHS_SET_VERSION(bhs, 0x00, 0x00);

    BHS_SET_DSL(bhs, text_len);

    /* AHS length = 0 (byte 4 already 0 from memset) */

    BHS_SET_ISID(bhs, s->isid);
    /* TSIH=0 in all login requests *from* target until final response;
     * RFC 3720 §5.3: target sets TSIH=0 in all responses except the
     * final login response (where T=1 and transitioning to full-feature).
     * Setting it always here is fine since we generate a valid TSIH. */
    BHS_SET_TSIH(bhs, (transit && nsg == ISCSI_STAGE_FULL) ? s->tsih : 0);

    /* Mirror the ITT back */
    BHS_SET_ITT(bhs, BHS_ITT(s->bhs));

    /* CmdSN field (bytes 20-23): reserved in login response, leave 0 */

    /*
     * StatSN: RFC 3720 §10.13.4.
     *
     * Non-final login responses (T=0): StatSN field is 0 (reserved/unused).
     * The initiator does not update its ExpStatSN from these PDUs.
     *
     * Final login response (T=1, transitioning to full-feature phase):
     * StatSN is set to s->stat_sn, which comes from the globally monotone
     * counter in server.c (g_next_stat_sn, seeded from time(NULL)+1).
     * The field is then incremented so the next full-feature PDU carries
     * stat_sn+1, stat_sn+2, etc., never repeating a value.
     *
     * The initiator records the StatSN from this final response as its
     * initial ExpStatSN for the session.  open-iscsi validates every
     * subsequent StatSN against this baseline strictly; any gap, repeat,
     * or backward step causes an immediate session teardown.
     *
     * Macro hazard: BHS_SET_STATSN expands to QD_WRITE_U32, which
     * evaluates its value argument once per byte (four times total).
     * Passing `s->stat_sn++` directly would increment stat_sn four times
     * and write four successive byte values into the field instead of one
     * consistent 32-bit value.  Always capture to a local first:
     *   { qd_u32 _sn = s->stat_sn++; BHS_SET_STATSN(bhs, _sn); }
     */
    if (transit && nsg == ISCSI_STAGE_FULL) {
        /*
         * RFC 3720 §10.13.4: the final login response carries the session's
         * initial StatSN and consumes it (post-increment).  The initiator
         * sets ExpStatSN = received_StatSN + 1 after seeing this PDU, so
         * the first full-feature response must carry stat_sn (the incremented
         * value) or the initiator will see a repeated StatSN and drop it.
         */
        { qd_u32 _sn = s->stat_sn++; BHS_SET_STATSN(bhs, _sn); }
    } else {
        BHS_SET_STATSN(bhs, 0);
    }

    /* ExpCmdSN and MaxCmdSN: set to track the window */
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }

    /* Status class/detail in bytes 36-37 */
    bhs[36] = status_class;
    bhs[37] = status_detail;

    QD_LOG(
        "login_rsp: T=%d CSG=%d NSG=%d status=%02x:%02x text_len=%u"
        " StatSN(wire)=%u ExpCmdSN(wire)=%u\n"
        "  BHS: %02x %02x %02x %02x  %02x %02x %02x %02x  "
              "%02x %02x %02x %02x  %02x %02x %02x %02x\n"
        "       %02x %02x %02x %02x  %02x %02x %02x %02x  "
              "%02x %02x %02x %02x  %02x %02x %02x %02x\n"
        "       %02x %02x %02x %02x  %02x %02x %02x %02x  "
              "%02x %02x %02x %02x  %02x %02x %02x %02x\n",
        transit, csg, nsg, status_class, status_detail,
        (unsigned)text_len,
        (unsigned)BHS_STATSN(bhs), (unsigned)BHS_EXPCMDSN(bhs),
        bhs[0],bhs[1],bhs[2],bhs[3],bhs[4],bhs[5],bhs[6],bhs[7],
        bhs[8],bhs[9],bhs[10],bhs[11],bhs[12],bhs[13],bhs[14],bhs[15],
        bhs[16],bhs[17],bhs[18],bhs[19],bhs[20],bhs[21],bhs[22],bhs[23],
        bhs[24],bhs[25],bhs[26],bhs[27],bhs[28],bhs[29],bhs[30],bhs[31],
        bhs[32],bhs[33],bhs[34],bhs[35],bhs[36],bhs[37],bhs[38],bhs[39],
        bhs[40],bhs[41],bhs[42],bhs[43],bhs[44],bhs[45],bhs[46],bhs[47]);

    return send_raw(s, bhs, (const qd_u8 *)text, text_len);
}

/* =========================================================================
 * Full-feature phase dispatcher
 * ====================================================================== */

static int handle_full_feature(session_t *s, qd_u32 dsl)
{
    int opcode = BHS_OPCODE(s->bhs);

    switch (opcode) {
    case ISCSI_OP_SCSI_CMD:      return handle_scsi_cmd(s, dsl);
    case ISCSI_OP_SCSI_DATA_OUT: return handle_data_out(s, dsl);
    case ISCSI_OP_NOP_OUT:       return handle_nop_out(s, dsl);
    case ISCSI_OP_LOGOUT_REQ:    return handle_logout(s, dsl);
    case ISCSI_OP_TEXT_REQ:      return handle_text_req(s, dsl);
    case ISCSI_OP_SCSI_TMFUNC:   return handle_tmfunc(s, dsl);
    default:
        if (opcode == ISCSI_OP_LOGIN_REQ) {
            /* Protocol error: login PDU in full-feature phase. Reject and close. */
            fprintf(stderr, "session: Login in full-feature phase -- rejected\n");
            return -1;
        }
        fprintf(stderr, "session: unknown opcode 0x%02x in full-feature\n",
                opcode);
        return 0;
    }
}

/* =========================================================================
 * NOP-Out handler: respond with NOP-In (ping/keepalive)
 * ====================================================================== */

static int handle_nop_out(session_t *s, qd_u32 dsl)
{
    qd_u32 itt = BHS_ITT(s->bhs);
    qd_u32 ttt = BHS_TTT(s->bhs);
    qd_u32 cmd_sn = BHS_CMDSN(s->bhs);
    qd_u32 exp_stat_sn = BHS_EXPSTSN(s->bhs);

    QD_UNUSED(dsl);

    /*
     * RFC 3720 §10.18.1: when ITT != 0xFFFFFFFF, the NOP-Out is a queued
     * command and CmdSN advances ExpCmdSN.  When ITT == 0xFFFFFFFF it is a
     * response to a target-initiated NOP-In and does NOT advance CmdSN.
     *
     * For unsolicited pings (TTT == RSVD_TTT), ITT is set by the initiator
     * and is not 0xFFFFFFFF, so we DO advance ExpCmdSN.
     */
    if (ttt == ISCSI_RSVD_TTT) {
        /* Unsolicited ping: advance ExpCmdSN */
        s->exp_cmd_sn = cmd_sn + 1;
    }

    /*
     * Do NOT blindly advance s->stat_sn from the initiator's ExpStatSN.
     * The initiator's ExpStatSN tells us which StatSNs it has received and
     * acknowledged -- it cannot be ahead of what we have actually sent.
     * Advancing our stat_sn to match would create a gap in the StatSN
     * sequence, causing the initiator to see a StatSN that was never sent
     * (it would look like a retransmit or a sequence skip and drop the
     * session).  We simply note it for debugging.
     */
    if ((qd_s32)(exp_stat_sn - s->stat_sn) > 0) {
    }

    if (ttt != ISCSI_RSVD_TTT) {
        /* Response to a NOP-In we sent — no reply needed. */
        return 0;
    }

    /*
     * Unsolicited NOP-Out (TTT=0xFFFFFFFF): initiator is pinging us.
     * Reply with NOP-In echoing the ITT.
     */

    {
        int rc = send_nop_in(s, itt, ISCSI_RSVD_TTT);
        return rc;
    }
}

static int send_nop_in(session_t *s, qd_u32 itt, qd_u32 ttt)
{
    qd_u8 bhs[ISCSI_BHS_SIZE];
    memset(bhs, 0, sizeof(bhs));
    BHS_SET_OPCODE(bhs, ISCSI_OP_NOP_IN);
    BHS_SET_FLAGS(bhs, ISCSI_FLAG_FINAL);
    BHS_SET_ITT(bhs, itt);
    BHS_SET_TTT(bhs, ttt);

    /*
     * RFC 3720 §10.19: NOP-In sent in response to a NOP-Out (ITT != RSVD)
     * carries a real StatSN and DOES consume one, just like any other
     * response PDU.  istgt: DSET32(&rsp[24], conn->StatSN); conn->StatSN++
     *
     * A target-initiated NOP-In (ITT == 0xFFFFFFFF, soliciting a NOP-Out)
     * does NOT consume a StatSN -- StatSN is sent but not incremented.
     * istgt handles this separately and skips the increment.
     *
     * We currently only send NOP-In as a reply to NOP-Out (TTT=RSVD_TTT),
     * so we always increment here.
     */
    { qd_u32 _sn = s->stat_sn++; BHS_SET_STATSN(bhs, _sn); }
    s->last_stat_sn = s->stat_sn - 1;
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }

    return send_raw(s, bhs, NULL, 0);
}

/* =========================================================================
 * Logout handler
 * ====================================================================== */

static int handle_logout(session_t *s, qd_u32 dsl)
{
    qd_u8 bhs[ISCSI_BHS_SIZE];
    QD_UNUSED(dsl);

    s->exp_cmd_sn = BHS_CMDSN(s->bhs) + 1;

    memset(bhs, 0, sizeof(bhs));
    BHS_SET_OPCODE(bhs, ISCSI_OP_LOGOUT_RSP);
    BHS_SET_FLAGS(bhs, ISCSI_FLAG_FINAL);
    BHS_SET_ITT(bhs, BHS_ITT(s->bhs));
    bhs[2] = ISCSI_LOGOUT_RSP_SUCCESS;
    { qd_u32 _sn = s->stat_sn++; BHS_SET_STATSN(bhs, _sn); }
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }

    send_raw(s, bhs, NULL, 0);
    s->state = SESS_CLOSED;
    return -1;
}

/* =========================================================================
 * Text Request handler (for SendTargets discovery)
 * ====================================================================== */

/* =========================================================================
 * Task Management Function Request handler
 * RFC 3720 s10.5/10.6: We must respond to every TMF Request or the
 * initiator will hang waiting.  We implement the minimum: ABORT TASK,
 * ABORT TASK SET, LOGICAL UNIT RESET, TARGET WARM RESET all respond
 * with "Function Complete" (response code 0x00).
 * ====================================================================== */

/* TMF function codes */
#define ISCSI_TMF_ABORT_TASK        1
#define ISCSI_TMF_ABORT_TASK_SET    2
#define ISCSI_TMF_CLEAR_ACA         3
#define ISCSI_TMF_CLEAR_TASK_SET    4
#define ISCSI_TMF_LUN_RESET         5
#define ISCSI_TMF_TARGET_WARM_RESET 6
#define ISCSI_TMF_TARGET_COLD_RESET 7
#define ISCSI_TMF_TASK_REASSIGN     8

/* TMF response codes */
#define ISCSI_TMF_RSP_COMPLETE      0x00
#define ISCSI_TMF_RSP_NO_TASK       0x01
#define ISCSI_TMF_RSP_NO_LUN        0x02
#define ISCSI_TMF_RSP_REJECTED      0x05
#define ISCSI_TMF_RSP_FAILED        0x05

static int handle_tmfunc(session_t *s, qd_u32 dsl)
{
    qd_u8  bhs[ISCSI_BHS_SIZE];
    qd_u8  func;
    qd_u8  rsp_code;

    QD_UNUSED(dsl);

    /* Function code is in low 7 bits of byte 1 */
    func = s->bhs[1] & 0x7F;

    s->exp_cmd_sn = BHS_CMDSN(s->bhs) + 1;

    fprintf(stderr, "session: TMF func=%u lun=%u\n",
            (unsigned)func, (unsigned)s->bhs[9]);

    switch (func) {
    case ISCSI_TMF_ABORT_TASK:
    case ISCSI_TMF_ABORT_TASK_SET:
    case ISCSI_TMF_CLEAR_ACA:
    case ISCSI_TMF_CLEAR_TASK_SET:
    case ISCSI_TMF_LUN_RESET:
    case ISCSI_TMF_TARGET_WARM_RESET:
    case ISCSI_TMF_TARGET_COLD_RESET:
        rsp_code = ISCSI_TMF_RSP_COMPLETE;
        break;
    case ISCSI_TMF_TASK_REASSIGN:
        /* We don't support MC/S so reassign is not possible */
        rsp_code = ISCSI_TMF_RSP_REJECTED;
        break;
    default:
        rsp_code = ISCSI_TMF_RSP_REJECTED;
        break;
    }

    memset(bhs, 0, sizeof(bhs));
    BHS_SET_OPCODE(bhs, ISCSI_OP_SCSI_TMFUNC_RSP);
    BHS_SET_FLAGS(bhs, ISCSI_FLAG_FINAL);
    bhs[2] = rsp_code;
    BHS_SET_ITT(bhs, BHS_ITT(s->bhs));
    BHS_SET_TTT(bhs, ISCSI_RSVD_TTT);
    { qd_u32 _sn = s->stat_sn++; BHS_SET_STATSN(bhs, _sn); }
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }
    s->last_stat_sn = s->stat_sn - 1;

    return send_raw(s, bhs, NULL, 0);
}

static int handle_text_req(session_t *s, qd_u32 dsl)
{
    const char *text = (const char *)s->data_buf;
    char        rsp[ISCSI_MAX_TEXT_BUF];
    qd_u32      rsp_len = 0;
    qd_u8       bhs[ISCSI_BHS_SIZE];
    const char *v;
    int         i;

    s->exp_cmd_sn = BHS_CMDSN(s->bhs) + 1;

    v = text_find(text, dsl, "SendTargets");
    if (v) {
        fprintf(stderr, "handle_text_req: SendTargets='%s' "
                "num_targets=%d\n", v, s->cfg->num_targets);
        /* Respond with all configured targets */
        for (i = 0; i < s->cfg->num_targets; i++) {
            target_cfg_t *t = &s->cfg->targets[i];
            fprintf(stderr, "  target[%d]: iqn='%s' backend=%s\n",
                    i, t->iqn, t->backend ? "open" : "NULL");
            if (t->backend) {
                rsp_len = text_append(rsp, rsp_len, sizeof(rsp),
                                      "TargetName", t->iqn);
                {
                    char addr_port[128];
                    snprintf(addr_port, sizeof(addr_port), "%s:3260,1", s->local_addr);
                    rsp_len = text_append(rsp, rsp_len, sizeof(rsp),
                                          "TargetAddress", addr_port);
                }
            }
        }
        fprintf(stderr, "handle_text_req: SendTargets response rsp_len=%u\n",
                (unsigned)rsp_len);
    } else {
        QD_LOG(
            "handle_text_req: no SendTargets key found in request "
            "(dsl=%u)\n", (unsigned)dsl);
    }

    memset(bhs, 0, sizeof(bhs));
    BHS_SET_OPCODE(bhs, ISCSI_OP_TEXT_RSP);
    BHS_SET_FLAGS(bhs, ISCSI_FLAG_FINAL);
    BHS_SET_DSL(bhs, rsp_len);
    BHS_SET_ITT(bhs, BHS_ITT(s->bhs));
    BHS_SET_TTT(bhs, ISCSI_RSVD_TTT);
    { qd_u32 _sn = s->stat_sn++; BHS_SET_STATSN(bhs, _sn); }
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }
    s->last_stat_sn = s->stat_sn - 1;

    return send_raw(s, bhs, (const qd_u8 *)rsp, rsp_len);
}

/* =========================================================================
 * SCSI command handler
 * ====================================================================== */

static int handle_scsi_cmd(session_t *s, qd_u32 dsl)
{
    qd_u8  lun;
    qd_u32 edtl;
    qd_u32 itt;
    qd_u32 cmd_sn;
    qd_bool is_write;
    const qd_u8 *cdb;
    const qd_u8 *imm_data = NULL;
    qd_u32 imm_len = 0;

    /* LUN: iSCSI uses 8-byte LUN field; for single-digit LUNs, byte [1] */
    lun     = s->bhs[9];
    edtl    = BHS_SCSI_EDTL(s->bhs);
    itt     = BHS_ITT(s->bhs);
    cmd_sn  = BHS_CMDSN(s->bhs);
    is_write = (BHS_SCSI_WRITE(s->bhs) != 0);
    cdb     = BHS_CDB(s->bhs);

    QD_LOG(
        "handle_scsi_cmd: raw LUN field bytes[8-15]="
        "%02x %02x %02x %02x %02x %02x %02x %02x "
        "-> decoded lun=%u\n",
        s->bhs[8], s->bhs[9], s->bhs[10], s->bhs[11],
        s->bhs[12], s->bhs[13], s->bhs[14], s->bhs[15],
        (unsigned)lun);

    /* ERL=1: advance ExpCmdSN */
    s->exp_cmd_sn = cmd_sn + 1;

    /* Immediate data (ImmediateData=No, so dsl should be 0 for writes
     * without immediate data; but handle it gracefully) */
    if (dsl > 0) {
        imm_data = s->data_buf;
        imm_len  = dsl;
    }

    return scsi_dispatch(s, lun, cdb, 16, edtl, itt, cmd_sn,
                          is_write, imm_data, imm_len);
}

/* =========================================================================
 * DATA-OUT handler (write data arriving after R2T)
 * ====================================================================== */

static int handle_data_out(session_t *s, qd_u32 dsl)
{
    qd_u32          ttt    = BHS_TTT(s->bhs);
    qd_u32          offset = BHS_BUFOFFSET(s->bhs);
    int             final  = BHS_FINAL(s->bhs);
    pending_write_t *pw;

    QD_UNUSED(final);

    pw = find_pending_write_by_ttt(s, ttt);
    if (!pw) {
        fprintf(stderr, "session: DATA-OUT with unknown TTT 0x%08x\n", ttt);
        return 0; /* ignore, keep going */
    }

    /* Bounds check */
    if (offset + dsl > pw->buf_size) {
        fprintf(stderr, "session: DATA-OUT overflow: off=%u len=%u buf=%u\n",
                (unsigned)offset, (unsigned)dsl, (unsigned)pw->buf_size);
        pw->active = QD_FALSE;
        free(pw->buf); pw->buf = NULL;
        return -1;
    }

    /* Copy data at R2T-specified offset */
    if (dsl > 0)
        memcpy(pw->buf + offset, s->data_buf, dsl);

    /* Track received bytes */
    {
        qd_u32 new_end = offset + dsl;
        if (new_end > pw->received)
            pw->received = new_end;
    }

    /* Decrement outstanding R2T count */
    if (pw->r2ts_outstanding > 0)
        pw->r2ts_outstanding--;

    /* More data expected: send follow-up R2T batch when outstanding drops to 0 */
    if (pw->received < pw->total_bytes) {
        if (pw->r2ts_outstanding == 0) {
            qd_u32 max_r2t = s->params.max_outstanding_r2t;
            while (pw->r2t_bytes < pw->total_bytes && max_r2t > 0) {
                qd_u32 remaining = pw->total_bytes - pw->r2t_bytes;
                qd_u32 chunk = (remaining < s->params.max_recv_data_seg)
                               ? remaining : s->params.max_recv_data_seg;
                if (send_r2t(s, pw, pw->r2t_bytes, chunk) != 0)
                    return -1;
                pw->r2t_bytes += chunk;
                max_r2t--;
            }
            pw->r2ts_outstanding = s->params.max_outstanding_r2t - max_r2t;
        }
        return 0;
    }

    /* All data received: commit the write */
    {
        qd_u32 block_count = pw->total_bytes / 512;
        int    rc;

        if (!pw->target || !pw->target->backend) {
            fprintf(stderr, "session: DATA-OUT: no target backend\n");
            pw->active = QD_FALSE;
            free(pw->buf); pw->buf = NULL;
            return -1;
        }

        rc = backend_write(pw->target->backend,
                           pw->lba_hi, pw->lba_lo,
                           block_count, pw->buf);

        /* Send SCSI Response */
        {
            qd_u8  sense[18];
            qd_u16 sense_len = 0;
            qd_u8  scsi_status = SCSI_STATUS_GOOD;

            if (rc != 0) {
                build_sense(sense, &sense_len,
                            SENSE_MEDIUM_ERROR, 0x03, 0x00);
                scsi_status = SCSI_STATUS_CHECK_CONDITION;
            }
            send_scsi_rsp(s, pw->itt, pw->cmd_sn,
                          scsi_status, sense, sense_len, 0, QD_FALSE);
        }

        pw->active = QD_FALSE;
        free(pw->buf);
        pw->buf = NULL;
    }
    return 0;
}

/* =========================================================================
 * Pending write management
 * ====================================================================== */

static pending_write_t *find_pending_write_by_ttt(session_t *s, qd_u32 ttt)
{
    int i;
    for (i = 0; i < SESS_MAX_PENDING_WRITES; i++) {
        if (s->pending_writes[i].active &&
            s->pending_writes[i].ttt == ttt)
            return &s->pending_writes[i];
    }
    return NULL;
}

static pending_write_t *alloc_pending_write(session_t *s)
{
    int i;
    for (i = 0; i < SESS_MAX_PENDING_WRITES; i++) {
        if (!s->pending_writes[i].active)
            return &s->pending_writes[i];
    }
    return NULL;
}

/* =========================================================================
 * SCSI response helpers
 * ====================================================================== */

static void build_sense(qd_u8 *buf, qd_u16 *len,
                         qd_u8 key, qd_u8 asc, qd_u8 ascq)
{
    /* Fixed-format sense data, 18 bytes */
    memset(buf, 0, 18);
    buf[0] = 0x70;          /* current errors, fixed format */
    buf[2] = key & 0x0F;
    buf[7] = 0x0A;          /* additional sense length (10 more bytes) */
    buf[12] = asc;
    buf[13] = ascq;
    *len = 18;
}

static int send_scsi_rsp(session_t *s, qd_u32 itt, qd_u32 cmd_sn,
                          qd_u8 scsi_status,
                          const qd_u8 *sense, qd_u16 sense_len,
                          qd_u32 residual, qd_bool underflow)
{
    qd_u8  bhs[ISCSI_BHS_SIZE];
    qd_u8  sense_buf[32];
    qd_u32 dsl = 0;
    qd_u8  flags = ISCSI_FLAG_FINAL;

    QD_UNUSED(cmd_sn);

    QD_LOG(
        "send_scsi_rsp: itt=0x%08x scsi_status=0x%02x sense_len=%u "
        "residual=%u underflow=%d stat_sn=%u\n",
        (unsigned)itt, (unsigned)scsi_status, (unsigned)sense_len,
        (unsigned)residual, (int)underflow, (unsigned)s->stat_sn);

    memset(bhs, 0, sizeof(bhs));
    BHS_SET_OPCODE(bhs, ISCSI_OP_SCSI_RSP);

    if (residual > 0) {
        if (underflow)
            flags |= 0x02; /* residual underflow flag */
        else
            flags |= 0x04; /* residual overflow flag */
    }
    BHS_SET_FLAGS(bhs, flags);

    BHS_SET_SCSI_RSP(bhs, ISCSI_SCSI_RSP_COMPLETE);
    BHS_SET_SCSI_STATUS(bhs, scsi_status);

    BHS_SET_ITT(bhs, itt);
    { qd_u32 _sn = s->stat_sn++; BHS_SET_STATSN(bhs, _sn); }
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }
    BHS_SET_RESIDUAL(bhs, residual);

    s->last_stat_sn = s->stat_sn - 1;

    if (sense && sense_len > 0) {
        /* Sense data is preceded by a 2-byte length field */
        sense_buf[0] = (qd_u8)(sense_len >> 8);
        sense_buf[1] = (qd_u8)(sense_len & 0xFF);
        memcpy(sense_buf + 2, sense, sense_len);
        dsl = (qd_u32)sense_len + 2;
        BHS_SET_DSL(bhs, dsl);
        return send_raw(s, bhs, sense_buf, dsl);
    }

    return send_raw(s, bhs, NULL, 0);
}

static int send_data_in(session_t *s, qd_u32 itt, qd_u32 lun,
                         qd_u32 data_sn, qd_u32 buf_offset,
                         const qd_u8 *data, qd_u32 len,
                         qd_bool final, qd_u32 cmd_sn,
                         qd_u8 scsi_status, qd_bool status_in_last)
{
    qd_u8 bhs[ISCSI_BHS_SIZE];
    qd_u8 flags = 0;
    qd_u32 residual = 0;

    QD_UNUSED(cmd_sn);

    QD_LOG(
        "send_data_in: itt=0x%08x lun=%u data_sn=%u buf_offset=%u "
        "len=%u final=%d status_in_last=%d scsi_status=0x%02x stat_sn_sent=%u\n",
        (unsigned)itt, (unsigned)lun, (unsigned)data_sn,
        (unsigned)buf_offset, (unsigned)len,
        (int)final, (int)status_in_last, (unsigned)scsi_status,
        (unsigned)((status_in_last && final) ? s->stat_sn : 0));

    if (final) flags |= ISCSI_FLAG_FINAL;
    if (status_in_last && final) flags |= 0x01; /* S bit: status included */

    /*
     * RFC 3720 10.7: a Data-In PDU with the S bit carries the residual.
     * total = bytes sent for this command. EDTL = bytes the initiator expects.
     *   total < EDTL: set U flag (0x02), Residual Count = EDTL - total
     *   total > EDTL: set O flag (0x04), Residual Count = total - EDTL
     */
    if (status_in_last && final) {
        qd_u32 total = buf_offset + len;
        if (total < s->cur_edtl) {
            flags |= 0x02; /* U: under-run */
            residual = s->cur_edtl - total;
        } else if (total > s->cur_edtl) {
            flags |= 0x04; /* O: over-run */
            residual = total - s->cur_edtl;
        }
    }

    memset(bhs, 0, sizeof(bhs));
    BHS_SET_OPCODE(bhs, ISCSI_OP_SCSI_DATA_IN);
    BHS_SET_FLAGS(bhs, flags);

    if (status_in_last && final)
        BHS_SET_SCSI_STATUS(bhs, scsi_status);

    BHS_SET_LUN(bhs, lun);
    BHS_SET_DSL(bhs, len);
    BHS_SET_ITT(bhs, itt);
    BHS_SET_TTT(bhs, ISCSI_RSVD_TTT);
    { qd_u32 _sn = (status_in_last && final) ? s->stat_sn++ : 0; BHS_SET_STATSN(bhs, _sn); }
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }
    BHS_SET_DATASN(bhs, data_sn);
    BHS_SET_BUFOFFSET(bhs, buf_offset);
    BHS_SET_RESIDUAL(bhs, residual);

    if (status_in_last && final)
        s->last_stat_sn = s->stat_sn - 1;

    return send_raw(s, bhs, data, len);
}

static int send_r2t(session_t *s, pending_write_t *pw,
                    qd_u32 offset, qd_u32 desired)
{
    qd_u8 bhs[ISCSI_BHS_SIZE];

    memset(bhs, 0, sizeof(bhs));
    BHS_SET_OPCODE(bhs, ISCSI_OP_READY_TO_XFER);
    BHS_SET_FLAGS(bhs, ISCSI_FLAG_FINAL);
    BHS_SET_LUN(bhs, pw->lun);
    BHS_SET_ITT(bhs, pw->itt);
    BHS_SET_TTT(bhs, pw->ttt);
    BHS_SET_STATSN(bhs, s->stat_sn);  /* R2T does not increment StatSN */
    BHS_SET_EXPCMDSN(bhs, s->exp_cmd_sn);
    { qd_u32 _mcmdsn = s->exp_cmd_sn + s->max_cmd_sn - 1; BHS_SET_MAXCMDSN(bhs, _mcmdsn); }
    { qd_u32 _r2tsn = pw->r2t_sn++; BHS_SET_R2TSN(bhs, _r2tsn); }
    BHS_SET_BUFOFFSET(bhs, offset);
    BHS_SET_DESIRED_XFER(bhs, desired);

    return send_raw(s, bhs, NULL, 0);
}

/* =========================================================================
 * SCSI emulation dispatcher
 * ====================================================================== */

static int scsi_dispatch(session_t *s, qd_u8 lun,
                          const qd_u8 *cdb, qd_u8 cdb_len,
                          qd_u32 edtl, qd_u32 itt, qd_u32 cmd_sn,
                          qd_bool is_write,
                          const qd_u8 *imm_data, qd_u32 imm_len)
{
    target_cfg_t *t = s->target;
    qd_u8         sense[18];
    qd_u16        sense_len = 0;
    qd_u8         opcode = cdb[0];

    s->cur_edtl = edtl;   /* send_data_in uses it for the residual count */
    QD_UNUSED(cdb_len);
    QD_UNUSED(is_write);
    QD_UNUSED(imm_data);
    QD_UNUSED(imm_len);

    if (!t && opcode != SCSI_INQUIRY && opcode != SCSI_REPORT_LUNS) {
        build_sense(sense, &sense_len,
                    SENSE_ILLEGAL_REQUEST, ASC_LUN_NOT_SUPPORTED, 0x00);
        return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                              sense, sense_len, 0, QD_FALSE);
    }

    if (lun != 0 && opcode != SCSI_REPORT_LUNS) {
        fprintf(stderr, "  -> REJECTING: lun=%u != 0 and opcode != REPORT_LUNS\n",
                (unsigned)lun);
        build_sense(sense, &sense_len,
                    SENSE_ILLEGAL_REQUEST, ASC_LUN_NOT_SUPPORTED, 0x00);
        return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                              sense, sense_len, 0, QD_FALSE);
    }

    /* Handle Immediate Data case for writes */
	/* TODO check: is this block in the right place? */
    if (is_write && imm_len > 0 && opcode != SCSI_WRITE_6 &&
        opcode != SCSI_WRITE_10 && opcode != SCSI_WRITE_16) {
        fprintf(stderr, "SCSI: unexpected immediate data on opcode 0x%02x\n",
                opcode);
        build_sense(sense, &sense_len, SENSE_ILLEGAL_REQUEST,
                   ASC_INVALID_CDB, 0x00);
        return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                            sense, sense_len, 0, QD_FALSE);
    }

    switch (opcode) {

    case SCSI_TEST_UNIT_READY:
        return send_scsi_rsp(s, itt, cmd_sn,
                              SCSI_STATUS_GOOD, NULL, 0, 0, QD_FALSE);

    case SCSI_REQUEST_SENSE:
    {
        qd_u8  buf[18];
        qd_u32 alloc = cdb[4];
        qd_u32 len;
        memset(buf, 0, sizeof(buf));
        buf[0] = 0x70;
        buf[7] = 0x0A;
        len = (alloc < 18) ? alloc : 18;
        send_data_in(s, itt, lun, 0, 0, buf, len,
                     QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE);
        return 0;
    }

    case SCSI_REPORT_LUNS:
    {
        /*
         * REPORT LUNS (SPC-3 §6.21).
         * We have one LUN (LUN 0). Response format:
         *   bytes 0-3: LUN list length = 8 (1 LUN × 8 bytes)
         *   bytes 4-7: reserved
         *   bytes 8-15: LUN 0 = 0x0000000000000000
         */
        qd_u8  buf[16];
        qd_u32 alloc = QD_READ_U32(cdb + 6);
        qd_u32 len;
        memset(buf, 0, sizeof(buf));
        QD_WRITE_U32(buf, 8); /* LUN list length = 8 bytes (1 LUN) */
        /* bytes 8-15: LUN 0 (already zeroed) */
        len = (alloc < 16) ? alloc : 16;
        QD_LOG(
            "  REPORT_LUNS: alloc=%u returning len=%u "
            "(LUN list length=8 => 1 LUN: LUN 0)\n"
            "  buf: %02x %02x %02x %02x %02x %02x %02x %02x "
                  "%02x %02x %02x %02x %02x %02x %02x %02x\n",
            (unsigned)alloc, (unsigned)len,
            buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],
            buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]);
        send_data_in(s, itt, lun, 0, 0, buf, len,
                     QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE);
        return 0;
    }

    case SCSI_INQUIRY:
    {
        qd_u8   buf[256];
        qd_u32  alloc = ((qd_u32)cdb[3] << 8) | cdb[4];
        qd_bool evpd  = (cdb[1] & 0x01) ? QD_TRUE : QD_FALSE;
        qd_u8   page  = cdb[2];
        qd_u32  len   = 0;

        memset(buf, 0, sizeof(buf));

        if (!evpd) {
            /*
             * Standard INQUIRY response, 36 bytes (minimum per SPC).
             *
             * buf[3]: response_data_format=2 (SPC), HISUP=0.
             *   - HISUP=1 (0x12) tells Linux the target supports hierarchical
             *     LUN addressing; open-iscsi then requires a compliant
             *     REPORT_LUNS before registering the block device.  We don't
             *     need it: set HISUP=0 (0x02) for a flat, simple target.
             *
             * buf[4]: additional_length = total_response_bytes - 4.
             *   - We return 36 bytes total, so additional_length = 32 = 0x1F.
             *   - Advertising 0x5B (=91, total 96) while clamping to 36 bytes
             *     is technically legal (the initiator may re-issue with a
             *     larger allocation_length) but wastes a round-trip and, more
             *     importantly, causes some strict initiators (open-iscsi) to
             *     wait for the extra data before proceeding.  Keep it honest.
             */
			buf[0] = 0x00;   /* Qualifier 0 (Connected), Device Type 0 (Disk) */
			buf[1] = 0x00;   /* not removable */
			buf[2] = 0x05;   /* SPC-3 */
			buf[3] = 0x02;   /* Response Data Format 2 */
			buf[4] = 31;     /* Additional Length (36 - 5) */
            buf[7] = 0x02;   /* CmdQue */
            memcpy(buf + 8,  "QUICKISC", 8);
            memcpy(buf + 16, "Virtual Disk    ", 16);
            memcpy(buf + 32, "1.00", 4);
            len = 36;
            QD_LOG(
                "  INQUIRY standard: alloc=%u lun=%u returning %u bytes "
                "(devtype=0x%02x peripheral_qualifier=0x%02x "
                "version=0x%02x response_fmt=0x%02x addl_len=0x%02x)\n",
                (unsigned)alloc, (unsigned)lun, (unsigned)(alloc < len ? alloc : len),
                (unsigned)buf[0], (unsigned)(buf[0]>>5),
                (unsigned)buf[2], (unsigned)(buf[3]&0x0f), (unsigned)buf[4]);
        } else {
            QD_LOG( "  INQUIRY EVPD page=0x%02x alloc=%u lun=%u\n",
                    (unsigned)page, (unsigned)alloc, (unsigned)lun);
            switch (page) {
            case 0x00:
                /*
                 * Supported VPD Pages list.
                 * buf[0]=devtype, buf[1]=page_code, buf[2]=reserved,
                 * buf[3]=page_length, buf[4..]=page codes.
                 */
                buf[1] = 0x00; /* this page's code */
                buf[3] = 3;    /* 3 supported pages */
                buf[4] = 0x00; /* Supported VPD Pages */
                buf[5] = 0x80; /* Unit Serial Number */
                buf[6] = 0x83; /* Device Identification */
                len = 7;
                break;
            case 0x80:
                buf[1] = 0x80; buf[3] = 8;
                memcpy(buf + 4, "QISCSI01", 8);
                len = 12;
                break;
            case 0x83:
            {
                /*
                 * Device Identification VPD page (SPC-4 §7.8.6).
                 * Build two descriptors, matching what istgt does:
                 *
                 * Descriptor 1: NAA IEEE Registered (binary, LU assoc)
                 *   code_set=1 (binary), type=3 (NAA), assoc=0 (LU)
                 *   8-byte NAA identifier derived from IQN
                 *
                 * Descriptor 2: T10 Vendor ID (UTF-8, LU assoc)
                 *   code_set=3 (UTF-8), type=1 (T10), assoc=0 (LU)
                 *   8-byte vendor + 16-byte product + serial
                 */
                qd_u8 *cp;
                int dlen = 0;

                buf[0] = 0x00;   /* peripheral device type = disk */
                buf[1] = 0x83;   /* page code */
                /* buf[2:3] = page length, filled at end */
                buf[2] = 0;
                buf[3] = 0;

                /* Descriptor 1: NAA (binary) */
                cp = buf + 4;
                cp[0] = 0x01;  /* code_set=1 (binary) */
                cp[1] = 0x03;  /* PIV=0, assoc=0 (LU), type=3 (NAA) */
                cp[2] = 0x00;  /* reserved */
                cp[3] = 8;     /* identifier length */
                /* 8-byte NAA-5 identifier: NAA=5 + 60-bit value */
                /* derive from IQN: use first 7 bytes of a simple hash */
                {
                    qd_u8 *naa = cp + 4;
                    const char *iqn = t ? t->iqn : "iqn.quickiscsi:lun0";
                    qd_u32 h = 0x811c9dc5UL; /* FNV-1a */
                    const char *p;
                    for (p = iqn; *p; p++) {
                        h ^= (qd_u8)*p;
                        h *= 0x01000193UL;
                    }
                    h ^= (qd_u32)lun;
                    naa[0] = 0x50 | ((h >> 28) & 0x0F); /* NAA=5 */
                    naa[1] = (h >> 20) & 0xFF;
                    naa[2] = (h >> 12) & 0xFF;
                    naa[3] = (h >>  4) & 0xFF;
                    naa[4] = ((h & 0x0F) << 4) | ((h >> 24) & 0x0F);
                    naa[5] = (h >> 16) & 0xFF;
                    naa[6] = (h >>  8) & 0xFF;
                    naa[7] = h & 0xFF;
                }
                dlen += 4 + 8;

                /* Descriptor 2: T10 Vendor ID (UTF-8) */
                cp = buf + 4 + dlen;
                cp[0] = 0x03;  /* code_set=3 (UTF-8) */
                cp[1] = 0x01;  /* PIV=0, assoc=0 (LU), type=1 (T10 vendor) */
                cp[2] = 0x00;
                {
                    /* vendor(8) + product(16) + serial(up to 12) */
                    memcpy(cp + 4,       "QUICKISC", 8);
                    memcpy(cp + 4 + 8,   "Virtual Disk    ", 16);
                    /* use IQN tail as serial */
                    {
                        const char *iqn = t ? t->iqn : "lun0";
                        const char *tail = iqn + strlen(iqn);
                        int slen;
                        while (tail > iqn && *(tail-1) != ':' && *(tail-1) != '.')
                            tail--;
                        slen = (int)strlen(tail);
                        if (slen > 12) slen = 12;
                        memcpy(cp + 4 + 24, tail, (size_t)slen);
                        cp[3] = (qd_u8)(8 + 16 + slen);
                    }
                }
                dlen += 4 + cp[3];

                /* Page length = total descriptor bytes */
                buf[2] = (qd_u8)((dlen >> 8) & 0xFF);
                buf[3] = (qd_u8)(dlen & 0xFF);
                len = (qd_u32)(4 + dlen);
                break;
            }
            default:
                build_sense(sense, &sense_len,
                            SENSE_ILLEGAL_REQUEST, ASC_INVALID_CDB, 0x00);
                return send_scsi_rsp(s, itt, cmd_sn,
                                      SCSI_STATUS_CHECK_CONDITION,
                                      sense, sense_len, 0, QD_FALSE);
            }
        }
        if (alloc < len) len = alloc;
        send_data_in(s, itt, lun, 0, 0, buf, len,
                     QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE);
        return 0;
    }

    case SCSI_MODE_SENSE_6:
    {
        qd_u8  buf[4];
        qd_u32 alloc = cdb[4];
        qd_u32 len;
        memset(buf, 0, sizeof(buf));
        buf[0] = 3;
        len = (alloc < 4) ? alloc : 4;
        send_data_in(s, itt, lun, 0, 0, buf, len,
                     QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE);
        return 0;
    }

    case SCSI_MODE_SENSE_10:
    {
        qd_u8  buf[8];
        qd_u32 alloc = ((qd_u32)cdb[7] << 8) | cdb[8];
        qd_u32 len;
        memset(buf, 0, sizeof(buf));
        buf[1] = 6;
        len = (alloc < 8) ? alloc : 8;
        send_data_in(s, itt, lun, 0, 0, buf, len,
                     QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE);
        return 0;
    }

    case SCSI_READ_CAPACITY_10:
    {
        qd_u8  buf[8];
        qd_u32 nb_hi, nb_lo, last_lba;
        if (!t || !t->backend) goto no_medium;
        backend_num_blocks(t->backend, &nb_hi, &nb_lo);
        last_lba = (nb_hi > 0) ? 0xFFFFFFFFUL : nb_lo - 1;
        QD_LOG(
            "  READ_CAPACITY_10: num_blocks=%u:%u last_lba=0x%08x "
            "block_size=512\n",
            (unsigned)nb_hi, (unsigned)nb_lo, (unsigned)last_lba);
        QD_WRITE_U32(buf,   last_lba);
        QD_WRITE_U32(buf+4, 512);
        send_data_in(s, itt, lun, 0, 0, buf, 8,
                     QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE);
        return 0;
    }

    case SCSI_READ_CAPACITY_16:
    {
        qd_u8  buf[32];
        qd_u32 nb_hi, nb_lo, alloc;
        qd_u32 last_hi, last_lo;
        if ((cdb[1] & 0x1F) != 0x10) {
            build_sense(sense, &sense_len,
                        SENSE_ILLEGAL_REQUEST, ASC_INVALID_CDB, 0x00);
            return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                                  sense, sense_len, 0, QD_FALSE);
        }
        if (!t || !t->backend) goto no_medium;
        alloc = QD_READ_U32(cdb + 10);
        backend_num_blocks(t->backend, &nb_hi, &nb_lo);
        last_hi = nb_hi;
        last_lo = nb_lo - 1;
        if (nb_lo == 0 && nb_hi > 0) { last_hi--; last_lo = 0xFFFFFFFFUL; }
        QD_LOG(
            "  READ_CAPACITY_16: num_blocks=%u:%u last_lba=%u:%u "
            "block_size=512 alloc=%u\n",
            (unsigned)nb_hi, (unsigned)nb_lo,
            (unsigned)last_hi, (unsigned)last_lo, (unsigned)alloc);
        memset(buf, 0, sizeof(buf));
        QD_WRITE_U32(buf,   last_hi);
        QD_WRITE_U32(buf+4, last_lo);
        QD_WRITE_U32(buf+8, 512);
        { qd_u32 len = (alloc < 32) ? alloc : 32;
          send_data_in(s, itt, lun, 0, 0, buf, len,
                       QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE); }
        return 0;
    }

    case SCSI_SYNC_CACHE_10:
    case SCSI_SYNC_CACHE_16:
        if (t && t->backend) backend_sync(t->backend);
        return send_scsi_rsp(s, itt, cmd_sn,
                              SCSI_STATUS_GOOD, NULL, 0, 0, QD_FALSE);

    case SCSI_READ_6:
    case SCSI_READ_10:
    case SCSI_READ_16:
    {
        qd_u32 lba_hi = 0, lba_lo = 0, xfer_blocks = 0;
        qd_u8 *rbuf;
        qd_u32 chunk, offset, data_sn, max_chunk;
        int rc;

        if (!t || !t->backend) goto no_medium;

        if (opcode == SCSI_READ_6) {
            lba_lo = ((qd_u32)(cdb[1]&0x1F)<<16)|((qd_u32)cdb[2]<<8)|cdb[3];
            xfer_blocks = cdb[4]; if (!xfer_blocks) xfer_blocks = 256;
        } else if (opcode == SCSI_READ_10) {
            lba_lo = QD_READ_U32(cdb+2);
            xfer_blocks = ((qd_u32)cdb[7]<<8)|cdb[8];
        } else {
            lba_hi = QD_READ_U32(cdb+2); lba_lo = QD_READ_U32(cdb+6);
            xfer_blocks = QD_READ_U32(cdb+10);
        }

        if (!xfer_blocks)
            return send_scsi_rsp(s, itt, cmd_sn,
                                  SCSI_STATUS_GOOD, NULL, 0, 0, QD_FALSE);

        max_chunk = s->params.max_recv_data_seg / 512;
        if (!max_chunk) max_chunk = 1;
        rbuf = (qd_u8 *)malloc(max_chunk * 512);
        if (!rbuf) {
            build_sense(sense, &sense_len, SENSE_HARDWARE_ERROR, 0x44, 0x00);
            return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                                  sense, sense_len, 0, QD_FALSE);
        }

        offset = 0; data_sn = 0;
        while (xfer_blocks > 0) {
            qd_u32 cur_hi, cur_lo;
            qd_bool last_c;
            chunk = (xfer_blocks < max_chunk) ? xfer_blocks : max_chunk;
            cur_lo = lba_lo + (offset / 512);
            cur_hi = lba_hi + (cur_lo < lba_lo ? 1 : 0);
            rc = backend_read(t->backend, cur_hi, cur_lo, chunk, rbuf);
            if (rc != 0) {
                free(rbuf);
                build_sense(sense, &sense_len, SENSE_MEDIUM_ERROR, 0x11, 0x00);
                return send_scsi_rsp(s, itt, cmd_sn,
                                      SCSI_STATUS_CHECK_CONDITION,
                                      sense, sense_len, 0, QD_FALSE);
            }
            last_c = ((xfer_blocks - chunk) == 0) ? QD_TRUE : QD_FALSE;
            rc = send_data_in(s, itt, lun, data_sn, offset,
                              rbuf, chunk*512, last_c, cmd_sn,
                              SCSI_STATUS_GOOD, last_c);
            if (rc != 0) {
                fprintf(stderr, "SCSI: send_data_in failed at offset %u\n", (unsigned)offset);
                free(rbuf); return -1;
            }
            offset += chunk * 512;
            xfer_blocks -= chunk;
            data_sn++;
        }
        free(rbuf);
        return 0;
    }

    case SCSI_WRITE_6:
    case SCSI_WRITE_10:
    case SCSI_WRITE_16:
    {
        qd_u32 lba_hi = 0, lba_lo = 0, xfer_blocks = 0;
        pending_write_t *pw;

        if (!t || !t->backend) goto no_medium;

        if (opcode == SCSI_WRITE_6) {
            lba_lo = ((qd_u32)(cdb[1]&0x1F)<<16)|((qd_u32)cdb[2]<<8)|cdb[3];
            xfer_blocks = cdb[4]; if (!xfer_blocks) xfer_blocks = 256;
        } else if (opcode == SCSI_WRITE_10) {
            lba_lo = QD_READ_U32(cdb+2);
            xfer_blocks = ((qd_u32)cdb[7]<<8)|cdb[8];
        } else {
            lba_hi = QD_READ_U32(cdb+2); lba_lo = QD_READ_U32(cdb+6);
            xfer_blocks = QD_READ_U32(cdb+10);
        }

        QD_UNUSED(edtl);

        if (!xfer_blocks)
            return send_scsi_rsp(s, itt, cmd_sn,
                                  SCSI_STATUS_GOOD, NULL, 0, 0, QD_FALSE);

        pw = alloc_pending_write(s);
        if (!pw) {
            build_sense(sense, &sense_len, SENSE_HARDWARE_ERROR, 0x44, 0x00);
            return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                                  sense, sense_len, 0, QD_FALSE);
        }

        pw->total_bytes = xfer_blocks * 512;
        pw->buf = (qd_u8 *)malloc(pw->total_bytes);
        if (!pw->buf) {
            pw->active = QD_FALSE;
            build_sense(sense, &sense_len, SENSE_HARDWARE_ERROR, 0x44, 0x00);
            return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                                  sense, sense_len, 0, QD_FALSE);
        }
        pw->buf_size  = pw->total_bytes;
        pw->active    = QD_TRUE;
        pw->itt       = itt;
        pw->ttt       = s->next_ttt++;
        pw->lba_hi    = lba_hi;
        pw->lba_lo    = lba_lo;
        pw->received      = 0;
        pw->r2t_bytes     = 0;
        pw->r2t_sn        = 0;
        pw->r2ts_outstanding = 0;
        pw->target        = t;
        pw->lun           = lun;
        pw->cmd_sn        = cmd_sn;
        QD_UNUSED(opcode);

        /* Send a batch of R2Ts upfront, respecting MaxOutstandingR2T.
         * Each R2T covers max_recv_data_seg bytes. The initiator will
         * respond with DATA-OUT PDUs for each R2T, pipelined.
         * Follow-up R2Ts are sent in handle_data_out when the outstanding
         * count drops to zero. */
        {
            qd_u32 max_r2t = s->params.max_outstanding_r2t;
            while (pw->r2t_bytes < pw->total_bytes && max_r2t > 0) {
                qd_u32 remaining = pw->total_bytes - pw->r2t_bytes;
                qd_u32 chunk = (remaining < s->params.max_recv_data_seg)
                               ? remaining : s->params.max_recv_data_seg;
                if (send_r2t(s, pw, pw->r2t_bytes, chunk) != 0)
                    return -1;
                pw->r2t_bytes += chunk;
                max_r2t--;
            }
            pw->r2ts_outstanding = s->params.max_outstanding_r2t - max_r2t;
            return 0;
        }
    }

    case SCSI_WRITE_SAME_10:
    {
        /* WRITE SAME(10): write the same 512-byte pattern to multiple blocks.
         * CDB: [0]opcode [1]flags [2-5]LBA [6-7]count [8]imm [9]...
         * The pattern is in imm_data (if imm bit set) or a dummy 512-byte zero
         * pattern.  We write it block by block via backend_write. */
        qd_u32 lba_lo = QD_READ_U32(cdb + 2) & 0x00FFFFFFUL;
        qd_u32 count  = QD_READ_U16(cdb + 6) & 0x01FF;
        qd_u32 i;

        if (count == 0) count = 65536;  /* LBA format bit set: count is 65536 */
        if (!t || !t->backend) goto no_medium;

        /* Use imm_data as the pattern if available, else zero buffer */
        if (imm_len < 512) {
            /* Zero-fill pattern */
            qd_u8 zbuf[512];
            memset(zbuf, 0, sizeof(zbuf));
            for (i = 0; i < count; i++) {
                if (backend_write(t->backend, 0, lba_lo + i, 1, zbuf) != 0) {
                    build_sense(sense, &sense_len,
                                 SENSE_HARDWARE_ERROR, ASC_INTERNAL_TARGET_FAILURE, 0);
                    return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                                          sense, sense_len, 0, QD_FALSE);
                }
            }
        } else {
            for (i = 0; i < count; i++) {
                if (backend_write(t->backend, 0, lba_lo + i, 1, imm_data) != 0) {
                    build_sense(sense, &sense_len,
                                 SENSE_HARDWARE_ERROR, ASC_INTERNAL_TARGET_FAILURE, 0);
                    return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                                          sense, sense_len, 0, QD_FALSE);
                }
            }
        }
        return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_GOOD, NULL, 0, 0, QD_FALSE);
    }

    case SCSI_MAINTENANCE_IN:
    {
        /* Maintenance In: return zeros for the requested length.
         * We don't implement any vendor-specific maintenance functions.
         * EDTL tells us how many bytes the initiator expects. */
        qd_u8 buf[256];
        qd_u32 len = edtl;
        if (len > sizeof(buf)) len = sizeof(buf);
        memset(buf, 0, len);
        send_data_in(s, itt, lun, 0, 0, buf, len,
                     QD_TRUE, cmd_sn, SCSI_STATUS_GOOD, QD_TRUE);
        return 0;
    }

    default:
        fprintf(stderr, "session: unsupported SCSI opcode 0x%02x\n", opcode);
        build_sense(sense, &sense_len,
                    SENSE_ILLEGAL_REQUEST, ASC_INVALID_CDB, 0x00);
        return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                              sense, sense_len, 0, QD_FALSE);
    }

no_medium:
    build_sense(sense, &sense_len,
                SENSE_NOT_READY, ASC_NOT_READY_CAUSE_NOT_REPORTABLE, 0x00);
    return send_scsi_rsp(s, itt, cmd_sn, SCSI_STATUS_CHECK_CONDITION,
                          sense, sense_len, 0, QD_FALSE);
}

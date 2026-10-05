/*
 * iscsi.h -- iSCSI PDU definitions, BHS layout, protocol constants
 *
 * Based on RFC 3720 (iSCSI) and RFC 3721 (iSCSI Naming).
 * All multi-byte fields are big-endian on the wire.
 * Use QD_READ_U16/QD_READ_U32/QD_WRITE_U16/QD_WRITE_U32 from compat.h.
 *
 * C89 clean: no stdint, no C99, no C++ comments.
 */

#ifndef QUICKISCSI_ISCSI_H
#define QUICKISCSI_ISCSI_H

#include "compat.h"

/* -------------------------------------------------------------------------
 * Wire sizes
 * ---------------------------------------------------------------------- */
#define ISCSI_BHS_SIZE          48      /* Basic Header Segment is always 48 bytes  */
#define ISCSI_PORT              3260
#define ISCSI_BLOCK_SIZE        512
#define ISCSI_MAX_DATA_SEG      (64*1024)  /* our max recv data segment: 64 KB      */
#define ISCSI_MAX_BURST         (256*1024) /* max burst length we'll advertise       */
#define ISCSI_MAX_TARGETS       32
#define ISCSI_MAX_SESSIONS      64
#define ISCSI_MAX_IQN           224     /* RFC 3720 §3.2.6: max IQN length          */
#define ISCSI_MAX_TEXT_BUF      (8*1024)

/* -------------------------------------------------------------------------
 * Opcode definitions (initiator opcodes in low 6 bits of byte 0)
 * ---------------------------------------------------------------------- */

/* Initiator opcodes */
#define ISCSI_OP_NOP_OUT        0x00
#define ISCSI_OP_SCSI_CMD       0x01
#define ISCSI_OP_SCSI_TMFUNC   0x02
#define ISCSI_OP_LOGIN_REQ      0x03
#define ISCSI_OP_TEXT_REQ       0x04
#define ISCSI_OP_SCSI_DATA_OUT  0x05
#define ISCSI_OP_LOGOUT_REQ     0x06

/* Target opcodes */
#define ISCSI_OP_NOP_IN         0x20
#define ISCSI_OP_SCSI_RSP       0x21
#define ISCSI_OP_SCSI_TMFUNC_RSP 0x22
#define ISCSI_OP_LOGIN_RSP      0x23
#define ISCSI_OP_TEXT_RSP       0x24
#define ISCSI_OP_SCSI_DATA_IN   0x25
#define ISCSI_OP_LOGOUT_RSP     0x26
#define ISCSI_OP_READY_TO_XFER  0x31    /* R2T */
#define ISCSI_OP_ASYNC_MSG      0x32
#define ISCSI_OP_REJECT         0x3f

/* Immediate bit: bit 6 of byte 0 */
#define ISCSI_IMMEDIATE_FLAG    0x40
/* Final bit: bit 7 of byte 1 */
#define ISCSI_FLAG_FINAL        0x80

/* -------------------------------------------------------------------------
 * Login phase / stage constants
 * ---------------------------------------------------------------------- */
#define ISCSI_STAGE_SECURITY    0
#define ISCSI_STAGE_LOGIN_OP    1
#define ISCSI_STAGE_FULL        3

/* Login response status classes */
#define ISCSI_LOGIN_SUCCESS     0x00
#define ISCSI_LOGIN_REDIRECT    0x01
#define ISCSI_LOGIN_INITIATOR_ERR 0x02
#define ISCSI_LOGIN_TARGET_ERR  0x03

/* Login response status details */
#define ISCSI_LOGIN_STATUS_ACCEPT           0x0000
#define ISCSI_LOGIN_STATUS_AUTH_FAIL        0x0201
#define ISCSI_LOGIN_STATUS_NOT_FOUND        0x0204
#define ISCSI_LOGIN_STATUS_TARGET_REMOVED   0x0205
#define ISCSI_LOGIN_STATUS_NO_RESOURCES     0x0301

/* -------------------------------------------------------------------------
 * Logout reason codes
 * ---------------------------------------------------------------------- */
#define ISCSI_LOGOUT_CLOSE_SESSION  0
#define ISCSI_LOGOUT_CLOSE_CONN     1
#define ISCSI_LOGOUT_REMOVE_CONN    2

/* Logout response codes */
#define ISCSI_LOGOUT_RSP_SUCCESS    0
#define ISCSI_LOGOUT_RSP_CID_FAIL   1
#define ISCSI_LOGOUT_RSP_RECOVERY   2

/* -------------------------------------------------------------------------
 * SCSI response / status
 * ---------------------------------------------------------------------- */
#define ISCSI_SCSI_RSP_COMPLETE     0x00
#define ISCSI_SCSI_RSP_SENSE        0x01

#define SCSI_STATUS_GOOD            0x00
#define SCSI_STATUS_CHECK_CONDITION 0x02
#define SCSI_STATUS_BUSY            0x08

/* SCSI sense key values */
#define SENSE_NO_SENSE          0x0
#define SENSE_RECOVERED_ERROR   0x1
#define SENSE_NOT_READY         0x2
#define SENSE_MEDIUM_ERROR      0x3
#define SENSE_HARDWARE_ERROR    0x4
#define SENSE_ILLEGAL_REQUEST   0x5
#define SENSE_UNIT_ATTENTION    0x6
#define SENSE_DATA_PROTECT      0x7
#define SENSE_ABORTED_COMMAND   0xB

/* Common ASC/ASCQ pairs */
#define ASC_INVALID_CDB         0x24  /* ASCQ 0x00 */
#define ASC_LBA_OUT_OF_RANGE    0x21
#define ASC_INVALID_FIELD       0x24
#define ASC_LUN_NOT_SUPPORTED   0x25
#define ASC_NOT_READY_CAUSE_NOT_REPORTABLE 0x04
#define ASC_INTERNAL_TARGET_FAILURE 0x44  /* ASC 0x44, ASCQ 0x00 */

/* -------------------------------------------------------------------------
 * SCSI command opcodes we handle
 * ---------------------------------------------------------------------- */
#define SCSI_TEST_UNIT_READY    0x00
#define SCSI_REQUEST_SENSE      0x03
#define SCSI_INQUIRY            0x12
#define SCSI_MODE_SENSE_6       0x1A
#define SCSI_READ_CAPACITY_10   0x25
#define SCSI_READ_6             0x08
#define SCSI_READ_10            0x28
#define SCSI_READ_16            0x88
#define SCSI_WRITE_6            0x0A
#define SCSI_WRITE_10           0x2A
#define SCSI_WRITE_16           0x8A
#define SCSI_SYNC_CACHE_10      0x35
#define SCSI_SYNC_CACHE_16      0x91
#define SCSI_READ_CAPACITY_16   0x9E  /* SERVICE ACTION 0x10 */
#define SCSI_REPORT_LUNS        0xA0
#define SCSI_MODE_SENSE_10      0x5A
#define SCSI_WRITE_SAME_10      0x41
#define SCSI_MAINTENANCE_IN     0xA3  /* SPC-4 Maintenance In (we treat as NOP) */

/* -------------------------------------------------------------------------
 * BHS field offsets (byte indices into the 48-byte BHS).
 * We access via raw byte arrays + macros rather than packed structs to
 * avoid any compiler alignment/padding surprises on exotic targets.
 * ---------------------------------------------------------------------- */

/* Byte 0: opcode (bits 5:0) + immediate (bit 6) */
#define BHS_OPCODE(b)       ((b)[0] & 0x3F)
#define BHS_IMMEDIATE(b)    (((b)[0] >> 6) & 1)

/* Byte 1: flags (Final bit = bit 7, rest opcode-specific) */
#define BHS_FLAGS(b)        ((b)[1])
#define BHS_FINAL(b)        (((b)[1] >> 7) & 1)

/* Bytes 1-3 for login: CSG/NSG/T/C bits in byte 1 */
#define BHS_LOGIN_T(b)      (((b)[1] >> 7) & 1)   /* Transit           */
#define BHS_LOGIN_C(b)      (((b)[1] >> 6) & 1)   /* Continue          */
#define BHS_LOGIN_CSG(b)    (((b)[1] >> 2) & 0x3) /* Current stage     */
#define BHS_LOGIN_NSG(b)    (((b)[1]     ) & 0x3) /* Next stage        */

/* Bytes 2-3: version */
#define BHS_VERSION_MAX(b)  ((b)[2])
#define BHS_VERSION_MIN(b)  ((b)[3])

/* Bytes 4-7: TotalAHSLength (byte 4) + DataSegmentLength (bytes 5-7) */
#define BHS_AHS_LEN(b)      ((b)[4])
#define BHS_DSL(b)          ((qd_u32)(((b)[5]<<16)|((b)[6]<<8)|((b)[7])))

/* Bytes 8-11: LUN (for SCSI commands) or ISID hi (for login) */
/* Bytes 8-15: 8-byte LUN field */
#define BHS_LUN_HI32(b)     QD_READ_U32((b)+8)
#define BHS_LUN_LO32(b)     QD_READ_U32((b)+12)

/* For login: ISID is bytes 8-13, TSIH is bytes 14-15 */
#define BHS_ISID(b)         ((b)+8)   /* 6-byte initiator session ID */
#define BHS_TSIH(b)         QD_READ_U16((b)+14)

/* Bytes 16-19: Initiator Task Tag (ITT) */
#define BHS_ITT(b)          QD_READ_U32((b)+16)

/* Bytes 20-23: opcode-specific (CmdSN for SCSI, TargetTransferTag for R2T...) */
#define BHS_TTT(b)          QD_READ_U32((b)+20)

/* Bytes 24-27: CmdSN */
#define BHS_CMDSN(b)        QD_READ_U32((b)+24)
#define BHS_STATSN(b)         QD_READ_U32((b)+24)

/* Bytes 28-31: ExpStatSN (Initiator) or ExpCmdSN (Target) */
#define BHS_EXPSTSN(b)      QD_READ_U32((b)+28)

/* Bytes 32-35: ExpCmdSN (target->initiator) or ExpDataSN / misc */
#define BHS_EXPCMDSN(b)     QD_READ_U32((b)+28)

/* Bytes 32-35: MaxCmdSN (Target) */
#define BHS_MAXCMDSN(b)     QD_READ_U32((b)+32)

/* Bytes 36-39: DataSN (Data-In) or R2TSN (R2T) */
#define BHS_DATASN(b)       QD_READ_U32((b)+36)

/* Bytes 40-43: Buffer Offset (Data-Out, Data-In, R2T). RFC 3720 10.7/10.8/10.9 */
#define BHS_BUFOFFSET(b)    QD_READ_U32((b)+40)
/* Bytes 44-47: Residual Count (Data-In). RFC 3720 10.7 */
#define BHS_RESIDUAL(b)     QD_READ_U32((b)+44)

/* SCSI command specific (byte 1 flags) */
#define BHS_SCSI_READ(b)    (((b)[1] >> 6) & 1)
#define BHS_SCSI_WRITE(b)   (((b)[1] >> 5) & 1)
#define BHS_SCSI_ATTR(b)    ((b)[1] & 0x7)
/* SCSI expected data transfer length: bytes 20-23 */
#define BHS_SCSI_EDTL(b)    QD_READ_U32((b)+20)
/* CDB starts at byte 32, up to 16 bytes in a standard BHS */
#define BHS_CDB(b)          ((b)+32)

/* -------------------------------------------------------------------------
 * BHS write helpers (build outgoing PDUs into a qd_u8[48] buffer)
 * ---------------------------------------------------------------------- */

#define BHS_SET_OPCODE(b, op)   ((b)[0] = (qd_u8)(op))
#define BHS_SET_FLAGS(b, f)     ((b)[1] = (qd_u8)(f))
#define BHS_SET_DSL(b, len) do { \
    (b)[5] = (qd_u8)(((len)>>16)&0xFF); \
    (b)[6] = (qd_u8)(((len)>> 8)&0xFF); \
    (b)[7] = (qd_u8)(((len)    )&0xFF); \
} while(0)
#define BHS_SET_ITT(b, v)       QD_WRITE_U32((b)+16, (v))
#define BHS_SET_TTT(b, v)       QD_WRITE_U32((b)+20, (v))
#define BHS_SET_STATSN(b, v)    QD_WRITE_U32((b)+24, (v))
#define BHS_SET_EXPCMDSN(b, v)  QD_WRITE_U32((b)+28, (v))
#define BHS_SET_MAXCMDSN(b, v)  QD_WRITE_U32((b)+32, (v))
#define BHS_SET_DATASN(b, v)    QD_WRITE_U32((b)+36, (v))
#define BHS_SET_BUFOFFSET(b, v) QD_WRITE_U32((b)+40, (v))
#define BHS_SET_RESIDUAL(b, v)  QD_WRITE_U32((b)+44, (v))
#define BHS_SET_LUN(b, lun) do { \
    memset((b)+8, 0, 8); \
    (b)[9] = (qd_u8)((lun) & 0xFF); \
} while(0)

/* Login response specific */
#define BHS_SET_LOGIN_T(b, v)   ((b)[1] = (qd_u8)(((b)[1] & ~0x80) | (((v)&1)<<7)))
#define BHS_SET_LOGIN_CSG(b, v) ((b)[1] = (qd_u8)(((b)[1] & ~0x0C) | (((v)&3)<<2)))
#define BHS_SET_LOGIN_NSG(b, v) ((b)[1] = (qd_u8)(((b)[1] & ~0x03) | ((v)&3)))
#define BHS_SET_VERSION(b, mx, mn) do { (b)[2]=(qd_u8)(mx); (b)[3]=(qd_u8)(mn); } while(0)
#define BHS_SET_TSIH(b, v)      QD_WRITE_U16((b)+14, (v))
#define BHS_SET_ISID(b, src)    memcpy((b)+8, (src), 6)
#define BHS_SET_STATUS(b, cls, detail) do { (b)[36]=(qd_u8)(cls); (b)[37]=(qd_u8)(detail); } while(0)

/* SCSI response specific */
#define BHS_SET_SCSI_STATUS(b, s)   ((b)[3] = (qd_u8)(s))
#define BHS_SET_SCSI_RSP(b, r)      ((b)[2] = (qd_u8)(r))
#define BHS_SET_RESIDUAL(b, v)      QD_WRITE_U32((b)+44, (v))
#define BHS_SET_BIDIR_RESIDUAL(b,v) QD_WRITE_U32((b)+40, (v))

/* R2T specific */
#define BHS_SET_R2TSN(b, v)         QD_WRITE_U32((b)+36, (v))
#define BHS_SET_DESIRED_XFER(b, v)  QD_WRITE_U32((b)+44, (v))

/* Data-In specific */
#define BHS_SET_DATA_TTT(b, v)      QD_WRITE_U32((b)+40, (v))

/* -------------------------------------------------------------------------
 * Padding: iSCSI data segments are padded to 4-byte boundaries
 * ---------------------------------------------------------------------- */
#define ISCSI_PAD4(n)   (((n) + 3) & ~3)
#define ISCSI_PAD_LEN(n) (ISCSI_PAD4(n) - (n))

/* -------------------------------------------------------------------------
 * Reserved / always-zero sentinel
 * ---------------------------------------------------------------------- */
#define ISCSI_RSVD_TTT  0xFFFFFFFFUL   /* "no TTT" value per RFC */

#endif /* QUICKISCSI_ISCSI_H */

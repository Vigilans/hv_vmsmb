/* SPDX-License-Identifier: GPL-2.0 */
/*
 * smb1pdu.h - SMB1/SMB2 shared constants (host-endian)
 *
 * Subset of fs/smb/client/smb1pdu.h containing CreateDisposition
 * and CreateOptions flags shared by SMB1 and SMB2 code paths.
 * Only constants actually used by hv_vmsmb are included.
 */
#ifndef _SMB1PDU_H
#define _SMB1PDU_H

/* CreateDisposition flags, see MS-SMB2 §2.2.13 */
#define FILE_OPEN             0x00000001
#define FILE_CREATE           0x00000002
#define FILE_OPEN_IF          0x00000003
#define FILE_OVERWRITE_IF     0x00000005

/* CreateOptions flags, see MS-SMB2 §2.2.13 */
#define CREATE_NOT_FILE       0x00000001  /* must be directory */
#define CREATE_NOT_DIR        0x00000040  /* must not be directory */
#define CREATE_DELETE_ON_CLOSE 0x00001000
#define OPEN_REPARSE_POINT    0x00200000

#endif /* _SMB1PDU_H */

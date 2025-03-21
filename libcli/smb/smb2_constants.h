/*
   Unix SMB/CIFS implementation.

   SMB2 client library header

   Copyright (C) Andrew Tridgell 2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __LIBCLI_SMB2_SMB2_CONSTANTS_H__
#define __LIBCLI_SMB2_SMB2_CONSTANTS_H__

/* offsets into SMB2_TRANSFORM header elements */
#define SMB2_TF_PROTOCOL_ID	0x00 /*  4 bytes */
#define SMB2_TF_SIGNATURE	0x04 /* 16 bytes */
#define SMB2_TF_NONCE		0x14 /* 16 bytes */
#define SMB2_TF_MSG_SIZE	0x24 /*  4 bytes */
#define SMB2_TF_RESERVED	0x28 /*  2 bytes */
#define SMB2_TF_FLAGS		0x2A /*  2 bytes */
#define SMB2_TF_SESSION_ID	0x2C /*  8 bytes */

#define SMB2_TF_HDR_SIZE	0x34 /* 52 bytes */

#define SMB2_TF_MAGIC 0x424D53FD /* 0xFD 'S' 'M' 'B' */

#define SMB2_TF_FLAGS_ENCRYPTED     0x0001

/* offsets into header elements for a sync SMB2 request */
#define SMB2_HDR_PROTOCOL_ID    0x00
#define SMB2_HDR_LENGTH		0x04
#define SMB2_HDR_CREDIT_CHARGE	0x06
#define SMB2_HDR_EPOCH		SMB2_HDR_CREDIT_CHARGE /* TODO: remove this */
#define SMB2_HDR_STATUS		0x08
#define SMB2_HDR_CHANNEL_SEQUENCE SMB2_HDR_STATUS /* in requests */
#define SMB2_HDR_OPCODE		0x0c
#define SMB2_HDR_CREDIT		0x0e
#define SMB2_HDR_FLAGS		0x10
#define SMB2_HDR_NEXT_COMMAND	0x14
#define SMB2_HDR_MESSAGE_ID     0x18
#define SMB2_HDR_PID		0x20
#define SMB2_HDR_TID		0x24
#define SMB2_HDR_SESSION_ID	0x28
#define SMB2_HDR_SIGNATURE	0x30 /* 16 bytes */
#define SMB2_HDR_BODY		0x40

/* offsets into header elements for an async SMB2 request */
#define SMB2_HDR_ASYNC_ID	0x20

/* header flags */
#define SMB2_HDR_FLAG_REDIRECT  0x01
#define SMB2_HDR_FLAG_ASYNC     0x02
#define SMB2_HDR_FLAG_CHAINED   0x04
#define SMB2_HDR_FLAG_SIGNED    0x08
#define SMB2_HDR_FLAG_PRIORITY_MASK 0x70
#define SMB2_HDR_FLAG_DFS       0x10000000
#define SMB2_HDR_FLAG_REPLAY_OPERATION 0x20000000

#define SMB2_PRIORITY_MASK_TO_VALUE(__m) (((__m) & SMB2_HDR_FLAG_PRIORITY_MASK) >> 4)
#define SMB2_PRIORITY_VALUE_TO_MASK(__v) (((__v) << 4) & SMB2_HDR_FLAG_PRIORITY_MASK)

/* SMB2 opcodes */
#define SMB2_OP_NEGPROT		0x00
#define SMB2_OP_SESSSETUP	0x01
#define SMB2_OP_LOGOFF		0x02
#define SMB2_OP_TCON		0x03
#define SMB2_OP_TDIS		0x04
#define SMB2_OP_CREATE		0x05
#define SMB2_OP_CLOSE		0x06
#define SMB2_OP_FLUSH		0x07
#define SMB2_OP_READ		0x08
#define SMB2_OP_WRITE		0x09
#define SMB2_OP_LOCK		0x0a
#define SMB2_OP_IOCTL		0x0b
#define SMB2_OP_CANCEL		0x0c
#define SMB2_OP_KEEPALIVE	0x0d
#define SMB2_OP_QUERY_DIRECTORY	0x0e
#define SMB2_OP_NOTIFY		0x0f
#define SMB2_OP_GETINFO		0x10
#define SMB2_OP_SETINFO		0x11
#define SMB2_OP_BREAK		0x12

#define SMB2_MAGIC 0x424D53FE /* 0xFE 'S' 'M' 'B' */

/* SMB2 negotiate dialects */
#define SMB2_DIALECT_REVISION_000       0x0000 /* early beta dialect */
#define SMB2_DIALECT_REVISION_202       0x0202
#define SMB2_DIALECT_REVISION_210       0x0210
#define SMB2_DIALECT_REVISION_222       0x0222
#define SMB2_DIALECT_REVISION_224       0x0224
#define SMB3_DIALECT_REVISION_300       0x0300
#define SMB3_DIALECT_REVISION_302       0x0302
#define SMB3_DIALECT_REVISION_310       0x0310
#define SMB3_DIALECT_REVISION_311       0x0311
#define SMB2_DIALECT_REVISION_2FF       0x02FF

/* SMB2 negotiate security_mode */
#define SMB2_NEGOTIATE_SIGNING_ENABLED   0x01
#define SMB2_NEGOTIATE_SIGNING_REQUIRED  0x02

/* SMB2 global capabilities */
#define SMB2_CAP_DFS			0x00000001
#define SMB2_CAP_LEASING		0x00000002 /* only in dialect >= 0x210 */
#define SMB2_CAP_LARGE_MTU		0x00000004 /* only in dialect >= 0x210 */
#define SMB2_CAP_MULTI_CHANNEL		0x00000008 /* only in dialect >= 0x222 */
#define SMB2_CAP_PERSISTENT_HANDLES	0x00000010 /* only in dialect >= 0x222 */
#define SMB2_CAP_DIRECTORY_LEASING	0x00000020 /* only in dialect >= 0x222 */
#define SMB2_CAP_ENCRYPTION		0x00000040 /* only in dialect >= 0x222 */

/* so we can spot new caps as added */
#define SMB2_CAP_ALL (\
		SMB2_CAP_DFS | \
		SMB2_CAP_LEASING | \
		SMB2_CAP_LARGE_MTU | \
		SMB2_CAP_MULTI_CHANNEL | \
		SMB2_CAP_PERSISTENT_HANDLES | \
		SMB2_CAP_DIRECTORY_LEASING | \
		SMB2_CAP_ENCRYPTION)

/* Types of SMB2 Negotiate Contexts - only in dialect >= 0x310 */
#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES 0x0001
#define SMB2_ENCRYPTION_CAPABILITIES        0x0002
#define SMB2_COMPRESSION_CAPABILITIES       0x0003
#define SMB2_NETNAME_NEGOTIATE_CONTEXT_ID   0x0005
#define SMB2_TRANSPORT_CAPABILITIES         0x0006
#define SMB2_RDMA_TRANSFORM_CAPABILITIES    0x0007
#define SMB2_SIGNING_CAPABILITIES           0x0008
#define SMB2_POSIX_EXTENSIONS_AVAILABLE     0x0100

/* Values for the SMB2_PREAUTH_INTEGRITY_CAPABILITIES Context (>= 0x310) */
#define SMB2_PREAUTH_INTEGRITY_SHA512       0x0001

/* Values for the SMB2_SIGNING_CAPABILITIES Context (>= 0x311) */
#define SMB2_SIGNING_INVALID_ALGO          0xffff /* only used internally */
#define SMB2_SIGNING_MD5_SMB1              0xfffe /* internally for SMB1 */
#define SMB2_SIGNING_HMAC_SHA256           0x0000 /* default <= 0x210 */
#define SMB2_SIGNING_AES128_CMAC           0x0001 /* default >= 0x224 */
#define SMB2_SIGNING_AES128_GMAC           0x0002 /* only in dialect >= 0x311 */

/* Values for the SMB2_ENCRYPTION_CAPABILITIES Context (>= 0x311) */
#define SMB2_ENCRYPTION_INVALID_ALGO       0xffff /* only used internally */
#define SMB2_ENCRYPTION_NONE               0x0000 /* only used internally */
#define SMB2_ENCRYPTION_AES128_CCM         0x0001 /* only in dialect >= 0x224 */
#define SMB2_ENCRYPTION_AES128_GCM         0x0002 /* only in dialect >= 0x311 */
#define SMB2_ENCRYPTION_AES256_CCM         0x0003 /* only in dialect >= 0x311 */
#define SMB2_ENCRYPTION_AES256_GCM         0x0004 /* only in dialect >= 0x311 */
#define SMB2_NONCE_HIGH_MAX(nonce_len_bytes) ((uint64_t)(\
	((nonce_len_bytes) >= 16) ? UINT64_MAX : \
	((nonce_len_bytes) <= 8) ? 0 : \
	(((uint64_t)1 << (((nonce_len_bytes) - 8)*8)) - 1) \
	))

/* Values for the SMB2_TRANSPORT_CAPABILITIES Context (>= 0x311) */
#define SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY           0x0001

/* Values for the SMB2_RDMA_TRANSFORM_CAPABILITIES Context (>= 0x311) */
#define SMB2_RDMA_TRANSFORM_NONE                       0x0000
#define SMB2_RDMA_TRANSFORM_ENCRYPTION                 0x0001
#define SMB2_RDMA_TRANSFORM_SIGNING                    0x0002

/* SMB2 session (request) flags */
#define SMB2_SESSION_FLAG_BINDING       0x01
/*      SMB2_SESSION_FLAG_ENCRYPT_DATA  0x04       only in dialect >= 0x310 */

/* SMB2 session (response) flags */
#define SMB2_SESSION_FLAG_IS_GUEST       0x0001
#define SMB2_SESSION_FLAG_IS_NULL        0x0002
#define SMB2_SESSION_FLAG_ENCRYPT_DATA   0x0004 /* in dialect >= 0x224 */

/* SMB2 tree connect (request) flags */
#define SMB2_SHAREFLAG_CLUSTER_RECONNECT 0x0001 /* only in dialect >= 0x310 */

/* SMB2 sharetype flags */
#define SMB2_SHARE_TYPE_DISK		0x1
#define SMB2_SHARE_TYPE_PIPE		0x2
#define SMB2_SHARE_TYPE_PRINT		0x3

/* SMB2 share flags */
#define SMB2_SHAREFLAG_MANUAL_CACHING                    0x0000
#define SMB2_SHAREFLAG_AUTO_CACHING                      0x0010
#define SMB2_SHAREFLAG_VDO_CACHING                       0x0020
#define SMB2_SHAREFLAG_NO_CACHING                        0x0030
#define SMB2_SHAREFLAG_DFS                               0x0001
#define SMB2_SHAREFLAG_DFS_ROOT                          0x0002
#define SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS          0x0100
#define SMB2_SHAREFLAG_FORCE_SHARED_DELETE               0x0200
#define SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING           0x0400
#define SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM       0x0800
#define SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCKS             0x1000
#define SMB2_SHAREFLAG_ENABLE_HASH_V1                    0x2000
#define SMB2_SHAREFLAG_ENABLE_HASH_V2                    0x4000
#define SMB2_SHAREFLAG_ENCRYPT_DATA                      0x8000
#define SMB2_SHAREFLAG_IDENTITY_REMOTING             0x00040000
#define SMB2_SHAREFLAG_COMPRESS_DATA                 0x00100000
#define SMB2_SHAREFLAG_ISOLATED_TRANSPORT            0x00200000

/* SMB2 share capabilities */
#define SMB2_SHARE_CAP_DFS			0x8
#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY	0x10 /* in dialect >= 0x222 */
#define SMB2_SHARE_CAP_SCALEOUT			0x20 /* in dialect >= 0x222 */
#define SMB2_SHARE_CAP_CLUSTER			0x40 /* in dialect >= 0x222 */
#define SMB2_SHARE_CAP_ASYMMETRIC		0x80 /* in dialect >= 0x302 */

/* SMB2 create security flags */
#define SMB2_SECURITY_DYNAMIC_TRACKING                   0x01
#define SMB2_SECURITY_EFFECTIVE_ONLY                     0x02

/* SMB2 lock flags */
#define SMB2_LOCK_FLAG_NONE		0x00000000
#define SMB2_LOCK_FLAG_SHARED		0x00000001
#define SMB2_LOCK_FLAG_EXCLUSIVE	0x00000002
#define SMB2_LOCK_FLAG_UNLOCK		0x00000004
#define SMB2_LOCK_FLAG_FAIL_IMMEDIATELY	0x00000010
#define SMB2_LOCK_FLAG_ALL_MASK		0x00000017

/* SMB2 requested oplock levels */
#define SMB2_OPLOCK_LEVEL_NONE                           0x00
#define SMB2_OPLOCK_LEVEL_II                             0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE                      0x08
#define SMB2_OPLOCK_LEVEL_BATCH                          0x09
#define SMB2_OPLOCK_LEVEL_LEASE                          0xFF

/* SMB2 lease bits */
#define SMB2_LEASE_NONE                                  0x00

/* SMB2 lease flags */
#define SMB2_LEASE_FLAG_BREAK_IN_PROGRESS                0x00000002
#define SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET             0x00000004

/* SMB2 lease break flags */
#define SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED        0x01

/* SMB2 impersonation levels */
#define SMB2_IMPERSONATION_ANONYMOUS                     0x00
#define SMB2_IMPERSONATION_IDENTIFICATION                0x01
#define SMB2_IMPERSONATION_IMPERSONATION                 0x02
#define SMB2_IMPERSONATION_DELEGATE                      0x03

/* SMB2 create tags */
#define SMB2_CREATE_TAG_EXTA "ExtA"
#define SMB2_CREATE_TAG_MXAC "MxAc"
#define SMB2_CREATE_TAG_SECD "SecD"
#define SMB2_CREATE_TAG_DHNQ "DHnQ"
#define SMB2_CREATE_TAG_DHNC "DHnC"
#define SMB2_CREATE_TAG_ALSI "AlSi"
#define SMB2_CREATE_TAG_TWRP "TWrp"
#define SMB2_CREATE_TAG_QFID "QFid"
#define SMB2_CREATE_TAG_RQLS "RqLs"
#define SMB2_CREATE_TAG_DH2Q "DH2Q"
#define SMB2_CREATE_TAG_DH2C "DH2C"
#define SMB2_CREATE_TAG_AAPL "AAPL"
#define SMB2_CREATE_TAG_APP_INSTANCE_ID "\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A\x90\x08\xFA\x46\x2E\x14\x4D\x74"
#define SVHDX_OPEN_DEVICE_CONTEXT "\x9C\xCB\xCF\x9E\x04\xC1\xE6\x43\x98\x0E\x15\x8D\xA1\xF6\xEC\x83"
#define SMB2_CREATE_TAG_POSIX "\x93\xAD\x25\x50\x9C\xB4\x11\xE7\xB4\x23\x83\xDE\x96\x8B\xCD\x7C"

/* SMB2 notify flags */
#define SMB2_WATCH_TREE 0x0001

/* SMB2 Create ignore some more create_options */
#define SMB2_CREATE_OPTIONS_NOT_SUPPORTED_MASK	(NTCREATEX_OPTIONS_TREE_CONNECTION | \
						 NTCREATEX_OPTIONS_OPFILTER)

/*
  SMB2 uses different level numbers for the same old SMB trans2 search levels
*/
#define SMB2_FIND_DIRECTORY_INFO         0x01
#define SMB2_FIND_FULL_DIRECTORY_INFO    0x02
#define SMB2_FIND_BOTH_DIRECTORY_INFO    0x03
#define SMB2_FIND_NAME_INFO              0x0C
#define SMB2_FIND_ID_BOTH_DIRECTORY_INFO 0x25
#define SMB2_FIND_ID_FULL_DIRECTORY_INFO 0x26

/* SMB2 UNIX Extensions. */
#define SMB2_FIND_POSIX_INFORMATION	 0x64

/* flags for SMB2 find */
#define SMB2_CONTINUE_FLAG_RESTART    0x01
#define SMB2_CONTINUE_FLAG_SINGLE     0x02
#define SMB2_CONTINUE_FLAG_INDEX      0x04
#define SMB2_CONTINUE_FLAG_REOPEN     0x10

/* get/setinfo classes, see [MS-SMB2] 2.2.37 and 2.2.39 */
#define SMB2_0_INFO_FILE                0x01
#define SMB2_0_INFO_FILESYSTEM          0x02
#define SMB2_0_INFO_SECURITY            0x03
#define SMB2_0_INFO_QUOTA               0x04

#define SMB2_CLOSE_FLAGS_FULL_INFORMATION (0x01)

#define SMB2_READFLAG_READ_UNBUFFERED	0x01

#define SMB2_WRITEFLAG_WRITE_THROUGH	0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED	0x00000002

/* 2.2.31 SMB2 IOCTL Request */
#define SMB2_IOCTL_FLAG_IS_FSCTL		0x00000001

/*
 * Flags for durable handle v2 requests
 */
#define SMB2_DHANDLE_FLAG_PERSISTENT 0x00000002

/* The AES CCM nonce N of 15 - L octets. Where L=4 */
#define SMB2_AES_128_CCM_NONCE_SIZE 11

#endif

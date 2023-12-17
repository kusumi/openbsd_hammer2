/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2022 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _FS_HAMMER2_MOUNT_H_
#define _FS_HAMMER2_MOUNT_H_

#include <sys/mount.h>

/* Also defined in sys/sys/mount.h. */
#ifndef MOUNT_HAMMER2
#define MOUNT_HAMMER2	"hammer2"	/* HAMMER2 Filesystem */
#endif

/*
 * This structure is passed from userland to the kernel during the mount
 * system call.
 *
 * The fspec is formatted as '/dev/ad0s1a@LABEL', where the label is
 * the mount point under the super-root.
 *
 * struct hammer2_mount_info definition must be same as struct hammer2_args,
 * and its size must not exceed 160. The struct has to have char * at
 * offset 0 followed by struct export_args.
 */
struct hammer2_mount_info {
	char		*fspec;
	struct export_args export_info;	/* network export information */
	int		hflags;		/* extended hammer2 mount flags */
};

#define HMNT2_LOCAL		0x00000002
#define HMNT2_EMERG		0x00000004

#define HMNT2_DEVFLAGS		(HMNT2_LOCAL)

/* for sbin/sysctl/sysctl.c */
#define HAMMER2CTL_SUPPORTED_VERSION	1
#define HAMMER2CTL_DEDUP_ENABLE		2
#define HAMMER2CTL_INODE_ALLOCATED	3
#define HAMMER2CTL_CHAIN_ALLOCATED	4
#define HAMMER2CTL_CHAIN_MODIFIED	5
#define HAMMER2CTL_DIO_ALLOCATED	6
#define HAMMER2CTL_DIO_LIMIT		7
#define HAMMER2CTL_BULKFREE_TPS		8
#define HAMMER2CTL_LIMIT_SCAN_DEPTH	9
#define HAMMER2CTL_LIMIT_SAVED_CHAINS	10
#define HAMMER2CTL_ALWAYS_COMPRESS	11
#define HAMMER2CTL_MAXID		12

#define HAMMER2_NAMES { \
	{ 0, 0, }, \
	{ "supported_version", CTLTYPE_INT, }, \
	{ "dedup_enable", CTLTYPE_INT, }, \
	{ "inode_allocated", CTLTYPE_INT, }, \
	{ "chain_allocated", CTLTYPE_INT, }, \
	{ "chain_modified", CTLTYPE_INT, }, \
	{ "dio_allocated", CTLTYPE_INT, }, \
	{ "dio_limit", CTLTYPE_INT, }, \
	{ "bulkfree_tps", CTLTYPE_INT, }, \
	{ "limit_scan_depth", CTLTYPE_INT, }, \
	{ "limit_saved_chains", CTLTYPE_INT, }, \
	{ "always_compress", CTLTYPE_INT, }, \
}

#endif /* !_FS_HAMMER2_MOUNT_H_ */

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2022 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
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

/*
 * HAMMER2 in-memory cache of media structures.
 *
 * This header file contains structures used internally by the HAMMER2
 * implementation.  See hammer2_disk.h for on-disk structures.
 *
 * There is an in-memory representation of all on-media data structure.
 * Almost everything is represented by a hammer2_chain structure in-memory.
 * Other higher-level structures typically map to chains.
 *
 * A great deal of data is accessed simply via its buffer cache buffer,
 * which is mapped for the duration of the chain's lock.  HAMMER2 must
 * implement its own buffer cache layer on top of the system layer to
 * allow for different threads to lock different sub-block-sized buffers.
 *
 * When modifications are made to a chain a new filesystem block must be
 * allocated.  Multiple modifications do not typically allocate new blocks
 * until the current block has been flushed.  Flushes do not block the
 * front-end unless the front-end operation crosses the current inode being
 * flushed.
 *
 * The in-memory representation may remain cached even after the related
 * data has been detached.
 */

#ifndef _FS_HAMMER2_HAMMER2_H_
#define _FS_HAMMER2_HAMMER2_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/buf.h>
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/uuid.h>
#include <sys/stat.h>
#include <sys/atomic.h>

#include "hammer2_compat.h"
#include "hammer2_os.h"
#include "hammer2_disk.h"
#include "hammer2_ioctl.h"
#include "hammer2_rb.h"

struct hammer2_io;
struct hammer2_chain;
struct hammer2_depend;
struct hammer2_inode;
struct hammer2_dev;
struct hammer2_pfs;
union hammer2_xop;

typedef struct hammer2_io hammer2_io_t;
typedef struct hammer2_chain hammer2_chain_t;
typedef struct hammer2_depend hammer2_depend_t;
typedef struct hammer2_inode hammer2_inode_t;
typedef struct hammer2_dev hammer2_dev_t;
typedef struct hammer2_pfs hammer2_pfs_t;
typedef union hammer2_xop hammer2_xop_t;

/* global list of PFS */
TAILQ_HEAD(hammer2_pfslist, hammer2_pfs); /* <-> hammer2_pfs::mntentry */
typedef struct hammer2_pfslist hammer2_pfslist_t;

/* per HAMMER2 list of device vnode */
TAILQ_HEAD(hammer2_devvp_list, hammer2_devvp); /* <-> hammer2_devvp::entry */
typedef struct hammer2_devvp_list hammer2_devvp_list_t;

/* per PFS list of inode */
LIST_HEAD(hammer2_ipdep_list, hammer2_inode); /* <-> hammer2_inode::ientry */
typedef struct hammer2_ipdep_list hammer2_ipdep_list_t;

/* per chain rbtree of sub-chain */
RB_HEAD(hammer2_chain_tree, hammer2_chain); /* <-> hammer2_chain::rbnode */
typedef struct hammer2_chain_tree hammer2_chain_tree_t;

/* per PFS list of depend */
TAILQ_HEAD(hammer2_depq_head, hammer2_depend); /* <-> hammer2_depend::entry */
typedef struct hammer2_depq_head hammer2_depq_head_t;

/* per PFS / depend list of inode */
TAILQ_HEAD(hammer2_inoq_head, hammer2_inode); /* <-> hammer2_inode::qentry */
typedef struct hammer2_inoq_head hammer2_inoq_head_t;

/*
 * Cap the dynamic calculation for the maximum number of dirty
 * chains and dirty inodes allowed.
 */
#define HAMMER2_LIMIT_DIRTY_CHAINS	(1024*1024)
#define HAMMER2_LIMIT_DIRTY_INODES	(65536)

#define HAMMER2_IOHASH_SIZE		1024	/* OpenBSD: originally 32768 */
#define HAMMER2_IOHASH_MASK		(HAMMER2_IOHASH_SIZE - 1)

#define HAMMER2_INUMHASH_SIZE		1024	/* OpenBSD: originally 32768 */
#define HAMMER2_INUMHASH_MASK		(HAMMER2_IOHASH_SIZE - 1)

/*
 * HAMMER2 dio - Management structure wrapping system buffer cache.
 *
 * HAMMER2 uses an I/O abstraction that allows it to cache and manipulate
 * fixed-sized filesystem buffers frontend by variable-sized hammer2_chain
 * structures.
 *
 * Note that DragonFly uses atomic + interlock for refs, atomic for
 * dedup_xxx, whereas other BSD's protect them with dio lock.
 */
struct hammer2_io {
	struct hammer2_io	*next;
	hammer2_mtx_t		lock;
	hammer2_dev_t		*hmp;
	struct vnode		*devvp;
	struct buf		*bp;
	uint32_t		refs;
	hammer2_off_t		dbase;		/* offset of devvp within volumes */
	hammer2_off_t		pbase;
	int			psize;
	int			act;		/* activity */
	int			btype;
	int			ticks;
	int			error;
	uint64_t		dedup_valid;	/* valid for dedup operation */
	uint64_t		dedup_alloc;	/* allocated / de-dupable */
};

struct hammer2_io_hash {
	hammer2_spin_t		spin;
	struct hammer2_io	*base;
};

typedef struct hammer2_io_hash	hammer2_io_hash_t;

#define HAMMER2_DIO_GOOD	0x40000000U	/* dio->bp is stable */
#define HAMMER2_DIO_DIRTY	0x10000000U	/* flush last drop */
#define HAMMER2_DIO_FLUSH	0x08000000U	/* immediate flush */
#define HAMMER2_DIO_MASK	0x00FFFFFFU

struct hammer2_inum_hash {
	hammer2_spin_t		spin;
	struct hammer2_inode	*base;
};

typedef struct hammer2_inum_hash hammer2_inum_hash_t;

/*
 * The chain structure tracks a portion of the media topology from the
 * root (volume) down.  Chains represent volumes, inodes, indirect blocks,
 * data blocks, and freemap nodes and leafs.
 */
struct hammer2_reptrack {
	struct hammer2_reptrack	*next;
	hammer2_chain_t		*chain;
	hammer2_spin_t		spin;
};

typedef struct hammer2_reptrack hammer2_reptrack_t;

/*
 * Core topology for chain (embedded in chain).  Protected by a spinlock.
 */
struct hammer2_chain_core {
	hammer2_reptrack_t	*reptrack;
	hammer2_chain_tree_t	rbtree;		/* sub-chains */
	hammer2_spin_t		spin;
	int			live_zero;	/* blockref array opt */
	unsigned int		live_count;	/* live (not deleted) chains in tree */
	unsigned int		chain_count;	/* live + deleted chains under core */
	int			generation;	/* generation number (inserts only) */
};

typedef struct hammer2_chain_core hammer2_chain_core_t;

/*
 * Primary chain structure keeps track of the topology in-memory.
 */
struct hammer2_chain {
	RB_ENTRY(hammer2_chain) rbnode;		/* live chain(s) */
	hammer2_mtx_t		lock;
	hammer2_mtx_t		diolk;		/* xop focus interlock */
	hammer2_lk_t		inp_lock;
	hammer2_lkc_t		inp_cv;
	hammer2_chain_core_t	core;
	hammer2_blockref_t	bref;
	hammer2_dev_t		*hmp;
	hammer2_pfs_t		*pmp;		/* A PFS or super-root (spmp) */
	hammer2_chain_t		*parent;
	hammer2_io_t		*dio;		/* physical data buffer */
	hammer2_media_data_t	*data;		/* data pointer shortcut */
	unsigned int		refs;
	unsigned int		lockcnt;
	unsigned int		flags;		/* for HAMMER2_CHAIN_xxx */
	unsigned int		bytes;		/* physical data size */
	int			error;		/* on-lock data error state */
	int			cache_index;	/* heur speeds up lookup */
};

/*
 * Passed to hammer2_chain_create(), causes methods to be inherited from
 * parent.
 */
#define HAMMER2_METH_DEFAULT		-1

/*
 * Special notes on flags:
 *
 * INITIAL	- This flag allows a chain to be created and for storage to
 *		  be allocated without having to immediately instantiate the
 *		  related buffer.  The data is assumed to be all-zeros.  It
 *		  is primarily used for indirect blocks.
 *
 * MODIFIED	- The chain's media data has been modified.  Prevents chain
 *		  free on lastdrop if still in the topology.
 *
 * UPDATE	- Chain might not be modified but parent blocktable needs
 *		  an update.  Prevents chain free on lastdrop if still in
 *		  the topology.
 *
 * BLKMAPPED	- Indicates that the chain is present in the parent blockmap.
 *
 * BLKMAPUPD	- Indicates that the chain is present but needs to be updated
 *		  in the parent blockmap.
 */
#define HAMMER2_CHAIN_MODIFIED		0x00000001	/* dirty chain data */
#define HAMMER2_CHAIN_ALLOCATED		0x00000002	/* kmalloc'd chain */
#define HAMMER2_CHAIN_DESTROY		0x00000004
#define HAMMER2_CHAIN_DEDUPABLE		0x00000008	/* registered w/dedup */
#define HAMMER2_CHAIN_DELETED		0x00000010	/* deleted chain */
#define HAMMER2_CHAIN_INITIAL		0x00000020	/* initial create */
#define HAMMER2_CHAIN_UPDATE		0x00000040	/* need parent update */
#define HAMMER2_CHAIN_NOTTESTED		0x00000080	/* crc not generated */
#define HAMMER2_CHAIN_TESTEDGOOD	0x00000100	/* crc tested good */
#define HAMMER2_CHAIN_ONFLUSH		0x00000200	/* on a flush list */
#define HAMMER2_CHAIN_VOLUMESYNC	0x00000800	/* needs volume sync */
#define HAMMER2_CHAIN_COUNTEDBREFS	0x00002000	/* block table stats */
#define HAMMER2_CHAIN_ONRBTREE		0x00004000	/* on parent RB tree */
#define HAMMER2_CHAIN_RELEASE		0x00020000	/* don't keep around */
#define HAMMER2_CHAIN_BLKMAPPED		0x00040000	/* present in blkmap */
#define HAMMER2_CHAIN_BLKMAPUPD		0x00080000	/* +needs updating */
#define HAMMER2_CHAIN_IOINPROG		0x00100000	/* I/O interlock */
#define HAMMER2_CHAIN_IOSIGNAL		0x00200000	/* I/O interlock */
#define HAMMER2_CHAIN_PFSBOUNDARY	0x00400000	/* super->pfs inode */
#define HAMMER2_CHAIN_HINT_LEAF_COUNT	0x00800000	/* redo leaf count */

#define HAMMER2_CHAIN_FLUSH_MASK	(HAMMER2_CHAIN_MODIFIED |	\
					 HAMMER2_CHAIN_UPDATE |		\
					 HAMMER2_CHAIN_ONFLUSH |	\
					 HAMMER2_CHAIN_DESTROY)

/*
 * HAMMER2 error codes, used by chain->error and cluster->error.  The error
 * code is typically set on-lock unless no I/O was requested, and set on
 * I/O otherwise.  If set for a cluster it generally means that the cluster
 * code could not find a valid copy to present.
 *
 * All HAMMER2 error codes are flags and can be accumulated by ORing them
 * together.
 *
 * EIO		- An I/O error occurred
 * CHECK	- I/O succeeded but did not match the check code
 *
 * NOTE: API allows callers to check zero/non-zero to determine if an error
 *	 condition exists.
 *
 * NOTE: Chain's data field is usually NULL on an IO error but not necessarily
 *	 NULL on other errors.  Check chain->error, not chain->data.
 */
#define HAMMER2_ERROR_EIO		0x00000001	/* device I/O error */
#define HAMMER2_ERROR_CHECK		0x00000002	/* check code error */
#define HAMMER2_ERROR_BADBREF		0x00000010	/* illegal bref */
#define HAMMER2_ERROR_ENOSPC		0x00000020	/* allocation failure */
#define HAMMER2_ERROR_ENOENT		0x00000040	/* entry not found */
#define HAMMER2_ERROR_ENOTEMPTY		0x00000080	/* dir not empty */
#define HAMMER2_ERROR_EAGAIN		0x00000100	/* retry */
#define HAMMER2_ERROR_ENOTDIR		0x00000200	/* not directory */
#define HAMMER2_ERROR_EISDIR		0x00000400	/* is directory */
#define HAMMER2_ERROR_ABORTED		0x00001000	/* aborted operation */
#define HAMMER2_ERROR_EOF		0x00002000	/* end of scan */
#define HAMMER2_ERROR_EINVAL		0x00004000	/* catch-all */
#define HAMMER2_ERROR_EEXIST		0x00008000	/* entry exists */
#define HAMMER2_ERROR_EOPNOTSUPP	0x10000000	/* unsupported */

/*
 * Flags passed to hammer2_chain_lookup() and hammer2_chain_next().
 *
 * NOTES:
 *	NODATA	    - Asks that the chain->data not be resolved in order
 *		      to avoid I/O.
 *
 *	NODIRECT    - Prevents a lookup of offset 0 in an inode from returning
 *		      the inode itself if the inode is in DIRECTDATA mode
 *		      (i.e. file is <= 512 bytes).  Used by the synchronization
 *		      code to prevent confusion.
 *
 *	SHARED	    - The input chain is expected to be locked shared,
 *		      and the output chain is locked shared.
 *
 *	MATCHIND    - Allows an indirect block / freemap node to be returned
 *		      when the passed key range matches the radix.  Remember
 *		      that key_end is inclusive (e.g. {0x000,0xFFF},
 *		      not {0x000,0x1000}).
 *
 *		      (Cannot be used for remote or cluster ops).
 *
 *	ALWAYS	    - Always resolve the data.  If ALWAYS and NODATA are both
 *		      missing, bulk file data is not resolved but inodes and
 *		      other meta-data will.
 */
#define HAMMER2_LOOKUP_NODATA		0x00000002	/* data left NULL */
#define HAMMER2_LOOKUP_NODIRECT		0x00000004	/* no offset=0 DD */
#define HAMMER2_LOOKUP_SHARED		0x00000100
#define HAMMER2_LOOKUP_MATCHIND		0x00000200	/* return all chains */
#define HAMMER2_LOOKUP_ALWAYS		0x00000800	/* resolve data */

/*
 * Flags passed to hammer2_chain_modify() and hammer2_chain_resize().
 *
 * NOTE: OPTDATA allows us to avoid instantiating buffers for INDIRECT
 *	 blocks in the INITIAL-create state.
 */
#define HAMMER2_MODIFY_OPTDATA		0x00000002	/* data can be NULL */

/*
 * Flags passed to hammer2_chain_lock().
 *
 * NOTE: NONBLOCK is only used for hammer2_chain_repparent() and getparent(),
 *	 other functions (e.g. hammer2_chain_lookup(), etc) can't handle its
 *	 operation.
 */
#define HAMMER2_RESOLVE_NEVER		1
#define HAMMER2_RESOLVE_MAYBE		2
#define HAMMER2_RESOLVE_ALWAYS		3
#define HAMMER2_RESOLVE_MASK		0x0F

#define HAMMER2_RESOLVE_SHARED		0x10	/* request shared lock */
#define HAMMER2_RESOLVE_LOCKAGAIN	0x20	/* another shared lock */
#define HAMMER2_RESOLVE_NONBLOCK	0x80	/* non-blocking */

/*
 * Flags passed to hammer2_chain_delete().
 */
#define HAMMER2_DELETE_PERMANENT	0x0001

/*
 * Flags passed to hammer2_chain_insert() or hammer2_chain_rename()
 * or hammer2_chain_create().
 */
#define HAMMER2_INSERT_PFSROOT		0x0004
#define HAMMER2_INSERT_SAMEPARENT	0x0008

/*
 * Flags passed to hammer2_freemap_adjust().
 */
#define HAMMER2_FREEMAP_DORECOVER	1

/*
 * HAMMER2 cluster - A set of chains representing the same entity.
 *
 * Currently a valid cluster can only have 1 set of chains (nchains)
 * representing the same entity.
 */
#define HAMMER2_XOPFIFO		16

#define HAMMER2_MAXCLUSTER	8
#define HAMMER2_XOPMASK_VOP	((uint32_t)0x80000000U)

#define HAMMER2_XOPMASK_ALLDONE	(HAMMER2_XOPMASK_VOP)

struct hammer2_cluster_item {
	hammer2_chain_t		*chain;
	uint32_t		flags;		/* for HAMMER2_CITEM_xxx */
	int			error;
};

typedef struct hammer2_cluster_item hammer2_cluster_item_t;

#define HAMMER2_CITEM_NULL	0x00000004

struct hammer2_cluster {
	hammer2_cluster_item_t	array[HAMMER2_MAXCLUSTER];
	hammer2_pfs_t		*pmp;
	hammer2_chain_t		*focus;		/* current focus (or mod) */
	int			nchains;
	int			error;		/* error code valid on lock */
};

typedef struct hammer2_cluster	hammer2_cluster_t;

struct hammer2_depend {
	TAILQ_ENTRY(hammer2_depend) entry;
	hammer2_inoq_head_t	sideq;
	long			count;
	int			pass2;
};

/*
 * HAMMER2 inode.
 */
struct hammer2_inode {
	struct hammer2_inode	*next;		/* inode tree */
	TAILQ_ENTRY(hammer2_inode) qentry;	/* SYNCQ/SIDEQ */
	LIST_ENTRY(hammer2_inode) ientry;
	hammer2_depend_t	*depend;	/* non-NULL if SIDEQ */
	hammer2_depend_t	depend_static;	/* (in-place allocation) */
	hammer2_mtx_t		lock;		/* inode lock */
	hammer2_mtx_t		truncate_lock;	/* prevent truncates */
	hammer2_mtx_t		vhold_lock;
	struct rrwlock		vnlock;		/* OpenBSD: vnode lock */
	hammer2_spin_t		cluster_spin;	/* update cluster */
	hammer2_cluster_t	cluster;
	hammer2_cluster_item_t	ccache[HAMMER2_MAXCLUSTER];
	int			ccache_nchains;
	hammer2_inode_meta_t	meta;		/* copy of meta-data */
	hammer2_pfs_t		*pmp;		/* PFS mount */
	hammer2_off_t		osize;
	struct vnode		*vp;
	unsigned int		refs;		/* +vpref, +flushref */
	unsigned int		flags;		/* for HAMMER2_INODE_xxx */
	uint8_t			comp_heuristic;
	int			ipdep_idx;
	int			vhold;
	int			in_seek;	/* FIOSEEKXXX */
};

/*
 * MODIFIED	- Inode is in a modified state, ip->meta may have changes.
 * RESIZED	- Inode truncated (any) or inode extended beyond
 *		  EMBEDDED_BYTES.
 *
 * SYNCQ	- Inode is included in the current filesystem sync.  The
 *		  DELETING and CREATING flags will be acted upon.
 *
 * SIDEQ	- Inode has likely been disconnected from the vnode topology
 *		  and so is not visible to the vnode-based filesystem syncer
 *		  code, but is dirty and must be included in the next
 *		  filesystem sync.  These inodes are moved to the SYNCQ at
 *		  the time the sync occurs.
 *
 *		  Inodes are not placed on this queue simply because they have
 *		  become dirty, if a vnode is attached.
 *
 * DELETING	- Inode is flagged for deletion during the next filesystem
 *		  sync.  That is, the inode's chain is currently connected
 *		  and must be deleting during the current or next fs sync.
 *
 * CREATING	- Inode is flagged for creation during the next filesystem
 *		  sync.  That is, the inode's chain topology exists (so
 *		  kernel buffer flushes can occur), but is currently
 *		  disconnected and must be inserted during the current or
 *		  next fs sync.  If the DELETING flag is also set, the
 *		  topology can be thrown away instead.
 *
 * If an inode that is already part of the current filesystem sync is
 * modified by the frontend, including by buffer flushes, the inode lock
 * code detects the SYNCQ flag and moves the inode to the head of the
 * flush-in-progress, then blocks until the flush has gotten past it.
 */
#define HAMMER2_INODE_MODIFIED		0x0001
#define HAMMER2_INODE_ONHASH		0x0008
#define HAMMER2_INODE_RESIZED		0x0010	/* requires inode_chain_sync */
#define HAMMER2_INODE_ISUNLINKED	0x0040
#define HAMMER2_INODE_SIDEQ		0x0100	/* on side processing queue */
#define HAMMER2_INODE_NOSIDEQ		0x0200	/* disable sideq operation */
#define HAMMER2_INODE_DIRTYDATA		0x0400	/* interlocks inode flush */
#define HAMMER2_INODE_SYNCQ		0x0800	/* sync interlock, sequenced */
#define HAMMER2_INODE_DELETING		0x1000	/* sync interlock, chain topo */
#define HAMMER2_INODE_CREATING		0x2000	/* sync interlock, chain topo */
#define HAMMER2_INODE_SYNCQ_WAKEUP	0x4000	/* sync interlock wakeup */
#define HAMMER2_INODE_SYNCQ_PASS2	0x8000	/* force retry delay */

/*
 * Transaction management sub-structure under hammer2_pfs.
 */
struct hammer2_trans {
	uint32_t		flags;
};

typedef struct hammer2_trans hammer2_trans_t;

#define HAMMER2_TRANS_ISFLUSH		0x80000000	/* flush code */
#define HAMMER2_TRANS_BUFCACHE		0x40000000	/* bio strategy */
#define HAMMER2_TRANS_SIDEQ		0x20000000	/* run sideq */
#define HAMMER2_TRANS_WAITING		0x08000000	/* someone waiting */
#define HAMMER2_TRANS_RESCAN		0x04000000	/* rescan sideq */
#define HAMMER2_TRANS_MASK		0x00FFFFFF	/* count mask */

#define HAMMER2_FREEMAP_HEUR_NRADIX	4	/* pwr 2 PBUFRADIX-LBUFRADIX */
#define HAMMER2_FREEMAP_HEUR_TYPES	8
#define HAMMER2_FREEMAP_HEUR_SIZE	(HAMMER2_FREEMAP_HEUR_NRADIX * \
					 HAMMER2_FREEMAP_HEUR_TYPES)

#define HAMMER2_DEDUP_HEUR_SIZE		(65536 * 4)
#define HAMMER2_DEDUP_HEUR_MASK		(HAMMER2_DEDUP_HEUR_SIZE - 1)

#define HAMMER2_FLUSH_TOP		0x0001
#define HAMMER2_FLUSH_ALL		0x0002
#define HAMMER2_FLUSH_INODE_STOP	0x0004	/* stop at sub-inode */
#define HAMMER2_FLUSH_FSSYNC		0x0008	/* part of filesystem sync */

/*
 * Support structure for dedup heuristic.
 */
struct hammer2_dedup {
	hammer2_off_t		data_off;
	uint64_t		data_crc;
	uint32_t		ticks;
	uint32_t		saved_error;
};

typedef struct hammer2_dedup hammer2_dedup_t;

/*
 * HAMMER2 XOP - container for VOP/XOP operation.
 *
 * This structure is used to distribute a VOP operation across multiple
 * nodes.  Unlike DragonFly HAMMER2, XOP is currently just a function called
 * by VOP to handle chains.
 */
typedef void (*hammer2_xop_func_t)(union hammer2_xop *, void *, int);

struct hammer2_xop_desc {
	hammer2_xop_func_t	storage_func;	/* local storage function */
	const char		*id;
};

typedef struct hammer2_xop_desc hammer2_xop_desc_t;

struct hammer2_xop_fifo {
	hammer2_chain_t		**array;
	int			*errors;
	int			ri;
	int			wi;
	int			flags;
};

typedef struct hammer2_xop_fifo hammer2_xop_fifo_t;

struct hammer2_xop_head {
	hammer2_tid_t		mtid;
	hammer2_xop_fifo_t	collect[HAMMER2_MAXCLUSTER];
	hammer2_cluster_t	cluster;
	hammer2_xop_desc_t	*desc;
	hammer2_inode_t		*ip1;
	hammer2_inode_t		*ip2;
	hammer2_inode_t		*ip3;
	hammer2_inode_t		*ip4;
	hammer2_io_t		*focus_dio;
	hammer2_key_t		collect_key;
	uint32_t		run_mask;
	uint32_t		chk_mask;
	int			flags;
	int			fifo_size;
	int			error;
	char			*name1;
	size_t			name1_len;
	char			*name2;
	size_t			name2_len;
	void			*scratch;
};

typedef struct hammer2_xop_head hammer2_xop_head_t;

#define fifo_mask(xop_head)	((xop_head)->fifo_size - 1)

struct hammer2_xop_ipcluster {
	hammer2_xop_head_t	head;
};

struct hammer2_xop_readdir {
	hammer2_xop_head_t	head;
	hammer2_key_t		lkey;
};

struct hammer2_xop_nresolve {
	hammer2_xop_head_t	head;
};

struct hammer2_xop_unlink {
	hammer2_xop_head_t	head;
	int			isdir;
	int			dopermanent;
};

#define H2DOPERM_PERMANENT	0x01
#define H2DOPERM_FORCE		0x02
#define H2DOPERM_IGNINO		0x04

struct hammer2_xop_nrename {
	hammer2_xop_head_t	head;
	hammer2_tid_t		lhc;
	int			ip_key;
};

struct hammer2_xop_scanlhc {
	hammer2_xop_head_t	head;
	hammer2_key_t		lhc;
};

struct hammer2_xop_scanall {
	hammer2_xop_head_t	head;
	hammer2_key_t		key_beg;	/* inclusive */
	hammer2_key_t		key_end;	/* inclusive */
	int			resolve_flags;
	int			lookup_flags;
};

struct hammer2_xop_lookup {
	hammer2_xop_head_t	head;
	hammer2_key_t		lhc;
};

struct hammer2_xop_mkdirent {
	hammer2_xop_head_t	head;
	hammer2_dirent_head_t	dirent;
	hammer2_key_t		lhc;
};

struct hammer2_xop_create {
	hammer2_xop_head_t	head;
	hammer2_inode_meta_t	meta;
	hammer2_key_t		lhc;
	int			flags;
};

struct hammer2_xop_destroy {
	hammer2_xop_head_t	head;
};

struct hammer2_xop_fsync {
	hammer2_xop_head_t	head;
	hammer2_inode_meta_t	meta;
	hammer2_off_t		osize;
	u_int			ipflags;
	int			clear_directdata;
};

struct hammer2_xop_unlinkall {
	hammer2_xop_head_t	head;
	hammer2_key_t		key_beg;
	hammer2_key_t		key_end;
};

struct hammer2_xop_connect {
	hammer2_xop_head_t	head;
	hammer2_key_t		lhc;
};

struct hammer2_xop_flush {
	hammer2_xop_head_t	head;
};

struct hammer2_xop_strategy {
	hammer2_xop_head_t	head;
	hammer2_key_t		lbase;
	struct buf		*bp;
};

struct hammer2_xop_bmap {
	hammer2_xop_head_t	head;
	daddr_t			lbn;
	int			runp;
	int			runb;
	hammer2_off_t		offset;
};

typedef struct hammer2_xop_ipcluster hammer2_xop_ipcluster_t;
typedef struct hammer2_xop_readdir hammer2_xop_readdir_t;
typedef struct hammer2_xop_nresolve hammer2_xop_nresolve_t;
typedef struct hammer2_xop_unlink hammer2_xop_unlink_t;
typedef struct hammer2_xop_nrename hammer2_xop_nrename_t;
typedef struct hammer2_xop_scanlhc hammer2_xop_scanlhc_t;
typedef struct hammer2_xop_scanall hammer2_xop_scanall_t;
typedef struct hammer2_xop_lookup hammer2_xop_lookup_t;
typedef struct hammer2_xop_mkdirent hammer2_xop_mkdirent_t;
typedef struct hammer2_xop_create hammer2_xop_create_t;
typedef struct hammer2_xop_destroy hammer2_xop_destroy_t;
typedef struct hammer2_xop_fsync hammer2_xop_fsync_t;
typedef struct hammer2_xop_unlinkall hammer2_xop_unlinkall_t;
typedef struct hammer2_xop_connect hammer2_xop_connect_t;
typedef struct hammer2_xop_flush hammer2_xop_flush_t;
typedef struct hammer2_xop_strategy hammer2_xop_strategy_t;
typedef struct hammer2_xop_bmap hammer2_xop_bmap_t;

union hammer2_xop {
	hammer2_xop_head_t	head;
	hammer2_xop_ipcluster_t	xop_ipcluster;
	hammer2_xop_readdir_t	xop_readdir;
	hammer2_xop_nresolve_t	xop_nresolve;
	hammer2_xop_unlink_t	xop_unlink;
	hammer2_xop_nrename_t	xop_nrename;
	hammer2_xop_scanlhc_t	xop_scanlhc;
	hammer2_xop_scanall_t	xop_scanall;
	hammer2_xop_lookup_t	xop_lookup;
	hammer2_xop_mkdirent_t	xop_mkdirent;
	hammer2_xop_create_t	xop_create;
	hammer2_xop_destroy_t	xop_destroy;
	hammer2_xop_fsync_t	xop_fsync;
	hammer2_xop_unlinkall_t	xop_unlinkall;
	hammer2_xop_connect_t	xop_connect;
	hammer2_xop_flush_t	xop_flush;
	hammer2_xop_strategy_t	xop_strategy;
	hammer2_xop_bmap_t	xop_bmap;
};

/*
 * flags to hammer2_xop_collect().
 */
#define HAMMER2_XOP_COLLECT_NOWAIT	0x00000001
#define HAMMER2_XOP_COLLECT_WAITALL	0x00000002

/*
 * flags to hammer2_xop_alloc().
 *
 * MODIFYING	- This is a modifying transaction, allocate a mtid.
 */
#define HAMMER2_XOP_MODIFYING		0x00000001
#define HAMMER2_XOP_STRATEGY		0x00000002
#define HAMMER2_XOP_INODE_STOP		0x00000004
#define HAMMER2_XOP_VOLHDR		0x00000008
#define HAMMER2_XOP_FSSYNC		0x00000010

/*
 * Device vnode management structure.
 */
struct hammer2_devvp {
	TAILQ_ENTRY(hammer2_devvp) entry;
	struct vnode		*devvp;		/* device vnode */
	char			*path;		/* device vnode path */
	char			*fname;		/* OpenBSD */
	int			open;		/* 1 if devvp open */
	int			xflags;		/* OpenBSD */
};

typedef struct hammer2_devvp hammer2_devvp_t;

/*
 * Volume management structure.
 */
struct hammer2_volume {
	hammer2_devvp_t		*dev;		/* device vnode management */
	hammer2_off_t		offset;		/* offset within volumes */
	hammer2_off_t		size;		/* volume size */
	int			id;		/* volume id */
};

typedef struct hammer2_volume hammer2_volume_t;

/*
 * I/O stat structure.
 */
struct hammer2_iostat_unit {
	unsigned long		count;
	unsigned long		bytes;
};

typedef struct hammer2_iostat_unit hammer2_iostat_unit_t;

struct hammer2_iostat {
	hammer2_iostat_unit_t	inode;
	hammer2_iostat_unit_t	indirect;
	hammer2_iostat_unit_t	data;
	hammer2_iostat_unit_t	dirent;
	hammer2_iostat_unit_t	freemap_node;
	hammer2_iostat_unit_t	freemap_leaf;
	hammer2_iostat_unit_t	freemap;
	hammer2_iostat_unit_t	volume;
};

typedef struct hammer2_iostat hammer2_iostat_t;

/*
 * Global (per partition) management structure, represents a hard block
 * device.  Typically referenced by hammer2_chain structures when applicable.
 *
 * Note that a single hammer2_dev can be indirectly tied to multiple system
 * mount points.  There is no direct relationship.  System mounts are
 * per-cluster-id, not per-block-device, and a single hard mount might contain
 * many PFSs.
 */
struct hammer2_dev {
	TAILQ_ENTRY(hammer2_dev) mntentry;	/* hammer2_mntlist */
	hammer2_devvp_list_t	devvp_list;	/* list of device vnodes including *devvp */
	hammer2_io_hash_t	iohash[HAMMER2_IOHASH_SIZE];
	hammer2_mtx_t		iohash_lock;
	hammer2_pfs_t		*spmp;		/* super-root pmp for transactions */
	struct vnode		*devvp;		/* device vnode for root volume */
	hammer2_chain_t		vchain;		/* anchor chain (topology) */
	hammer2_chain_t		fchain;		/* anchor chain (freemap) */
	hammer2_volume_data_t	voldata;
	hammer2_volume_data_t	volsync;	/* synchronized voldata */
	hammer2_volume_t	volumes[HAMMER2_MAX_VOLUMES]; /* list of volumes */
	hammer2_off_t		total_size;	/* total size of volumes */
	uint32_t		hflags;		/* HMNT2 flags applicable to device */
	int			rdonly;		/* read-only mount */
	int			mount_count;	/* number of actively mounted PFSs */
	int			nvolumes;	/* total number of volumes */
	int			volhdrno;	/* last volhdrno written */
	int			iofree_count;
	int			io_iterator;
	hammer2_lk_t		vollk;		/* lockmgr lock */
	hammer2_lk_t		bulklk;		/* bulkfree operation lock */
	hammer2_lk_t		bflk;		/* bulk-free manual function lock */
	int			freemap_relaxed;
	hammer2_off_t		free_reserved;	/* nominal free reserved */
	hammer2_off_t		heur_freemap[HAMMER2_FREEMAP_HEUR_SIZE];
	hammer2_dedup_t		heur_dedup[HAMMER2_DEDUP_HEUR_SIZE];
	hammer2_iostat_t	iostat_read;	/* read I/O stat */
	hammer2_iostat_t	iostat_write;	/* write I/O stat */
};

/*
 * Per-cluster management structure.  This structure will be tied to a
 * system mount point if the system is mounting the PFS.
 *
 * This structure is also used to represent the super-root that hangs off
 * of a hard mount point.  The super-root is not really a cluster element.
 * In this case the spmp_hmp field will be non-NULL.  It's just easier to do
 * this than to special case super-root manipulation in the hammer2_chain*
 * code as being only hammer2_dev-related.
 *
 * WARNING! The chains making up pfs->iroot's cluster are accounted for in
 *	    hammer2_dev->mount_count when the pfs is associated with a mount
 *	    point.
 */
#define HAMMER2_IHASH_SIZE	32

struct hammer2_pfs {
	TAILQ_ENTRY(hammer2_pfs) mntentry;	/* hammer2_pfslist */
	hammer2_ipdep_list_t	*ipdep_lists;	/* inode dependencies for XOP */
	hammer2_spin_t          blockset_spin;
	hammer2_spin_t		list_spin;
	hammer2_lk_t		xop_lock[HAMMER2_IHASH_SIZE];
	hammer2_lkc_t		xop_cv[HAMMER2_IHASH_SIZE];
	hammer2_lk_t		trans_lock;	/* XXX temporary */
	hammer2_lkc_t		trans_cv;
	struct mount		*mp;
	struct uuid		pfs_clid;
	hammer2_trans_t		trans;
	hammer2_inode_t		*iroot;		/* PFS root inode */
	hammer2_dev_t		*spmp_hmp;	/* only if super-root pmp */
	hammer2_dev_t		*force_local;	/* only if 'local' mount */
	hammer2_dev_t		*pfs_hmps[HAMMER2_MAXCLUSTER];
	char			*pfs_names[HAMMER2_MAXCLUSTER];
	uint8_t			pfs_types[HAMMER2_MAXCLUSTER];
	hammer2_blockset_t	pfs_iroot_blocksets[HAMMER2_MAXCLUSTER];
	int			flags;		/* for HAMMER2_PMPF_xxx */
	int			rdonly;		/* read-only mount */
	int			free_ticks;	/* free_* calculations */
	unsigned long		ipdep_mask;
	hammer2_off_t		free_reserved;
	hammer2_off_t		free_nominal;
	hammer2_tid_t		modify_tid;	/* modify transaction id */
	hammer2_tid_t		inode_tid;	/* inode allocator */
	hammer2_inoq_head_t	syncq;		/* SYNCQ flagged inodes */
	hammer2_depq_head_t	depq;		/* SIDEQ flagged inodes */
	long			sideq_count;	/* total inodes on depq */
	/* note: inumhash not applicable to spmp */
	hammer2_inum_hash_t	inumhash[HAMMER2_INUMHASH_SIZE];
	char			*fspec;		/* OpenBSD */
	struct netexport	pm_export;	/* OpenBSD: export information */
};

#define HAMMER2_PMPF_SPMP	0x00000001
#define HAMMER2_PMPF_EMERG	0x00000002
#define HAMMER2_PMPF_WAITING	0x10000000

#define HAMMER2_CHECK_NULL	0x00000001

#define MPTOPMP(mp)	((hammer2_pfs_t *)(mp)->mnt_data)
#define VTOI(vp)	((hammer2_inode_t *)(vp)->v_data)

extern struct hammer2_pfslist hammer2_pfslist;

extern hammer2_lk_t hammer2_mntlk;

extern int hammer2_dedup_enable;
extern int hammer2_count_inode_allocated;
extern int hammer2_count_chain_allocated;
extern int hammer2_count_chain_modified;
extern int hammer2_count_dio_allocated;
extern int hammer2_dio_limit;
extern int hammer2_bulkfree_tps;
extern int hammer2_limit_scan_depth;
extern int hammer2_limit_saved_chains;
extern int hammer2_always_compress;

extern hammer2_xop_desc_t hammer2_ipcluster_desc;
extern hammer2_xop_desc_t hammer2_readdir_desc;
extern hammer2_xop_desc_t hammer2_nresolve_desc;
extern hammer2_xop_desc_t hammer2_unlink_desc;
extern hammer2_xop_desc_t hammer2_nrename_desc;
extern hammer2_xop_desc_t hammer2_scanlhc_desc;
extern hammer2_xop_desc_t hammer2_scanall_desc;
extern hammer2_xop_desc_t hammer2_lookup_desc;
extern hammer2_xop_desc_t hammer2_delete_desc;
extern hammer2_xop_desc_t hammer2_inode_mkdirent_desc;
extern hammer2_xop_desc_t hammer2_inode_create_desc;
extern hammer2_xop_desc_t hammer2_inode_create_det_desc;
extern hammer2_xop_desc_t hammer2_inode_create_ins_desc;
extern hammer2_xop_desc_t hammer2_inode_destroy_desc;
extern hammer2_xop_desc_t hammer2_inode_chain_sync_desc;
extern hammer2_xop_desc_t hammer2_inode_unlinkall_desc;
extern hammer2_xop_desc_t hammer2_inode_connect_desc;
extern hammer2_xop_desc_t hammer2_inode_flush_desc;
extern hammer2_xop_desc_t hammer2_strategy_read_desc;
extern hammer2_xop_desc_t hammer2_strategy_write_desc;
extern hammer2_xop_desc_t hammer2_bmap_desc;

/* hammer2_admin.c */
void *hammer2_xop_alloc(hammer2_inode_t *, int);
void hammer2_xop_setname(hammer2_xop_head_t *, const char *, size_t);
void hammer2_xop_setname2(hammer2_xop_head_t *, const char *, size_t);
size_t hammer2_xop_setname_inum(hammer2_xop_head_t *, hammer2_key_t);
void hammer2_xop_setip2(hammer2_xop_head_t *, hammer2_inode_t *);
void hammer2_xop_setip3(hammer2_xop_head_t *, hammer2_inode_t *);
void hammer2_xop_setip4(hammer2_xop_head_t *, hammer2_inode_t *);
void hammer2_xop_start(hammer2_xop_head_t *, hammer2_xop_desc_t *);
void hammer2_xop_retire(hammer2_xop_head_t *, uint32_t);
int hammer2_xop_feed(hammer2_xop_head_t *, hammer2_chain_t *, int, int);
int hammer2_xop_collect(hammer2_xop_head_t *, int);

/* hammer2_bulkfree.c */
void hammer2_bulkfree_init(hammer2_dev_t *);
void hammer2_bulkfree_uninit(hammer2_dev_t *);
int hammer2_bulkfree_pass(hammer2_dev_t *, hammer2_chain_t *,
    struct hammer2_ioc_bulkfree *);

/* hammer2_chain.c */
int hammer2_chain_cmp(const hammer2_chain_t *, const hammer2_chain_t *);
void hammer2_chain_setflush(hammer2_chain_t *);
void hammer2_chain_init(hammer2_chain_t *);
void hammer2_chain_ref(hammer2_chain_t *);
void hammer2_chain_ref_hold(hammer2_chain_t *);
void hammer2_chain_drop(hammer2_chain_t *);
void hammer2_chain_unhold(hammer2_chain_t *);
void hammer2_chain_drop_unhold(hammer2_chain_t *);
void hammer2_chain_rehold(hammer2_chain_t *);
int hammer2_chain_lock(hammer2_chain_t *, int);
void hammer2_chain_unlock(hammer2_chain_t *);
int hammer2_chain_resize(hammer2_chain_t *, hammer2_tid_t, hammer2_off_t, int,
    int);
int hammer2_chain_modify(hammer2_chain_t *, hammer2_tid_t, hammer2_off_t, int);
int hammer2_chain_modify_ip(hammer2_inode_t *, hammer2_chain_t *, hammer2_tid_t,
    int);
hammer2_chain_t *hammer2_chain_lookup_init(hammer2_chain_t *, int);
void hammer2_chain_lookup_done(hammer2_chain_t *);
hammer2_chain_t *hammer2_chain_getparent(hammer2_chain_t *, int);
hammer2_chain_t *hammer2_chain_lookup(hammer2_chain_t **, hammer2_key_t *,
    hammer2_key_t, hammer2_key_t, int *, int);
hammer2_chain_t *hammer2_chain_next(hammer2_chain_t **, hammer2_chain_t *,
    hammer2_key_t *, hammer2_key_t, int *, int);
int hammer2_chain_scan(hammer2_chain_t *, hammer2_chain_t **,
    hammer2_blockref_t *, int *, int);
int hammer2_chain_create(hammer2_chain_t **, hammer2_chain_t **,
    hammer2_dev_t *, hammer2_pfs_t *, int, hammer2_key_t, int, int, size_t,
    hammer2_tid_t, hammer2_off_t, int);
int hammer2_chain_indirect_maintenance(hammer2_chain_t *, hammer2_chain_t *);
int hammer2_chain_delete(hammer2_chain_t *, hammer2_chain_t *, hammer2_tid_t,
    int);
void hammer2_base_delete(hammer2_chain_t *, hammer2_blockref_t *, int,
    hammer2_chain_t *, hammer2_blockref_t *);
void hammer2_base_insert(hammer2_chain_t *, hammer2_blockref_t *, int,
    hammer2_chain_t *, hammer2_blockref_t *);
void hammer2_chain_setcheck(hammer2_chain_t *, void *);
int hammer2_chain_inode_find(hammer2_pfs_t *, hammer2_key_t, int, int,
    hammer2_chain_t **, hammer2_chain_t **);
hammer2_chain_t *hammer2_chain_bulksnap(hammer2_dev_t *);
void hammer2_chain_bulkdrop(hammer2_chain_t *);
int hammer2_chain_dirent_test(const hammer2_chain_t *, const char *, size_t);
void hammer2_dump_chain(hammer2_chain_t *, int, int, int, char);

RB_PROTOTYPE(hammer2_chain_tree, hammer2_chain, rbnode, hammer2_chain_cmp);
RB_PROTOTYPE_SCAN(hammer2_chain_tree, hammer2_chain, rbnode);

/* hammer2_cluster.c */
uint8_t hammer2_cluster_type(const hammer2_cluster_t *);
void hammer2_cluster_bref(const hammer2_cluster_t *, hammer2_blockref_t *);
void hammer2_dummy_xop_from_chain(hammer2_xop_head_t *, hammer2_chain_t *);
void hammer2_cluster_unhold(hammer2_cluster_t *);
void hammer2_cluster_rehold(hammer2_cluster_t *);
int hammer2_cluster_check(hammer2_cluster_t *, hammer2_key_t, int);

/* hammer2_flush.c */
void hammer2_trans_manage_init(hammer2_pfs_t *);
void hammer2_trans_init(hammer2_pfs_t *, uint32_t);
void hammer2_trans_setflags(hammer2_pfs_t *, uint32_t);
void hammer2_trans_clearflags(hammer2_pfs_t *, uint32_t);
hammer2_tid_t hammer2_trans_sub(hammer2_pfs_t *);
void hammer2_trans_done(hammer2_pfs_t *, uint32_t);
hammer2_tid_t hammer2_trans_newinum(hammer2_pfs_t *);
void hammer2_trans_assert_strategy(hammer2_pfs_t *);
int hammer2_flush(hammer2_chain_t *, int);
void hammer2_xop_inode_flush(hammer2_xop_t *, void *, int);

/* hammer2_freemap.c */
int hammer2_freemap_alloc(hammer2_chain_t *, size_t);
void hammer2_freemap_adjust(hammer2_dev_t *, hammer2_blockref_t *, int);

/* hammer2_inode.c */
void hammer2_inum_hash_init(hammer2_pfs_t *);
void hammer2_inum_hash_destroy(hammer2_pfs_t *);
void hammer2_inode_delayed_sideq(hammer2_inode_t *);
void hammer2_inode_lock(hammer2_inode_t *, int);
void hammer2_inode_lock4(hammer2_inode_t *, hammer2_inode_t *,
    hammer2_inode_t *, hammer2_inode_t *);
void hammer2_inode_unlock(hammer2_inode_t *);
void hammer2_inode_depend(hammer2_inode_t *, hammer2_inode_t *);
hammer2_chain_t *hammer2_inode_chain(hammer2_inode_t *, int, int);
hammer2_chain_t *hammer2_inode_chain_and_parent(hammer2_inode_t *, int,
    hammer2_chain_t **, int);
hammer2_inode_t *hammer2_inode_lookup(hammer2_pfs_t *, hammer2_tid_t);
void hammer2_inode_ref(hammer2_inode_t *);
void hammer2_inode_drop(hammer2_inode_t *);
int hammer2_igetv(hammer2_inode_t *, struct vnode **);
hammer2_inode_t *hammer2_inode_get(hammer2_pfs_t *, hammer2_xop_head_t *,
    hammer2_tid_t, int);
hammer2_inode_t *hammer2_inode_create_pfs(hammer2_pfs_t *, const char *,
    size_t, int *);
hammer2_inode_t *hammer2_inode_create_normal(hammer2_inode_t *, struct vattr *,
    struct ucred *, hammer2_key_t, int *);
int hammer2_dirent_create(hammer2_inode_t *, const char *, size_t,
    hammer2_key_t, uint8_t);
hammer2_key_t hammer2_inode_data_count(const hammer2_inode_t *);
hammer2_key_t hammer2_inode_inode_count(const hammer2_inode_t *);
int hammer2_inode_unlink_finisher(hammer2_inode_t *, struct vnode **);
void hammer2_inode_modify(hammer2_inode_t *);
void hammer2_inode_vhold(hammer2_inode_t *);
void hammer2_inode_vdrop(hammer2_inode_t *, int);
int hammer2_inode_chain_sync(hammer2_inode_t *);
int hammer2_inode_chain_ins(hammer2_inode_t *);
int hammer2_inode_chain_des(hammer2_inode_t *);
int hammer2_inode_chain_flush(hammer2_inode_t *, int);

/* hammer2_io.c */
void hammer2_io_hash_init(hammer2_dev_t *);
void hammer2_io_hash_destroy(hammer2_dev_t *);
hammer2_io_t *hammer2_io_getblk(hammer2_dev_t *, int, hammer2_off_t, int, int);
void hammer2_io_putblk(hammer2_io_t **);
void hammer2_io_hash_cleanup_all(hammer2_dev_t *);
char *hammer2_io_data(hammer2_io_t *, hammer2_off_t);
int hammer2_io_new(hammer2_dev_t *, int, hammer2_off_t, int, hammer2_io_t **);
int hammer2_io_newnz(hammer2_dev_t *, int, hammer2_off_t, int, hammer2_io_t **);
int hammer2_io_bread(hammer2_dev_t *, int, hammer2_off_t, int, hammer2_io_t **);
hammer2_io_t *hammer2_io_getquick(hammer2_dev_t *, off_t, int);
void hammer2_io_bawrite(hammer2_io_t **);
void hammer2_io_bdwrite(hammer2_io_t **);
int hammer2_io_bwrite(hammer2_io_t **);
void hammer2_io_setdirty(hammer2_io_t *);
void hammer2_io_brelse(hammer2_io_t **);
void hammer2_io_bqrelse(hammer2_io_t **);
uint64_t hammer2_dedup_mask(hammer2_io_t *, hammer2_off_t, u_int);
void hammer2_io_dedup_set(hammer2_dev_t *, hammer2_blockref_t *);
void hammer2_io_dedup_delete(hammer2_dev_t *, uint8_t, hammer2_off_t,
    unsigned int);
void hammer2_io_dedup_assert(hammer2_dev_t *, hammer2_off_t, unsigned int);

/* hammer2_ioctl.c */
int hammer2_ioctl_impl(struct vnode *, unsigned long, void *, int,
    struct ucred *);

/* hammer2_ondisk.c */
int hammer2_open_devvp(struct mount *, const hammer2_devvp_list_t *,
    struct proc *);
int hammer2_close_devvp(const hammer2_devvp_list_t *, struct proc *);
int hammer2_init_devvp(struct mount *, const char *,
    hammer2_devvp_list_t *, struct nameidata *, struct proc *);
void hammer2_cleanup_devvp(hammer2_devvp_list_t *);
int hammer2_init_volumes(const hammer2_devvp_list_t *, hammer2_volume_t *,
    hammer2_volume_data_t *, int *, struct vnode **);
hammer2_volume_t *hammer2_get_volume(hammer2_dev_t *, hammer2_off_t);

/* hammer2_strategy.c */
int hammer2_strategy(void *v);
void hammer2_xop_strategy_read(hammer2_xop_t *, void *, int);
void hammer2_xop_strategy_write(hammer2_xop_t *, void *, int);
void hammer2_bioq_sync(hammer2_pfs_t *);
void hammer2_dedup_clear(hammer2_dev_t *);

/* hammer2_subr.c */
int hammer2_get_dtype(uint8_t);
int hammer2_get_vtype(uint8_t);
uint8_t hammer2_get_obj_type(uint8_t);
void hammer2_time_to_timespec(uint64_t, struct timespec *);
uint64_t hammer2_timespec_to_time(const struct timespec *);
uint32_t hammer2_to_unix_xid(const struct uuid *);
void hammer2_guid_to_uuid(struct uuid *, uint32_t);
hammer2_key_t hammer2_dirhash(const char *, size_t);
int hammer2_getradix(size_t);
int hammer2_calc_logical(hammer2_inode_t *, hammer2_off_t, hammer2_key_t *,
    hammer2_key_t *);
int hammer2_get_logical(void);
int hammer2_calc_physical(hammer2_inode_t *, hammer2_key_t);
void hammer2_update_time(uint64_t *);
void hammer2_inc_iostat(hammer2_iostat_t *, int, size_t);
void hammer2_print_iostat(const hammer2_iostat_t *, const char *);
int hammer2_signal_check(void);
const char *hammer2_breftype_to_str(uint8_t);

/* hammer2_vfsops.c */
hammer2_pfs_t *hammer2_pfsalloc(hammer2_chain_t *, const hammer2_inode_data_t *,
    hammer2_dev_t *);
void hammer2_pfsdealloc(hammer2_pfs_t *, int, int);
int hammer2_sync(struct mount *, int, int, struct ucred *, struct proc *);
int hammer2_vfs_sync_pmp(hammer2_pfs_t *, int);
void hammer2_voldata_lock(hammer2_dev_t *);
void hammer2_voldata_unlock(hammer2_dev_t *);
void hammer2_voldata_modify(hammer2_dev_t *);
int hammer2_vfs_enospace(hammer2_inode_t *, off_t, struct ucred *);

/* hammer2_vnops.c */
int hammer2_vinit(struct mount *, struct vnode **);

/* hammer2_xops.c */
void hammer2_xop_ipcluster(hammer2_xop_t *, void *, int);
void hammer2_xop_readdir(hammer2_xop_t *, void *, int);
void hammer2_xop_nresolve(hammer2_xop_t *, void *, int);
void hammer2_xop_unlink(hammer2_xop_t *, void *, int);
void hammer2_xop_nrename(hammer2_xop_t *, void *, int);
void hammer2_xop_scanlhc(hammer2_xop_t *, void *, int);
void hammer2_xop_scanall(hammer2_xop_t *, void *, int);
void hammer2_xop_lookup(hammer2_xop_t *, void *, int);
void hammer2_xop_delete(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_mkdirent(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_create(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_create_det(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_create_ins(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_destroy(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_chain_sync(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_unlinkall(hammer2_xop_t *, void *, int);
void hammer2_xop_inode_connect(hammer2_xop_t *, void *, int);
void hammer2_xop_bmap(hammer2_xop_t *, void *, int);

/* XXX no way to return multiple errnos */
static __inline int
hammer2_error_to_errno(int error)
{
	if (!error)
		return (0);
	else if (error & HAMMER2_ERROR_EIO)
		return (EIO);
	else if (error & HAMMER2_ERROR_CHECK)
		return (EDOM);
	else if (error & HAMMER2_ERROR_BADBREF)
		return (EIO); /* no EBADBREF */
	else if (error & HAMMER2_ERROR_ENOSPC)
		return (ENOSPC);
	else if (error & HAMMER2_ERROR_ENOENT)
		return (ENOENT);
	else if (error & HAMMER2_ERROR_ENOTEMPTY)
		return (ENOTEMPTY);
	else if (error & HAMMER2_ERROR_EAGAIN)
		return (EAGAIN);
	else if (error & HAMMER2_ERROR_ENOTDIR)
		return (ENOTDIR);
	else if (error & HAMMER2_ERROR_EISDIR)
		return (EISDIR);
	else if (error & HAMMER2_ERROR_ABORTED)
		return (EINTR);
	//else if (error & HAMMER2_ERROR_EOF)
	//	return (xxx);
	else if (error & HAMMER2_ERROR_EINVAL)
		return (EINVAL);
	else if (error & HAMMER2_ERROR_EEXIST)
		return (EEXIST);
	else if (error & HAMMER2_ERROR_EOPNOTSUPP)
		return (EOPNOTSUPP);
	else
		return (EDOM);
}

static __inline int
hammer2_errno_to_error(int error)
{
	switch (error) {
	case 0:
		return (0);
	case EIO:
		return (HAMMER2_ERROR_EIO);
	case EDOM:
		return (HAMMER2_ERROR_CHECK);
	//case EIO:
	//	return (HAMMER2_ERROR_BADBREF);
	case ENOSPC:
		return (HAMMER2_ERROR_ENOSPC);
	case ENOENT:
		return (HAMMER2_ERROR_ENOENT);
	case ENOTEMPTY:
		return (HAMMER2_ERROR_ENOTEMPTY);
	case EAGAIN:
		return (HAMMER2_ERROR_EAGAIN);
	case ENOTDIR:
		return (HAMMER2_ERROR_ENOTDIR);
	case EISDIR:
		return (HAMMER2_ERROR_EISDIR);
	case EINTR:
		return (HAMMER2_ERROR_ABORTED);
	//case xxx:
	//	return (HAMMER2_ERROR_EOF);
	case EINVAL:
		return (HAMMER2_ERROR_EINVAL);
	case EEXIST:
		return (HAMMER2_ERROR_EEXIST);
	case EOPNOTSUPP:
		return (HAMMER2_ERROR_EOPNOTSUPP);
	default:
		return (HAMMER2_ERROR_EINVAL);
	}
}

static __inline const hammer2_media_data_t *
hammer2_xop_gdata(hammer2_xop_head_t *xop)
{
	hammer2_chain_t *focus = xop->cluster.focus;
	const void *data;

	if (focus->dio) {
		hammer2_mtx_sh(&focus->diolk);
		if ((xop->focus_dio = focus->dio) != NULL)
			atomic_add_32(&xop->focus_dio->refs, 1);
		data = focus->data;
		hammer2_mtx_unlock(&focus->diolk);
	} else {
		data = focus->data;
	}

	return (data);
}

static __inline void
hammer2_xop_pdata(hammer2_xop_head_t *xop)
{
	if (xop->focus_dio)
		hammer2_io_putblk(&xop->focus_dio);
}

static __inline void
hammer2_assert_cluster(const hammer2_cluster_t *cluster)
{
	/* Currently a valid cluster can only have 1 nchains. */
	KASSERTMSG(cluster->nchains == 1,
	    "unexpected cluster nchains %d", cluster->nchains);
}

static __inline void
hammer2_assert_inode_meta(const hammer2_inode_t *ip)
{
	KASSERTMSG(ip, "NULL ip");
	KASSERTMSG(ip->meta.mode, "mode 0");
	KASSERTMSG(ip->meta.type, "type 0");
}

uint32_t iscsi_crc32(const void *, size_t);
uint32_t iscsi_crc32_ext(const void *, size_t, uint32_t);

#define hammer2_icrc32(buf, size)	iscsi_crc32((buf), (size))
#define hammer2_icrc32c(buf, size, crc)	iscsi_crc32_ext((buf), (size), (crc))

#endif /* !_FS_HAMMER2_HAMMER2_H_ */

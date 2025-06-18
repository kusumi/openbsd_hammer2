/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2023 The DragonFly Project.  All rights reserved.
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

#include "hammer2.h"
#include "hammer2_mount.h"

#include <sys/sysctl.h>
#include <sys/specdev.h>

static int hammer2_unmount(struct mount *, int, struct proc *);
static int hammer2_recovery(hammer2_dev_t *);
static int hammer2_fixup_pfses(hammer2_dev_t *);
static int hammer2_remount_impl(hammer2_dev_t *);
static int hammer2_remount(hammer2_dev_t *, struct mount *);
static int hammer2_statfs(struct mount *, struct statfs *, struct proc *);
static void hammer2_update_pmps(hammer2_dev_t *);
static void hammer2_mount_helper(struct mount *, hammer2_pfs_t *);
static void hammer2_unmount_helper(struct mount *, hammer2_pfs_t *,
    hammer2_dev_t *);

struct pool hammer2_pool_inode;
struct pool hammer2_pool_xops;

/* global list of HAMMER2 */
TAILQ_HEAD(hammer2_mntlist, hammer2_dev); /* <-> hammer2_dev::mntentry */
typedef struct hammer2_mntlist hammer2_mntlist_t;
static hammer2_mntlist_t hammer2_mntlist;

/* global list of PFS */
hammer2_pfslist_t hammer2_pfslist;
static hammer2_pfslist_t hammer2_spmplist;

hammer2_lk_t hammer2_mntlk;

/* sysctl */
static int hammer2_supported_version = HAMMER2_VOL_VERSION_DEFAULT;
int hammer2_dedup_enable = 1;
int hammer2_count_inode_allocated;
int hammer2_count_chain_allocated;
int hammer2_count_chain_modified;
int hammer2_count_dio_allocated;
int hammer2_dio_limit = 256;
int hammer2_bulkfree_tps = 5000;
int hammer2_limit_scan_depth;
int hammer2_limit_saved_chains;
int hammer2_always_compress;

/* not sysctl */
int malloc_leak_m_hammer2;
int malloc_leak_m_hammer2_rbuf;
int malloc_leak_m_hammer2_wbuf;
int malloc_leak_m_hammer2_lz4;
int malloc_leak_m_temp;

static const struct sysctl_bounded_args hammer2_vars[] = {
	{ HAMMER2CTL_SUPPORTED_VERSION, &hammer2_supported_version, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_DEDUP_ENABLE, &hammer2_dedup_enable, 0, INT_MAX, },
	{ HAMMER2CTL_INODE_ALLOCATED, &hammer2_count_inode_allocated, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_CHAIN_ALLOCATED, &hammer2_count_chain_allocated, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_CHAIN_MODIFIED, &hammer2_count_chain_modified, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_DIO_ALLOCATED, &hammer2_count_dio_allocated, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_DIO_LIMIT, &hammer2_dio_limit, 0, INT_MAX, },
	{ HAMMER2CTL_BULKFREE_TPS, &hammer2_bulkfree_tps, 0, INT_MAX, },
	{ HAMMER2CTL_LIMIT_SCAN_DEPTH, &hammer2_limit_scan_depth, 0, INT_MAX, },
	{ HAMMER2CTL_LIMIT_SAVED_CHAINS, &hammer2_limit_saved_chains, 0, INT_MAX, },
	{ HAMMER2CTL_ALWAYS_COMPRESS, &hammer2_always_compress, 0, INT_MAX, },
};

static unsigned long
buf_nbuf(void)
{
	return ((bufhighpages * PAGE_SIZE) / 1024 / 3);
}

static int
hammer2_assert_clean(void)
{
	int error = 0;

	if (hammer2_count_inode_allocated > 0) {
		hprintf("%d inode left\n", hammer2_count_inode_allocated);
		error = EINVAL;
	}
	KKASSERT(hammer2_count_inode_allocated == 0);

	if (hammer2_count_chain_allocated > 0) {
		hprintf("%d chain left\n", hammer2_count_chain_allocated);
		error = EINVAL;
	}
	KKASSERT(hammer2_count_chain_allocated == 0);

	if (hammer2_count_chain_modified > 0) {
		hprintf("%d modified chain left\n",
		    hammer2_count_chain_modified);
		error = EINVAL;
	}
	KKASSERT(hammer2_count_chain_modified == 0);

	if (hammer2_count_dio_allocated > 0) {
		hprintf("%d dio left\n", hammer2_count_dio_allocated);
		error = EINVAL;
	}
	KKASSERT(hammer2_count_dio_allocated == 0);

	return (error);
}

static int
hammer2_start(struct mount *mp, int flags, struct proc *p)
{
	return (0);
}

static int
hammer2_init(struct vfsconf *vfsp)
{
	long hammer2_limit_dirty_chains; /* originally sysctl */

	KASSERT(sizeof(struct hammer2_mount_info) == sizeof(struct hammer2_args));
	KASSERT(sizeof(struct hammer2_mount_info) <= 160); /* union mount_info */

	hammer2_assert_clean();

	hammer2_dio_limit = buf_nbuf() * 2;
	if (hammer2_dio_limit > 100000 || hammer2_dio_limit < 0)
		hammer2_dio_limit = 100000;

	/*
	 * Note that buffers for strategy read/write use malloc(9) as
	 * subsequent pool_get() gets blocked and never returns.
	 */
	pool_init(&hammer2_pool_inode, sizeof(hammer2_inode_t), 0,
	    IPL_NONE, PR_WAITOK, "h2inopool", NULL);

	pool_init(&hammer2_pool_xops, sizeof(hammer2_xop_t), 0,
	    IPL_NONE, PR_WAITOK, "h2xopspool", NULL);

	hammer2_lk_init(&hammer2_mntlk, "h2mntlk");

	TAILQ_INIT(&hammer2_mntlist);
	TAILQ_INIT(&hammer2_pfslist);
	TAILQ_INIT(&hammer2_spmplist);

#define desiredvnodes	maxvnodes
	hammer2_limit_dirty_chains = desiredvnodes / 10;
	if (hammer2_limit_dirty_chains > HAMMER2_LIMIT_DIRTY_CHAINS)
		hammer2_limit_dirty_chains = HAMMER2_LIMIT_DIRTY_CHAINS;
	if (hammer2_limit_dirty_chains < 1000)
		hammer2_limit_dirty_chains = 1000;
	hammer2_limit_saved_chains = hammer2_limit_dirty_chains * 5;

	return (0);
}

/*
 * Core PFS allocator.  Used to allocate or reference the pmp structure
 * for PFS cluster mounts and the spmp structure for media (hmp) structures.
 */
hammer2_pfs_t *
hammer2_pfsalloc(hammer2_chain_t *chain, const hammer2_inode_data_t *ripdata,
    hammer2_dev_t *force_local)
{
	hammer2_pfs_t *pmp = NULL;
	hammer2_inode_t *iroot;
	int i, j;

	/*
	 * Locate or create the PFS based on the cluster id.  If ripdata
	 * is NULL this is a spmp which is unique and is always allocated.
	 *
	 * If the device is mounted in local mode all PFSs are considered
	 * independent and not part of any cluster.
	 */
	if (ripdata) {
		TAILQ_FOREACH(pmp, &hammer2_pfslist, mntentry) {
			if (force_local != pmp->force_local)
				continue;
			if (force_local == NULL &&
			    bcmp(&pmp->pfs_clid, &ripdata->meta.pfs_clid,
			    sizeof(pmp->pfs_clid)) == 0)
				break;
			else if (force_local && pmp->pfs_names[0] &&
			    strcmp(pmp->pfs_names[0],
			    (const char *)ripdata->filename) == 0)
				break;
		}
	}

	if (pmp == NULL) {
		pmp = hmalloc(sizeof(*pmp), M_HAMMER2, M_WAITOK | M_ZERO);
		pmp->force_local = force_local;
		hammer2_trans_manage_init(pmp);
		hammer2_spin_init(&pmp->blockset_spin, "h2pmp_bssp");
		hammer2_spin_init(&pmp->list_spin, "h2pmp_lssp");
		for (i = 0; i < HAMMER2_IHASH_SIZE; i++) {
			hammer2_lk_init(&pmp->xop_lock[i], "h2pmp_xoplk");
			hammer2_lkc_init(&pmp->xop_cv[i], "h2pmp_xoplkc");
		}
		hammer2_lk_init(&pmp->trans_lock, "h2pmp_trlk");
		hammer2_lkc_init(&pmp->trans_cv, "h2pmp_trlkc");
		TAILQ_INIT(&pmp->syncq);
		TAILQ_INIT(&pmp->depq);
		hammer2_inum_hash_init(pmp);

		KKASSERT((HAMMER2_IHASH_SIZE & (HAMMER2_IHASH_SIZE - 1)) == 0);
		pmp->ipdep_lists = hashinit(HAMMER2_IHASH_SIZE, M_HAMMER2,
		    M_WAITOK, &pmp->ipdep_mask);
		KKASSERT(HAMMER2_IHASH_SIZE == pmp->ipdep_mask + 1);

		if (ripdata) {
			pmp->pfs_clid = ripdata->meta.pfs_clid;
			TAILQ_INSERT_TAIL(&hammer2_pfslist, pmp, mntentry);
		} else {
			pmp->flags |= HAMMER2_PMPF_SPMP;
			TAILQ_INSERT_TAIL(&hammer2_spmplist, pmp, mntentry);
		}
	}

	/* Create the PFS's root inode. */
	if ((iroot = pmp->iroot) == NULL) {
		iroot = hammer2_inode_get(pmp, NULL, 1, -1);
		if (ripdata)
			iroot->meta = ripdata->meta;
		pmp->iroot = iroot;
		hammer2_inode_ref(iroot);
		hammer2_inode_unlock(iroot);
	}

	/* Stop here if no chain is passed in. */
	if (chain == NULL)
		goto done;

	/*
	 * When a chain is passed in we must add it to the PFS's root
	 * inode, update pmp->pfs_types[].
	 *
	 * When forcing local mode, mark the PFS as a MASTER regardless.
	 *
	 * At the moment empty spots can develop due to removals or failures.
	 * Ultimately we want to re-fill these spots but doing so might
	 * confused running code. XXX
	 */
	hammer2_inode_ref(iroot);
	hammer2_mtx_ex(&iroot->lock);
	j = iroot->cluster.nchains;

	if (j == HAMMER2_MAXCLUSTER) {
		hprintf("cluster full\n");
		/* XXX fatal error? */
	} else {
		KKASSERT(chain->pmp == NULL);
		chain->pmp = pmp;
		hammer2_chain_ref(chain);
		iroot->cluster.array[j].chain = chain;
		if (force_local)
			pmp->pfs_types[j] = HAMMER2_PFSTYPE_MASTER;
		else
			pmp->pfs_types[j] = ripdata->meta.pfs_type;
		pmp->pfs_names[j] = hstrdup((const char *)ripdata->filename);
		pmp->pfs_hmps[j] = chain->hmp;
		hammer2_spin_ex(&pmp->blockset_spin);
		pmp->pfs_iroot_blocksets[j] = chain->data->ipdata.u.blockset;
		hammer2_spin_unex(&pmp->blockset_spin);

		/*
		 * If the PFS is already mounted we must account
		 * for the mount_count here.
		 */
		if (pmp->mp)
			++chain->hmp->mount_count;
		++j;
	}
	iroot->cluster.nchains = j;
	hammer2_assert_cluster(&iroot->cluster);

	hammer2_mtx_unlock(&iroot->lock);
	hammer2_inode_drop(iroot);
done:
	return (pmp);
}

/*
 * Deallocate an element of a probed PFS.
 *
 * This function does not physically destroy the PFS element in its device
 * under the super-root  (see hammer2_ioctl_pfs_delete()).
 */
void
hammer2_pfsdealloc(hammer2_pfs_t *pmp, int clindex, int destroying __unused)
{
	hammer2_inode_t *iroot;
	hammer2_chain_t *chain;

	/*
	 * Cleanup our reference on iroot.  iroot is (should) not be needed
	 * by the flush code.
	 */
	iroot = pmp->iroot;
	if (iroot) {
		/* Remove the cluster index from the group. */
		hammer2_mtx_ex(&iroot->lock);
		chain = iroot->cluster.array[clindex].chain;
		iroot->cluster.array[clindex].chain = NULL;
		pmp->pfs_types[clindex] = HAMMER2_PFSTYPE_NONE;
		hammer2_mtx_unlock(&iroot->lock);

		/* Release the chain. */
		if (chain) {
			atomic_set_int(&chain->flags, HAMMER2_CHAIN_RELEASE);
			hammer2_chain_drop(chain);
		}
	}
}

/*
 * Destroy a PFS, typically only occurs after the last mount on a device
 * has gone away.
 */
static void
hammer2_pfsfree(hammer2_pfs_t *pmp)
{
	hammer2_inode_t *iroot;
	hammer2_chain_t *chain;
	int i, chains_still_present = 0;

	KKASSERT(!(pmp->flags & HAMMER2_PMPF_WAITING));

	/* Cleanup our reference on iroot. */
	if (pmp->flags & HAMMER2_PMPF_SPMP)
		TAILQ_REMOVE(&hammer2_spmplist, pmp, mntentry);
	else
		TAILQ_REMOVE(&hammer2_pfslist, pmp, mntentry);

	/* Clean up iroot. */
	iroot = pmp->iroot;
	if (iroot) {
		for (i = 0; i < iroot->cluster.nchains; ++i) {
			chain = iroot->cluster.array[i].chain;
			if (chain && !RB_EMPTY(&chain->core.rbtree))
				chains_still_present = 1;
		}
		KASSERTMSG(iroot->refs == 1,
		    "iroot inum %016llx refs %d not 1",
		    (long long)iroot->meta.inum, iroot->refs);
		hammer2_inode_drop(iroot);
		pmp->iroot = NULL;
	}

	/* Free remaining pmp resources. */
	if (chains_still_present) {
		KKASSERT(pmp->mp);
		hprintf("PFS still in use\n");
	} else {
		hammer2_spin_destroy(&pmp->blockset_spin);
		hammer2_spin_destroy(&pmp->list_spin);
		for (i = 0; i < HAMMER2_IHASH_SIZE; i++) {
			hammer2_lk_destroy(&pmp->xop_lock[i]);
			hammer2_lkc_destroy(&pmp->xop_cv[i]);
		}
		hammer2_lk_destroy(&pmp->trans_lock);
		hammer2_lkc_destroy(&pmp->trans_cv);
		hammer2_inum_hash_destroy(pmp);
		hashfree(pmp->ipdep_lists, HAMMER2_IHASH_SIZE, M_HAMMER2);
		if (pmp->fspec)
			hfree(pmp->fspec, M_HAMMER2, strlen(pmp->fspec) + 1);
		hfree(pmp, M_HAMMER2, sizeof(*pmp));
	}
}

/*
 * Remove all references to hmp from the pfs list.  Any PFS which becomes
 * empty is terminated and freed.
 */
static void
hammer2_pfsfree_scan(hammer2_dev_t *hmp, int which)
{
	hammer2_pfs_t *pmp;
	hammer2_inode_t *iroot;
	hammer2_chain_t *rchain;
	struct hammer2_pfslist *wlist;
	int i;

	if (which == 0)
		wlist = &hammer2_pfslist;
	else
		wlist = &hammer2_spmplist;
again:
	TAILQ_FOREACH(pmp, wlist, mntentry) {
		if ((iroot = pmp->iroot) == NULL)
			continue;

		/* Determine if this PFS is affected. */
		for (i = 0; i < HAMMER2_MAXCLUSTER; ++i)
			if (pmp->pfs_hmps[i] == hmp)
				break;
		if (i == HAMMER2_MAXCLUSTER)
			continue;

		hammer2_vfs_sync_pmp(pmp, MNT_WAIT);

		/*
		 * Lock the inode and clean out matching chains.
		 * Note that we cannot use hammer2_inode_lock_*()
		 * here because that would attempt to validate the
		 * cluster that we are in the middle of ripping
		 * apart.
		 */
		hammer2_mtx_ex(&iroot->lock);

		/* Remove the chain from matching elements of the PFS. */
		for (i = 0; i < HAMMER2_MAXCLUSTER; ++i) {
			if (pmp->pfs_hmps[i] != hmp)
				continue;
			rchain = iroot->cluster.array[i].chain;
			iroot->cluster.array[i].chain = NULL;
			pmp->pfs_types[i] = HAMMER2_PFSTYPE_NONE;
			if (pmp->pfs_names[i]) {
				hstrfree(pmp->pfs_names[i]);
				pmp->pfs_names[i] = NULL;
			}
			if (rchain) {
				hammer2_chain_drop(rchain);
				/* focus hint */
				if (iroot->cluster.focus == rchain)
					iroot->cluster.focus = NULL;
			}
			pmp->pfs_hmps[i] = NULL;
		}
		hammer2_mtx_unlock(&iroot->lock);

		/* Cleanup trailing chains.  Gaps may remain. */
		for (i = HAMMER2_MAXCLUSTER - 1; i >= 0; --i)
			if (pmp->pfs_hmps[i])
				break;
		iroot->cluster.nchains = i + 1;

		/* If the PMP has no elements remaining we can destroy it. */
		if (iroot->cluster.nchains == 0) {
			/*
			 * If this was the hmp's spmp, we need to clean
			 * a little more stuff out.
			 */
			if (hmp->spmp == pmp) {
				hmp->spmp = NULL;
				hmp->vchain.pmp = NULL;
				hmp->fchain.pmp = NULL;
			}

			/* Free the pmp and restart the loop. */
			hammer2_pfsfree(pmp);
			goto again;
		}
	}
}

/*
 * Mount or remount HAMMER2 fileystem from physical media.
 */
static int
hammer2_mount(struct mount *mp, const char *path, void *data,
    struct nameidata *ndp, struct proc *p)
{
	dev_t dev;
	struct hammer2_mount_info *args = data;
	hammer2_dev_t *hmp = NULL, *hmp_tmp, *force_local;
	hammer2_pfs_t *pmp = NULL, *spmp;
	hammer2_key_t key_next, key_dummy, lhc;
	hammer2_chain_t *chain, *parent;
	const hammer2_inode_data_t *ripdata;
	hammer2_devvp_list_t devvpl;
	hammer2_devvp_t *e, *e_tmp;
	hammer2_chain_t *schain;
	hammer2_xop_head_t *xop;
	hammer2_cluster_t *cluster;
	char devstr[MNAMELEN] = {0};
	char fnamestr[MNAMELEN] = {0};
	char *label = NULL;
	int rdonly = (mp->mnt_flag & MNT_RDONLY) != 0;
	int i, error, devvp_found;
	size_t dlen;

	if (args == NULL) {
		hprintf("NULL args\n");
		return (EINVAL);
	}

	/* HMNT2_LOCAL is not allowed, it's already broken in DragonFly. */
	if (args->hflags & HMNT2_LOCAL) {
		hprintf("HMNT2_LOCAL is not allowed\n");
		return (EINVAL);
	}
	KKASSERT((args->hflags & HMNT2_LOCAL) == 0);

	if (mp->mnt_flag & MNT_UPDATE) {
		/*
		 * Update mount.  Note that pmp->iroot->cluster is
		 * an inode-embedded cluster and thus cannot be
		 * directly locked.
		 */
		error = 0;
		pmp = MPTOPMP(mp);
		cluster = &pmp->iroot->cluster;
		for (i = 0; i < cluster->nchains; ++i) {
			if (cluster->array[i].chain == NULL)
				continue;
			hmp = cluster->array[i].chain->hmp;
			error = hammer2_remount(hmp, mp);
			if (error)
				break;
		}
		if (error)
			return (error);

		if (args && args->fspec == NULL) {
			/* Process export requests. */
			return (vfs_export(mp, &pmp->pm_export,
			    &args->export_info));
		}
		return (0);
	}

	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible block device.
	 */
	error = copyinstr(args->fspec, devstr, sizeof(devstr), NULL);
	if (error) {
		hprintf("copyinstr failed %d\n", error);
		return (error);
	}
	/* Note that path is already in kernel space. */
	debug_hprintf("devstr \"%s\" mntpt \"%s\"\n", devstr, path);

	/*
	 * Extract device and label, automatically mount @DATA if no label
	 * specified.  Error out if no label or device is specified.  This is
	 * a convenience to match the default label created by newfs_hammer2,
	 * our preference is that a label always be specified.
	 *
	 * NOTE: We allow 'mount @LABEL <blah>'... that is, a mount command
	 *	 that does not specify a device, as long as some HAMMER2 label
	 *	 has already been mounted from that device.  This makes
	 *	 mounting snapshots a lot easier.
	 */
	label = strchr(devstr, '@');
	if (label == NULL || label[1] == 0) {
		/*
		 * DragonFly HAMMER2 uses either "BOOT", "ROOT" or "DATA"
		 * based on label[-1].
		 */
		label = __DECONST(char *, "DATA");
	} else {
		*label = '\0';
		label++;
	}

	debug_hprintf("device \"%s\" label \"%s\" rdonly %d\n",
	    devstr, label, rdonly);

	/* Initialize all device vnodes. */
	TAILQ_INIT(&devvpl);
	error = hammer2_init_devvp(mp, devstr, &devvpl, ndp, p);
	if (error) {
		hprintf("failed to initialize devvp in %s\n", devstr);
		hammer2_cleanup_devvp(&devvpl);
		return (error);
	}

	/*
	 * Determine if the device has already been mounted.  After this
	 * check hmp will be non-NULL if we are doing the second or more
	 * HAMMER2 mounts from the same device.
	 */
	hammer2_lk_ex(&hammer2_mntlk);
	if (!TAILQ_EMPTY(&devvpl)) {
		/*
		 * Match the device.  Due to the way devfs works,
		 * we may not be able to directly match the vnode pointer,
		 * so also check to see if the underlying device matches.
		 */
		TAILQ_FOREACH(hmp_tmp, &hammer2_mntlist, mntentry) {
			TAILQ_FOREACH(e_tmp, &hmp_tmp->devvp_list, entry) {
				devvp_found = 0;
				TAILQ_FOREACH(e, &devvpl, entry) {
					KKASSERT(e->devvp);
					if (e_tmp->devvp == e->devvp)
						devvp_found = 1;
					if (e_tmp->devvp->v_rdev &&
					    e_tmp->devvp->v_rdev == e->devvp->v_rdev)
						devvp_found = 1;
				}
				if (!devvp_found)
					goto next_hmp;
			}
			hmp = hmp_tmp;
			debug_hprintf("hmp matched\n");
			break;
next_hmp:
			continue;
		}
		/*
		 * If no match this may be a fresh H2 mount, make sure
		 * the device is not mounted on anything else.
		 */
		if (hmp == NULL) {
			TAILQ_FOREACH(e, &devvpl, entry) {
				KKASSERT(e->devvp);
				error = vfs_mountedon(e->devvp);
				if (error) {
					hprintf("%s mounted %d\n", e->path,
					    error);
					hammer2_cleanup_devvp(&devvpl);
					hammer2_lk_unlock(&hammer2_mntlk);
					return (error);
				}
			}
		}
	} else {
		/* Match the label to a pmp already probed. */
		TAILQ_FOREACH(pmp, &hammer2_pfslist, mntentry) {
			for (i = 0; i < HAMMER2_MAXCLUSTER; ++i) {
				if (pmp->pfs_names[i] &&
				    strcmp(pmp->pfs_names[i], label) == 0) {
					hmp = pmp->pfs_hmps[i];
					break;
				}
			}
			if (hmp)
				break;
		}
		if (hmp == NULL) {
			hprintf("PFS label \"%s\" not found\n", label);
			hammer2_cleanup_devvp(&devvpl);
			hammer2_lk_unlock(&hammer2_mntlk);
			return (ENOENT);
		}
	}

	/*
	 * Open the device if this isn't a secondary mount and construct the
	 * HAMMER2 device mount (hmp).
	 */
	if (hmp == NULL) {
		/* Now open the device(s). */
		KKASSERT(!TAILQ_EMPTY(&devvpl));
		error = hammer2_open_devvp(mp, &devvpl, p);
		if (error) {
			hammer2_close_devvp(&devvpl, p);
			hammer2_cleanup_devvp(&devvpl);
			hammer2_lk_unlock(&hammer2_mntlk);
			return (error);
		}

		/* Construct volumes and link with device vnodes. */
		hmp = hmalloc(sizeof(*hmp), M_HAMMER2, M_WAITOK | M_ZERO);
		hmp->devvp = NULL;
		error = hammer2_init_volumes(&devvpl, hmp->volumes,
		    &hmp->voldata, &hmp->volhdrno, &hmp->devvp);
		if (error) {
			hammer2_close_devvp(&devvpl, p);
			hammer2_cleanup_devvp(&devvpl);
			hammer2_lk_unlock(&hammer2_mntlk);
			hfree(hmp, M_HAMMER2, sizeof(*hmp));
			return (error);
		}
		if (!hmp->devvp) {
			hprintf("failed to initialize root volume\n");
			hammer2_unmount_helper(mp, NULL, hmp);
			hammer2_lk_unlock(&hammer2_mntlk);
			hammer2_unmount(mp, MNT_FORCE, curproc);
			return (EINVAL);
		}

		hmp->rdonly = rdonly;
		hmp->hflags = args->hflags & HMNT2_DEVFLAGS;

		TAILQ_INSERT_TAIL(&hammer2_mntlist, hmp, mntentry);
		hammer2_mtx_init(&hmp->iohash_lock, "h2hmp_iohlk");
		hammer2_io_hash_init(hmp);

		hammer2_lk_init(&hmp->vollk, "h2vol");
		hammer2_lk_init(&hmp->bulklk, "h2bulk");
		hammer2_lk_init(&hmp->bflk, "h2bflk");

		/*
		 * vchain setup.  vchain.data is embedded.
		 * vchain.refs is initialized and will never drop to 0.
		 */
		hmp->vchain.hmp = hmp;
		hmp->vchain.refs = 1;
		hmp->vchain.data = (void *)&hmp->voldata;
		hmp->vchain.bref.type = HAMMER2_BREF_TYPE_VOLUME;
		hmp->vchain.bref.data_off = 0 | HAMMER2_PBUFRADIX;
		hammer2_chain_init(&hmp->vchain);

		/*
		 * fchain setup.  fchain.data is embedded.
		 * fchain.refs is initialized and will never drop to 0.
		 *
		 * The data is not used but needs to be initialized to
		 * pass assertion muster.  We use this chain primarily
		 * as a placeholder for the freemap's top-level radix tree
		 * so it does not interfere with the volume's topology
		 * radix tree.
		 */
		hmp->fchain.hmp = hmp;
		hmp->fchain.refs = 1;
		hmp->fchain.data = (void *)&hmp->voldata.freemap_blockset;
		hmp->fchain.bref.type = HAMMER2_BREF_TYPE_FREEMAP;
		hmp->fchain.bref.data_off = 0 | HAMMER2_PBUFRADIX;
		hmp->fchain.bref.methods =
		    HAMMER2_ENC_CHECK(HAMMER2_CHECK_FREEMAP) |
		    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE);
		hammer2_chain_init(&hmp->fchain);

		/* Initialize volume header related fields. */
		KKASSERT(hmp->voldata.magic == HAMMER2_VOLUME_ID_HBO ||
		    hmp->voldata.magic == HAMMER2_VOLUME_ID_ABO);
		hmp->volsync = hmp->voldata;
		hmp->free_reserved = hmp->voldata.allocator_size / 20;

		/*
		 * Must use hmp instead of volume header for these two
		 * in order to handle volume versions transparently.
		 */
		if (hmp->voldata.version >= HAMMER2_VOL_VERSION_MULTI_VOLUMES) {
			hmp->nvolumes = hmp->voldata.nvolumes;
			hmp->total_size = hmp->voldata.total_size;
		} else {
			hmp->nvolumes = 1;
			hmp->total_size = hmp->voldata.volu_size;
		}
		KKASSERT(hmp->nvolumes > 0);

		/* Move devvpl entries to hmp. */
		TAILQ_INIT(&hmp->devvp_list);
		while ((e = TAILQ_FIRST(&devvpl)) != NULL) {
			TAILQ_REMOVE(&devvpl, e, entry);
			TAILQ_INSERT_TAIL(&hmp->devvp_list, e, entry);
		}
		KKASSERT(TAILQ_EMPTY(&devvpl));
		KKASSERT(!TAILQ_EMPTY(&hmp->devvp_list));

		/*
		 * Really important to get these right or teardown code
		 * will get confused.
		 */
		hmp->spmp = hammer2_pfsalloc(NULL, NULL, hmp);
		spmp = hmp->spmp;
		spmp->pfs_hmps[0] = hmp;

		/*
		 * Dummy-up vchain and fchain's modify_tid.
		 * mirror_tid is inherited from the volume header.
		 */
		hmp->vchain.bref.mirror_tid = hmp->voldata.mirror_tid;
		hmp->vchain.bref.modify_tid = hmp->vchain.bref.mirror_tid;
		hmp->vchain.pmp = spmp;
		hmp->fchain.bref.mirror_tid = hmp->voldata.freemap_tid;
		hmp->fchain.bref.modify_tid = hmp->fchain.bref.mirror_tid;
		hmp->fchain.pmp = spmp;

		/*
		 * First locate the super-root inode, which is key 0
		 * relative to the volume header's blockset.
		 *
		 * Then locate the root inode by scanning the directory keyspace
		 * represented by the label.
		 */
		parent = hammer2_chain_lookup_init(&hmp->vchain, 0);
		schain = hammer2_chain_lookup(&parent, &key_dummy,
		    HAMMER2_SROOT_KEY, HAMMER2_SROOT_KEY, &error, 0);
		hammer2_chain_lookup_done(parent);
		if (schain == NULL) {
			hprintf("invalid super-root\n");
			hammer2_unmount_helper(mp, NULL, hmp);
			hammer2_lk_unlock(&hammer2_mntlk);
			hammer2_unmount(mp, MNT_FORCE, curproc);
			return (EINVAL);
		}
		if (schain->error) {
			hprintf("chain error %08x reading super-root\n",
			    schain->error);
			hammer2_chain_unlock(schain);
			hammer2_chain_drop(schain);
			schain = NULL;
			hammer2_unmount_helper(mp, NULL, hmp);
			hammer2_lk_unlock(&hammer2_mntlk);
			hammer2_unmount(mp, MNT_FORCE, curproc);
			return (EINVAL);
		}

		/*
		 * The super-root always uses an inode_tid of 1 when
		 * creating PFSs.
		 */
		spmp->inode_tid = 1;
		spmp->modify_tid = schain->bref.modify_tid + 1;

		/*
		 * Sanity-check schain's pmp and finish initialization.
		 * Any chain belonging to the super-root topology should
		 * have a NULL pmp (not even set to spmp).
		 */
		ripdata = &schain->data->ipdata;
		KKASSERT(schain->pmp == NULL);
		spmp->pfs_clid = ripdata->meta.pfs_clid;

		/*
		 * Replace the dummy spmp->iroot with a real one.  It's
		 * easier to just do a wholesale replacement than to try
		 * to update the chain and fixup the iroot fields.
		 *
		 * The returned inode is locked with the supplied cluster.
		 */
		xop = pool_get(&hammer2_pool_xops, PR_WAITOK | PR_ZERO);
		hammer2_dummy_xop_from_chain(xop, schain);
		hammer2_inode_drop(spmp->iroot);
		spmp->iroot = hammer2_inode_get(spmp, xop, -1, -1);
		spmp->spmp_hmp = hmp;
		spmp->pfs_types[0] = ripdata->meta.pfs_type;
		spmp->rdonly = rdonly;
		hammer2_inode_ref(spmp->iroot);
		hammer2_inode_unlock(spmp->iroot);
		hammer2_chain_unlock(schain);
		hammer2_chain_drop(schain);
		schain = NULL;
		pool_put(&hammer2_pool_xops, xop);
		/* Leave spmp->iroot with one ref. */

		if (!hmp->rdonly) {
			error = hammer2_recovery(hmp);
			if (error == 0)
				error |= hammer2_fixup_pfses(hmp);
			/* XXX do something with error */
		}

		/*
		 * A false-positive lock order reversal may be detected.
		 * There are 2 directions of locking, which is a bad design.
		 * chain is locked -> hammer2_inode_get() -> lock inode
		 * inode is locked -> hammer2_inode_chain() -> lock chain
		 */
		hammer2_update_pmps(hmp);
		hammer2_bulkfree_init(hmp);
	} else {
		/* hmp->devvp_list is already constructed. */
		hammer2_cleanup_devvp(&devvpl);
		spmp = hmp->spmp;
		if (args->hflags & HMNT2_DEVFLAGS)
			hprintf("WARNING: mount flags pertaining to the whole "
			    "device may only be specified on the first mount "
			    "of the device: %08x\n",
			    args->hflags & HMNT2_DEVFLAGS);
	}

	/*
	 * Force local mount (disassociate all PFSs from their clusters).
	 * Used primarily for debugging.
	 */
	force_local = (hmp->hflags & HMNT2_LOCAL) ? hmp : NULL;

	/*
	 * Lookup the mount point under the media-localized super-root.
	 * Scanning hammer2_pfslist doesn't help us because it represents
	 * PFS cluster ids which can aggregate several named PFSs together.
	 */
	hammer2_inode_lock(spmp->iroot, 0);
	parent = hammer2_inode_chain(spmp->iroot, 0, HAMMER2_RESOLVE_ALWAYS);
	lhc = hammer2_dirhash(label, strlen(label));
	chain = hammer2_chain_lookup(&parent, &key_next, lhc,
	    lhc + HAMMER2_DIRHASH_LOMASK, &error, 0);
	while (chain) {
		if (chain->bref.type == HAMMER2_BREF_TYPE_INODE &&
		    strcmp(label, (char *)chain->data->ipdata.filename) == 0)
			break;
		chain = hammer2_chain_next(&parent, chain, &key_next,
		    lhc + HAMMER2_DIRHASH_LOMASK, &error, 0);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_inode_unlock(spmp->iroot);

	/* PFS could not be found? */
	if (chain == NULL) {
		hammer2_unmount_helper(mp, NULL, hmp);
		hammer2_lk_unlock(&hammer2_mntlk);
		hammer2_unmount(mp, MNT_FORCE, curproc);

		if (error) {
			hprintf("PFS label \"%s\" error %08x\n", label, error);
			return (EINVAL);
		} else {
			hprintf("PFS label \"%s\" not found\n", label);
			return (ENOENT);
		}
	}

	/* Acquire the pmp structure. */
	if (chain->error) {
		hprintf("PFS label \"%s\" chain error %08x\n",
		    label, chain->error);
	} else {
		ripdata = &chain->data->ipdata;
		pmp = hammer2_pfsalloc(NULL, ripdata, force_local);
	}
	hammer2_chain_unlock(chain);
	hammer2_chain_drop(chain);

	/* PFS to mount must exist at this point. */
	if (pmp == NULL) {
		hprintf("failed to acquire PFS structure\n");
		hammer2_unmount_helper(mp, NULL, hmp);
		hammer2_lk_unlock(&hammer2_mntlk);
		hammer2_unmount(mp, MNT_FORCE, curproc);
		return (EINVAL);
	}

	if (pmp->mp) {
		hprintf("PFS already mounted!\n");
		hammer2_unmount_helper(mp, NULL, hmp);
		hammer2_lk_unlock(&hammer2_mntlk);
		hammer2_unmount(mp, MNT_FORCE, curproc);
		return (EBUSY);
	}

	/*
	 * dev alone isn't unique to PFS, but pfs_clid isn't either against
	 * multiple mounts with the same image.
	 */
	KKASSERT(!TAILQ_EMPTY(&hmp->devvp_list));
	dev = TAILQ_FIRST(&hmp->devvp_list)->devvp->v_rdev;
	mp->mnt_stat.f_fsid.val[0] = ((long)dev) ^
	    ((long)pmp->pfs_clid.time_low);
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;

	mp->mnt_stat.f_namemax = HAMMER2_INODE_MAXNAME;
	mp->mnt_flag |= MNT_LOCAL;

	/* Required mount structure initializations. */
	mp->mnt_stat.f_iosize = HAMMER2_PBUFSIZE;
	mp->mnt_stat.f_bsize = HAMMER2_PBUFSIZE;

	/* Connect up mount pointers. */
	hammer2_mount_helper(mp, pmp);

	/* Update readonly hmp if !rdonly. */
	pmp->rdonly = rdonly;
	if (hmp->rdonly && !pmp->rdonly) {
		error = hammer2_remount_impl(hmp);
		if (error) {
			hprintf("failed to update to rw\n");
			hammer2_unmount_helper(mp, pmp, NULL);
			hammer2_lk_unlock(&hammer2_mntlk);
			hammer2_unmount(mp, MNT_FORCE, curproc);
			return (error);
		}
	}
	hammer2_lk_unlock(&hammer2_mntlk);

	/* Initial statfs to prime mnt_stat. */
	hammer2_statfs(mp, &mp->mnt_stat, p);

	/* Keep devstr string in PFS mount. */
	dlen = strlen(devstr) + strlen(label) + 1 + 1;
	pmp->fspec = hmalloc(dlen, M_HAMMER2, M_WAITOK | M_ZERO);
	snprintf(pmp->fspec, dlen, "%s@%s", devstr, label);

	/* Build f_mntfromspec buffer. */
	bzero(fnamestr, sizeof(fnamestr));
	for (i = 0; i < hmp->nvolumes; i++) {
		strlcat(fnamestr, hmp->volumes[i].dev->fname, sizeof(fnamestr));
		if (i != hmp->nvolumes - 1)
			strlcat(fnamestr, ":", sizeof(fnamestr));
	}
	strlcat(fnamestr, "@", sizeof(fnamestr));
	strlcat(fnamestr, label, sizeof(fnamestr));

	/* Set mnt_stat.f_xxx. */
	bzero(mp->mnt_stat.f_mntonname, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntonname, path, MNAMELEN);
	bzero(mp->mnt_stat.f_mntfromname, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntfromname, fnamestr, MNAMELEN);
	bzero(mp->mnt_stat.f_mntfromspec, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntfromspec, pmp->fspec, MNAMELEN);
	bcopy(args, &mp->mnt_stat.mount_info.hammer2_args, sizeof(*args));

	/* These two are usually the same. */
	if (strncmp(mp->mnt_stat.f_mntfromname, mp->mnt_stat.f_mntfromspec,
	    MNAMELEN))
		debug_hprintf("f_mntfromname=%s != f_mntfromspec=%s\n",
		    mp->mnt_stat.f_mntfromname, mp->mnt_stat.f_mntfromspec);

	return (0);
}

/*
 * Scan PFSs under the super-root and create hammer2_pfs structures.
 */
static void
hammer2_update_pmps(hammer2_dev_t *hmp)
{
	hammer2_dev_t *force_local;
	hammer2_pfs_t *spmp;
	const hammer2_inode_data_t *ripdata;
	hammer2_chain_t *parent;
	hammer2_chain_t *chain;
	hammer2_key_t key_next;
	int error;

	/*
	 * Force local mount (disassociate all PFSs from their clusters).
	 * Used primarily for debugging.
	 */
	force_local = (hmp->hflags & HMNT2_LOCAL) ? hmp : NULL;

	/* Lookup mount point under the media-localized super-root. */
	spmp = hmp->spmp;
	hammer2_inode_lock(spmp->iroot, 0);
	parent = hammer2_inode_chain(spmp->iroot, 0, HAMMER2_RESOLVE_ALWAYS);
	chain = hammer2_chain_lookup(&parent, &key_next, HAMMER2_KEY_MIN,
	    HAMMER2_KEY_MAX, &error, 0);
	while (chain) {
		if (chain->error) {
			hprintf("chain error %08x reading PFS root\n",
			    chain->error);
		} else if (chain->bref.type != HAMMER2_BREF_TYPE_INODE) {
			hprintf("non inode chain type %d under super-root\n",
			    chain->bref.type);
		} else {
			ripdata = &chain->data->ipdata;
			hammer2_pfsalloc(chain, ripdata, force_local);
		}
		chain = hammer2_chain_next(&parent, chain, &key_next,
		    HAMMER2_KEY_MAX, &error, 0);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_inode_unlock(spmp->iroot);
}

static int
hammer2_unmount(struct mount *mp, int mntflags, struct proc *p)
{
	hammer2_pfs_t *pmp = MPTOPMP(mp);
	int flags = 0, error = 0;

	/* Still NULL during mount before hammer2_mount_helper() called. */
	if (pmp == NULL)
		return (0);

	hammer2_lk_ex(&hammer2_mntlk);

	/*
	 * If mount initialization proceeded far enough we must flush
	 * its vnodes and sync the underlying mount points.  Three syncs
	 * are required to fully flush the filesystem (freemap updates lag
	 * by one flush, and one extra for safety).
	 */
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;
	if (pmp->iroot) {
		error = vflush(mp, NULLVP, flags);
		if (error) {
			hprintf("vflush failed %d\n", error);
			goto failed;
		}
		hammer2_sync(mp, MNT_WAIT, 0, NULL, NULL);
		hammer2_sync(mp, MNT_WAIT, 0, NULL, NULL);
		hammer2_sync(mp, MNT_WAIT, 0, NULL, NULL);
	} else {
		debug_hprintf("no root inode"); /* failed before allocation */
	}

	hammer2_unmount_helper(mp, pmp, NULL);
failed:
	hammer2_lk_unlock(&hammer2_mntlk);

	if (TAILQ_EMPTY(&hammer2_mntlist))
		hammer2_assert_clean();

	return (error);
}

/*
 * Mount helper, hook the system mount into our PFS.
 * The mount lock is held.
 *
 * We must bump the mount_count on related devices for any mounted PFSs.
 */
static void
hammer2_mount_helper(struct mount *mp, hammer2_pfs_t *pmp)
{
	hammer2_cluster_t *cluster;
	hammer2_chain_t *rchain;
	int i;

	mp->mnt_data = pmp;
	pmp->mp = mp;

	/* After pmp->mp is set adjust hmp->mount_count. */
	cluster = &pmp->iroot->cluster;
	for (i = 0; i < cluster->nchains; ++i) {
		rchain = cluster->array[i].chain;
		if (rchain == NULL)
			continue;
		++rchain->hmp->mount_count;
	}
}

/*
 * Unmount helper, unhook the system mount from our PFS.
 * The mount lock is held.
 *
 * If hmp is supplied a mount responsible for being the first to open
 * the block device failed and the block device and all PFSs using the
 * block device must be cleaned up.
 *
 * If pmp is supplied multiple devices might be backing the PFS and each
 * must be disconnected.  This might not be the last PFS using some of the
 * underlying devices.  Also, we have to adjust our hmp->mount_count
 * accounting for the devices backing the pmp which is now undergoing an
 * unmount.
 */
static void
hammer2_unmount_helper(struct mount *mp, hammer2_pfs_t *pmp, hammer2_dev_t *hmp)
{
	hammer2_cluster_t *cluster;
	hammer2_chain_t *rchain;
	int i;

	/*
	 * If no device supplied this is a high-level unmount and we have to
	 * to disconnect the mount, adjust mount_count, and locate devices
	 * that might now have no mounts.
	 */
	if (pmp) {
		KKASSERT(hmp == NULL);
		KKASSERT(MPTOPMP(mp) == pmp);
		pmp->mp = NULL;
		mp->mnt_data = NULL;
		mp->mnt_flag &= ~MNT_LOCAL;

		/*
		 * After pmp->mp is cleared we have to account for
		 * mount_count.
		 */
		cluster = &pmp->iroot->cluster;
		for (i = 0; i < cluster->nchains; ++i) {
			rchain = cluster->array[i].chain;
			if (rchain == NULL)
				continue;
			--rchain->hmp->mount_count;
			/* Scrapping hmp now may invalidate the pmp. */
		}
again:
		TAILQ_FOREACH(hmp, &hammer2_mntlist, mntentry) {
			if (hmp->mount_count == 0) {
				hammer2_unmount_helper(NULL, NULL, hmp);
				goto again;
			}
		}
		return;
	}

	/*
	 * Try to terminate the block device.  We can't terminate it if
	 * there are still PFSs referencing it.
	 */
	if (hmp->mount_count) {
		hprintf("%d PFS mounts still exist\n", hmp->mount_count);
		return;
	}

	hammer2_bulkfree_uninit(hmp);
	hammer2_pfsfree_scan(hmp, 0);

	/*
	 * Flush whatever is left.  Unmounted but modified PFS's might still
	 * have some dirty chains on them.
	 */
	hammer2_chain_lock(&hmp->vchain, HAMMER2_RESOLVE_ALWAYS);
	hammer2_chain_lock(&hmp->fchain, HAMMER2_RESOLVE_ALWAYS);

	if (hmp->fchain.flags & HAMMER2_CHAIN_FLUSH_MASK) {
		hammer2_voldata_modify(hmp);
		hammer2_flush(&hmp->fchain,
		    HAMMER2_FLUSH_TOP | HAMMER2_FLUSH_ALL);
	}
	hammer2_chain_unlock(&hmp->fchain);

	if (hmp->vchain.flags & HAMMER2_CHAIN_FLUSH_MASK)
		hammer2_flush(&hmp->vchain,
		    HAMMER2_FLUSH_TOP | HAMMER2_FLUSH_ALL);
	hammer2_chain_unlock(&hmp->vchain);

	if ((hmp->vchain.flags | hmp->fchain.flags) &
	    HAMMER2_CHAIN_FLUSH_MASK) {
		hprintf("chains left over after final sync "
		    "vchain %08x fchain %08x\n",
		    hmp->vchain.flags, hmp->fchain.flags);
		KKASSERT(0);
	}

	hammer2_pfsfree_scan(hmp, 1);
	KKASSERT(hmp->spmp == NULL);

	/* Finish up with the device vnode. */
	if (!TAILQ_EMPTY(&hmp->devvp_list)) {
		hammer2_close_devvp(&hmp->devvp_list, NULL);
		hammer2_cleanup_devvp(&hmp->devvp_list);
	}
	KKASSERT(TAILQ_EMPTY(&hmp->devvp_list));

	/*
	 * Clear vchain/fchain flags that might prevent final cleanup
	 * of these chains.
	 */
	if (hmp->vchain.flags & HAMMER2_CHAIN_MODIFIED) {
		atomic_add_int(&hammer2_count_chain_modified, -1);
		atomic_clear_int(&hmp->vchain.flags, HAMMER2_CHAIN_MODIFIED);
	}
	if (hmp->vchain.flags & HAMMER2_CHAIN_UPDATE)
		atomic_clear_int(&hmp->vchain.flags, HAMMER2_CHAIN_UPDATE);

	if (hmp->fchain.flags & HAMMER2_CHAIN_MODIFIED) {
		atomic_add_int(&hammer2_count_chain_modified, -1);
		atomic_clear_int(&hmp->fchain.flags, HAMMER2_CHAIN_MODIFIED);
	}
	if (hmp->fchain.flags & HAMMER2_CHAIN_UPDATE)
		atomic_clear_int(&hmp->fchain.flags, HAMMER2_CHAIN_UPDATE);

#ifdef HAMMER2_INVARIANTS
	hammer2_dump_chain(&hmp->vchain, 0, 0, -1, 'v');
	hammer2_dump_chain(&hmp->fchain, 0, 0, -1, 'f');
#endif
	/*
	 * Final drop of embedded volume/freemap root chain to clean up
	 * [vf]chain.core ([vf]chain structure is not flagged ALLOCATED so
	 * it is cleaned out and then left to rot).
	 */
	hammer2_chain_drop(&hmp->vchain);
	hammer2_chain_drop(&hmp->fchain);

	hammer2_mtx_ex(&hmp->iohash_lock);
	hammer2_io_hash_cleanup_all(hmp);
	if (hmp->iofree_count) {
		hprintf("XXX %d I/O's left hanging\n", hmp->iofree_count);
		//KKASSERT(0); /* XXX2 enable this */
	}
	hammer2_mtx_unlock(&hmp->iohash_lock);

	TAILQ_REMOVE(&hammer2_mntlist, hmp, mntentry);
	hammer2_mtx_destroy(&hmp->iohash_lock);
	hammer2_io_hash_destroy(hmp);

	hammer2_lk_destroy(&hmp->vollk);
	hammer2_lk_destroy(&hmp->bulklk);
	hammer2_lk_destroy(&hmp->bflk);

	hammer2_print_iostat(&hmp->iostat_read, "read");
	hammer2_print_iostat(&hmp->iostat_write, "write");

	hfree(hmp, M_HAMMER2, sizeof(*hmp));

	if (TAILQ_EMPTY(&hammer2_mntlist)) {
		if (malloc_leak_m_hammer2)
			hprintf("XXX M_HAMMER2 %d bytes leaked\n",
			    malloc_leak_m_hammer2);
		if (malloc_leak_m_hammer2_rbuf)
			hprintf("XXX M_HAMMER2_RBUF %d bytes leaked\n",
			    malloc_leak_m_hammer2_rbuf);
		if (malloc_leak_m_hammer2_wbuf)
			hprintf("XXX M_HAMMER2_WBUF %d bytes leaked\n",
			    malloc_leak_m_hammer2_wbuf);
		if (malloc_leak_m_hammer2_lz4)
			hprintf("XXX M_HAMMER2_LZ4 %d bytes leaked\n",
			    malloc_leak_m_hammer2_lz4);
		if (malloc_leak_m_temp)
			hprintf("XXX M_TEMP %d bytes leaked\n",
			    malloc_leak_m_temp);
	}
}

/*
 * Mount-time recovery (RW mounts)
 *
 * Updates to the free block table are allowed to lag flushes by one
 * transaction.  In case of a crash, then on a fresh mount we must do an
 * incremental scan of the last committed transaction id and make sure that
 * all related blocks have been marked allocated.
 */
struct hammer2_recovery_elm {
	TAILQ_ENTRY(hammer2_recovery_elm) entry;
	hammer2_chain_t *chain;
	hammer2_tid_t sync_tid;
};

TAILQ_HEAD(hammer2_recovery_list, hammer2_recovery_elm);

struct hammer2_recovery_info {
	struct hammer2_recovery_list list;
	hammer2_tid_t mtid;
	int depth;
};

static int hammer2_recovery_scan(hammer2_dev_t *, hammer2_chain_t *,
    struct hammer2_recovery_info *, hammer2_tid_t);

#define HAMMER2_RECOVERY_MAXDEPTH	10

static int
hammer2_recovery(hammer2_dev_t *hmp)
{
	struct hammer2_recovery_info info;
	struct hammer2_recovery_elm *elm;
	hammer2_chain_t *parent;
	hammer2_tid_t sync_tid, mirror_tid;
	int error;

	hammer2_trans_init(hmp->spmp, 0);

	sync_tid = hmp->voldata.freemap_tid;
	mirror_tid = hmp->voldata.mirror_tid;

	if (sync_tid >= mirror_tid)
		debug_hprintf("no recovery needed\n");
	else
		hprintf("freemap recovery %016llx-%016llx\n",
		    (long long)sync_tid + 1, (long long)mirror_tid);

	TAILQ_INIT(&info.list);
	info.depth = 0;
	parent = hammer2_chain_lookup_init(&hmp->vchain, 0);
	error = hammer2_recovery_scan(hmp, parent, &info, sync_tid);
	hammer2_chain_lookup_done(parent);

	while ((elm = TAILQ_FIRST(&info.list)) != NULL) {
		TAILQ_REMOVE(&info.list, elm, entry);
		parent = elm->chain;
		sync_tid = elm->sync_tid;
		hfree(elm, M_HAMMER2, sizeof(*elm));

		hammer2_chain_lock(parent, HAMMER2_RESOLVE_ALWAYS);
		error |= hammer2_recovery_scan(hmp, parent, &info,
		    hmp->voldata.freemap_tid);
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent); /* drop elm->chain ref */
	}

	hammer2_trans_done(hmp->spmp, 0);

	return (error);
}

static int
hammer2_recovery_scan(hammer2_dev_t *hmp, hammer2_chain_t *parent,
    struct hammer2_recovery_info *info, hammer2_tid_t sync_tid)
{
	hammer2_chain_t *chain;
	hammer2_blockref_t bref;
	struct hammer2_recovery_elm *elm;
	const hammer2_inode_data_t *ripdata;
	int tmp_error, rup_error, error, first;

	/* Adjust freemap to ensure that the block(s) are marked allocated. */
	if (parent->bref.type != HAMMER2_BREF_TYPE_VOLUME)
		hammer2_freemap_adjust(hmp, &parent->bref,
		    HAMMER2_FREEMAP_DORECOVER);

	/* Check type for recursive scan. */
	switch (parent->bref.type) {
	case HAMMER2_BREF_TYPE_VOLUME:
		/* data already instantiated */
		break;
	case HAMMER2_BREF_TYPE_INODE:
		/*
		 * Must instantiate data for DIRECTDATA test and also
		 * for recursion.
		 */
		hammer2_chain_lock(parent, HAMMER2_RESOLVE_ALWAYS);
		ripdata = &parent->data->ipdata;
		if (ripdata->meta.op_flags & HAMMER2_OPFLAG_DIRECTDATA) {
			/* not applicable to recovery scan */
			hammer2_chain_unlock(parent);
			return (0);
		}
		hammer2_chain_unlock(parent);
		break;
	case HAMMER2_BREF_TYPE_INDIRECT:
		/* Must instantiate data for recursion. */
		hammer2_chain_lock(parent, HAMMER2_RESOLVE_ALWAYS);
		hammer2_chain_unlock(parent);
		break;
	case HAMMER2_BREF_TYPE_DIRENT:
	case HAMMER2_BREF_TYPE_DATA:
	case HAMMER2_BREF_TYPE_FREEMAP:
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
	case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
		/* not applicable to recovery scan */
		return (0);
		break;
	default:
		return (HAMMER2_ERROR_BADBREF);
	}

	/* Defer operation if depth limit reached. */
	if (info->depth >= HAMMER2_RECOVERY_MAXDEPTH) {
		elm = hmalloc(sizeof(*elm), M_HAMMER2, M_ZERO | M_WAITOK);
		elm->chain = parent;
		elm->sync_tid = sync_tid;
		hammer2_chain_ref(parent);
		TAILQ_INSERT_TAIL(&info->list, elm, entry);
		/* unlocked by caller */
		return (0);
	}

	/*
	 * Recursive scan of the last flushed transaction only.  We are
	 * doing this without pmp assignments so don't leave the chains
	 * hanging around after we are done with them.
	 *
	 * error	Cumulative error this level only
	 * rup_error	Cumulative error for recursion
	 * tmp_error	Specific non-cumulative recursion error
	 */
	chain = NULL;
	first = 1;
	rup_error = 0;
	error = 0;

	for (;;) {
		error |= hammer2_chain_scan(parent, &chain, &bref, &first,
		    HAMMER2_LOOKUP_NODATA);
		/* Problem during scan or EOF. */
		if (error)
			break;

		/* If this is a leaf. */
		if (chain == NULL) {
			if (bref.mirror_tid > sync_tid)
				hammer2_freemap_adjust(hmp, &bref,
				    HAMMER2_FREEMAP_DORECOVER);
			continue;
		}

		/* This may or may not be a recursive node. */
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_RELEASE);
		if (bref.mirror_tid > sync_tid) {
			++info->depth;
			tmp_error = hammer2_recovery_scan(hmp, chain, info,
			    sync_tid);
			--info->depth;
		} else {
			tmp_error = 0;
		}

		/*
		 * Flush the recovery at the PFS boundary to stage it for
		 * the final flush of the super-root topology.
		 */
		if (tmp_error == 0 &&
		    (bref.flags & HAMMER2_BREF_FLAG_PFSROOT) &&
		    (chain->flags & HAMMER2_CHAIN_ONFLUSH))
			hammer2_flush(chain,
			    HAMMER2_FLUSH_TOP | HAMMER2_FLUSH_ALL);
		rup_error |= tmp_error;
	}
	return ((error | rup_error) & ~HAMMER2_ERROR_EOF);
}

/*
 * This fixes up an error introduced in earlier H2 implementations where
 * moving a PFS inode into an indirect block wound up causing the
 * HAMMER2_BREF_FLAG_PFSROOT flag in the bref to get cleared.
 */
static int
hammer2_fixup_pfses(hammer2_dev_t *hmp)
{
	const hammer2_inode_data_t *ripdata;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	hammer2_pfs_t *spmp;
	int error = 0, error2;

	/*
	 * Lookup mount point under the media-localized super-root.
	 *
	 * cluster->pmp will incorrectly point to spmp and must be fixed
	 * up later on.
	 */
	spmp = hmp->spmp;
	hammer2_inode_lock(spmp->iroot, 0);
	parent = hammer2_inode_chain(spmp->iroot, 0, HAMMER2_RESOLVE_ALWAYS);
	chain = hammer2_chain_lookup(&parent, &key_next, HAMMER2_KEY_MIN,
	    HAMMER2_KEY_MAX, &error, 0);

	while (chain) {
		if (chain->bref.type != HAMMER2_BREF_TYPE_INODE)
			continue;
		if (chain->error) {
			hprintf("I/O error scanning PFS labels\n");
			error |= chain->error;
		} else if ((chain->bref.flags & HAMMER2_BREF_FLAG_PFSROOT) == 0) {
			ripdata = &chain->data->ipdata;
			hammer2_trans_init(hmp->spmp, 0);
			error2 = hammer2_chain_modify(chain,
			    chain->bref.modify_tid, 0, 0);
			if (error2 == 0) {
				hprintf("correct mis-flagged PFS %s\n",
				    ripdata->filename);
				chain->bref.flags |= HAMMER2_BREF_FLAG_PFSROOT;
			} else {
				error |= error2;
			}
			hammer2_flush(chain,
			    HAMMER2_FLUSH_TOP | HAMMER2_FLUSH_ALL);
			hammer2_trans_done(hmp->spmp, 0);
		}
		chain = hammer2_chain_next(&parent, chain, &key_next,
		    HAMMER2_KEY_MAX, &error, 0);
	}

	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_inode_unlock(spmp->iroot);

	return (error);
}

static int
hammer2_remount_impl(hammer2_dev_t *hmp)
{
	hammer2_volume_t *vol;
	int i, error;

	for (i = 0; i < hmp->nvolumes; ++i) {
		vol = &hmp->volumes[i];
		if (vol->id == HAMMER2_ROOT_VOLUME) {
			error = hammer2_recovery(hmp);
			if (error == 0)
				error |= hammer2_fixup_pfses(hmp);
			if (error)
				return (hammer2_error_to_errno(error));
		}
	}
	hmp->rdonly = 0;
	hmp->spmp->rdonly = 0; /* never used */

	return (0);
}

static int
hammer2_remount(hammer2_dev_t *hmp, struct mount *mp)
{
	hammer2_pfs_t *pmp = MPTOPMP(mp);
	int error;

	if (pmp->rdonly == 0 && (mp->mnt_flag & MNT_RDONLY)) {
		pmp->rdonly = 1;
	} else if (pmp->rdonly == 1 && (mp->mnt_flag & MNT_WANTRDWR)) {
		if (hmp->rdonly) {
			error = hammer2_remount_impl(hmp);
			if (error)
				return (error);
		}
		pmp->rdonly = 0;
	}

	debug_hprintf("MNT_WANTRDWR %d MNT_RDONLY %d rdonly %d/%d/%d\n",
	    (mp->mnt_flag & MNT_WANTRDWR) ? 1 : 0,
	    (mp->mnt_flag & MNT_RDONLY) ? 1 : 0,
	    hmp->rdonly, hmp->spmp->rdonly, pmp->rdonly);

	return (0);
}

/*
 * Sync a mount point; this is called periodically on a per-mount basis from
 * the filesystem syncer, and whenever a user issues a sync.
 */
int
hammer2_sync(struct mount *mp, int waitfor, int stall, struct ucred *cred,
    struct proc *p)
{
	return (hammer2_vfs_sync_pmp(MPTOPMP(mp), waitfor));
}

int
hammer2_vfs_sync_pmp(hammer2_pfs_t *pmp, int waitfor __unused)
{
	hammer2_inode_t *ip;
	hammer2_depend_t *depend, *depend_next;
	struct vnode *vp;
	uint32_t pass2;
	int error, dorestart, ndrop;

	/*
	 * Move all inodes on sideq to syncq.  This will clear sideq.
	 * This should represent all flushable inodes.  These inodes
	 * will already have refs due to being on syncq or sideq.  We
	 * must do this all at once with the spinlock held to ensure that
	 * all inode dependencies are part of the same flush.
	 *
	 * We should be able to do this asynchronously from frontend
	 * operations because we will be locking the inodes later on
	 * to actually flush them, and that will partition any frontend
	 * op using the same inode.  Either it has already locked the
	 * inode and we will block, or it has not yet locked the inode
	 * and it will block until we are finished flushing that inode.
	 *
	 * When restarting, only move the inodes flagged as PASS2 from
	 * SIDEQ to SYNCQ.  PASS2 propagation by inode_lock4() and
	 * inode_depend() are atomic with the spin-lock.
	 */
	hammer2_trans_init(pmp, HAMMER2_TRANS_ISFLUSH);
	debug_hprintf("FILESYSTEM SYNC BOUNDARY\n");
	dorestart = 0;

	/*
	 * Move inodes from depq to syncq, releasing the related
	 * depend structures.
	 */
restart:
	debug_hprintf("FILESYSTEM SYNC RESTART (%d)\n", dorestart);
	hammer2_trans_setflags(pmp, 0);
	hammer2_trans_clearflags(pmp, HAMMER2_TRANS_RESCAN);

	/*
	 * Move inodes from depq to syncq.  When restarting, only depq's
	 * marked pass2 are moved.
	 */
	hammer2_spin_ex(&pmp->list_spin);
	depend_next = TAILQ_FIRST(&pmp->depq);

	while ((depend = depend_next) != NULL) {
		depend_next = TAILQ_NEXT(depend, entry);
		if (dorestart && depend->pass2 == 0)
			continue;
		TAILQ_FOREACH(ip, &depend->sideq, qentry) {
			KKASSERT(ip->flags & HAMMER2_INODE_SIDEQ);
			atomic_set_int(&ip->flags, HAMMER2_INODE_SYNCQ);
			atomic_clear_int(&ip->flags, HAMMER2_INODE_SIDEQ);
			ip->depend = NULL;
		}

		/* NOTE: pmp->sideq_count includes both sideq and syncq */
		TAILQ_CONCAT(&pmp->syncq, &depend->sideq, qentry);

		depend->count = 0;
		depend->pass2 = 0;
		TAILQ_REMOVE(&pmp->depq, depend, entry);
	}

	hammer2_spin_unex(&pmp->list_spin);
	hammer2_trans_clearflags(pmp, HAMMER2_TRANS_WAITING);
	dorestart = 0;

	/*
	 * Now run through all inodes on syncq.
	 * Flush transactions only interlock with other flush transactions.
	 * Any conflicting frontend operations will block on the inode, but
	 * may hold a vnode lock while doing so.
	 */
	hammer2_spin_ex(&pmp->list_spin);
	while ((ip = TAILQ_FIRST(&pmp->syncq)) != NULL) {
		/*
		 * Remove the inode from the SYNCQ, transfer the syncq ref
		 * to us.  We must clear SYNCQ to allow any potential
		 * front-end deadlock to proceed.  We must set PASS2 so
		 * the dependency code knows what to do.
		 */
		pass2 = ip->flags;
		cpu_ccfence();
		if (atomic_cmpset_int(&ip->flags, pass2,
		    (pass2 & ~(HAMMER2_INODE_SYNCQ | HAMMER2_INODE_SYNCQ_WAKEUP)) |
		    HAMMER2_INODE_SYNCQ_PASS2) == 0)
			continue;
		TAILQ_REMOVE(&pmp->syncq, ip, qentry);
		--pmp->sideq_count;
		hammer2_spin_unex(&pmp->list_spin);

		/*
		 * Tickle anyone waiting on ip->flags or the hysteresis
		 * on the dirty inode count.
		 */
		if (pass2 & HAMMER2_INODE_SYNCQ_WAKEUP)
			wakeup(&ip->flags);

		/*
		 * Relock the inode, and we inherit a ref from the above.
		 * We will check for a race after we acquire the vnode.
		 */
		hammer2_mtx_ex(&ip->lock);

		/*
		 * We need the vp in order to vfsync() dirty buffers, so if
		 * one isn't attached we can skip it.
		 *
		 * Ordering the inode lock and then the vnode lock has the
		 * potential to deadlock.  If we had left SYNCQ set that could
		 * also deadlock us against the frontend even if we don't hold
		 * any locks, but the latter is not a problem now since we
		 * cleared it.  igetv will temporarily release the inode lock
		 * in a safe manner to work-around the deadlock.
		 *
		 * Unfortunately it is still possible to deadlock when the
		 * frontend obtains multiple inode locks, because all the
		 * related vnodes are already locked (nor can the vnode locks
		 * be released and reacquired without messing up RECLAIM and
		 * INACTIVE sequencing).
		 *
		 * The solution for now is to move the vp back onto SIDEQ
		 * and set dorestart, which will restart the flush after we
		 * exhaust the current SYNCQ.  Note that additional
		 * dependencies may build up, so we definitely need to move
		 * the whole SIDEQ back to SYNCQ when we restart.
		 */
		vp = ip->vp; /* NULL after vflush() */
		if (vp) {
			if (vget(vp, LK_EXCLUSIVE | LK_NOWAIT)) {
				/*
				 * Failed to get the vnode, requeue the inode
				 * (PASS2 is already set so it will be found
				 * again on the restart).  Then unlock.
				 */
				vp = NULL;
				dorestart |= 1;
				debug_hprintf("inum %016llx vn_lock failed\n",
				    (long long)ip->meta.inum);
				hammer2_inode_delayed_sideq(ip);

				hammer2_mtx_unlock(&ip->lock);
				hammer2_inode_drop(ip);

				/*
				 * If PASS2 was previously set we might
				 * be looping too hard, ask for a delay
				 * along with the restart.
				 */
				if (pass2 & HAMMER2_INODE_SYNCQ_PASS2)
					dorestart |= 2;
				hammer2_spin_ex(&pmp->list_spin);
				continue;
			}
		} else {
			vp = NULL;
		}

		/*
		 * If the inode wound up on a SIDEQ again it will already be
		 * prepped for another PASS2.  In this situation if we flush
		 * it now we will just wind up flushing it again in the same
		 * syncer run, so we might as well not flush it now.
		 */
		if (ip->flags & HAMMER2_INODE_SIDEQ) {
			hammer2_mtx_unlock(&ip->lock);
			hammer2_inode_drop(ip);
			if (vp)
				vput(vp);
			dorestart |= 1;
			hammer2_spin_ex(&pmp->list_spin);
			continue;
		}

		/*
		 * Ok we have the inode exclusively locked and if vp is
		 * not NULL that will also be exclusively locked.  Do the
		 * meat of the flush.
		 */
		if (vp)
			vflushbuf(vp, 1);

		/*
		 * If the inode has not yet been inserted into the tree
		 * we must do so.  Then sync and flush it.  The flush should
		 * update the parent.
		 */
		if (ip->flags & HAMMER2_INODE_DELETING) {
			debug_hprintf("inum %016llx destroy\n",
			    (long long)ip->meta.inum);
			hammer2_inode_chain_des(ip);
		} else if (ip->flags & HAMMER2_INODE_CREATING) {
			debug_hprintf("inum %016llx insert\n",
			    (long long)ip->meta.inum);
			hammer2_inode_chain_ins(ip);
		}

		/*
		 * Because I kinda messed up the design and index the inodes
		 * under the root inode, along side the directory entries,
		 * we can't flush the inode index under the iroot until the
		 * end.  If we do it now we might miss effects created by
		 * other inodes on the SYNCQ.
		 *
		 * Do a normal (non-FSSYNC) flush instead, which allows the
		 * vnode code to work the same.  We don't want to force iroot
		 * back onto the SIDEQ, and we also don't want the flush code
		 * to update pfs_iroot_blocksets until the final flush later.
		 *
		 * XXX at the moment this will likely result in a double-flush
		 * of the iroot chain.
		 */
		debug_hprintf("inum %016llx pinum %016llx chain-sync\n",
		    (long long)ip->meta.inum, (long long)ip->meta.iparent);
		hammer2_inode_chain_sync(ip);

		if (ip == pmp->iroot)
			hammer2_inode_chain_flush(ip, HAMMER2_XOP_INODE_STOP);
		else
			hammer2_inode_chain_flush(ip,
			    HAMMER2_XOP_INODE_STOP | HAMMER2_XOP_FSSYNC);
		if (vp) {
			if ((ip->flags & (HAMMER2_INODE_MODIFIED |
			    HAMMER2_INODE_RESIZED |
			    HAMMER2_INODE_DIRTYDATA)) == 0) {
				/*
				 * DragonFly uses DragonFly's vsyncscan specific
				 * vclrisdirty() here.
				 */
			} else {
				hammer2_inode_delayed_sideq(ip);
			}
			ndrop = ip->vhold;
			vput(vp);
			hammer2_inode_vdrop(ip, ndrop);
			/* OpenBSD mknod specific, not a must to begin with. */
			/*
			if (vp->v_type == VFIFO) {
				vp->v_type = VNON;
				vgone(vp);
			}
			*/
			vp = NULL; /* safety */
		}
		atomic_clear_int(&ip->flags, HAMMER2_INODE_SYNCQ_PASS2);
		hammer2_inode_unlock(ip); /* unlock+drop */
		/* ip pointer invalid */

		/*
		 * If the inode got dirted after we dropped our locks,
		 * it will have already been moved back to the SIDEQ.
		 */
		hammer2_spin_ex(&pmp->list_spin);
	}
	hammer2_spin_unex(&pmp->list_spin);

	if (dorestart || (pmp->trans.flags & HAMMER2_TRANS_RESCAN)) {
		/*
		 * bit 2 is set if something above thinks we might be
		 * looping too hard, try to unclog the frontend
		 * dependency and wait a bit before restarting.
		 *
		 * NOTE: The frontend could be stuck in h2memw, though
		 *	 it isn't supposed to be holding vnode locks
		 *	 in that case.
		 */
		if (dorestart & 2)
			tsleep(&dorestart, 0, "h2syndel", 2);
		debug_hprintf("FILESYSTEM SYNC STAGE 1 RESTART\n");
		dorestart = 1;
		goto restart;
	}
	debug_hprintf("FILESYSTEM SYNC STAGE 2 BEGIN\n");

	/*
	 * We have to flush the PFS root last, even if it does not appear to
	 * be dirty, because all the inodes in the PFS are indexed under it.
	 * The normal flushing of iroot above would only occur if directory
	 * entries under the root were changed.
	 *
	 * Specifying VOLHDR will cause an additionl flush of hmp->spmp
	 * for the media making up the cluster.
	 */
	if ((ip = pmp->iroot) != NULL) {
		hammer2_inode_ref(ip);
		hammer2_mtx_ex(&ip->lock);
		hammer2_inode_chain_sync(ip);
		hammer2_inode_chain_flush(ip,
		    HAMMER2_XOP_INODE_STOP | HAMMER2_XOP_FSSYNC |
		    HAMMER2_XOP_VOLHDR);
		hammer2_inode_unlock(ip); /* unlock+drop */
	}
	debug_hprintf("FILESYSTEM SYNC STAGE 2 DONE\n");

	hammer2_bioq_sync(pmp);

	error = 0; /* XXX */
	hammer2_trans_done(pmp, HAMMER2_TRANS_ISFLUSH);

	return (error);
}

static int
hammer2_vget(struct mount *mp, ino_t ino, struct vnode **vpp)
{
	hammer2_pfs_t *pmp = MPTOPMP(mp);
	hammer2_inode_t *ip;
	hammer2_xop_lookup_t *xop;
	hammer2_tid_t inum;
	int error;

	inum = (hammer2_tid_t)ino & HAMMER2_DIRHASH_USERMSK;

	/* Easy if we already have it cached. */
	ip = hammer2_inode_lookup(pmp, inum);
	if (ip) {
		hammer2_inode_lock(ip, HAMMER2_RESOLVE_SHARED);
		error = hammer2_igetv(ip, vpp);
		hammer2_inode_unlock(ip);
		hammer2_inode_drop(ip); /* from lookup */
		return (error);
	}

	/* Otherwise we have to find the inode. */
	xop = hammer2_xop_alloc(pmp->iroot, 0);
	xop->lhc = inum;
	hammer2_xop_start(&xop->head, &hammer2_lookup_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	if (error == 0)
		ip = hammer2_inode_get(pmp, &xop->head, -1, -1);
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	if (ip) {
		error = hammer2_igetv(ip, vpp);
		hammer2_inode_unlock(ip);
	} else {
		*vpp = NULL;
		error = ENOENT;
	}

	return (error);
}

static int
hammer2_root(struct mount *mp, struct vnode **vpp)
{
	hammer2_pfs_t *pmp = MPTOPMP(mp);
	hammer2_xop_ipcluster_t *xop;
	const hammer2_inode_meta_t *meta;
	int error = 0;

	if (pmp->iroot == NULL) {
		hprintf("%s has no root inode\n", mp->mnt_stat.f_mntfromname);
		*vpp = NULL;
		return (EINVAL);
	}

	hammer2_inode_lock(pmp->iroot, HAMMER2_RESOLVE_SHARED);

	while (pmp->inode_tid == 0) {
		xop = hammer2_xop_alloc(pmp->iroot, HAMMER2_XOP_MODIFYING);
		hammer2_xop_start(&xop->head, &hammer2_ipcluster_desc);
		error = hammer2_xop_collect(&xop->head, 0);

		if (error == 0) {
			meta = &hammer2_xop_gdata(&xop->head)->ipdata.meta;
			pmp->iroot->meta = *meta;
			pmp->inode_tid = meta->pfs_inum + 1;
			hammer2_xop_pdata(&xop->head);

			if (pmp->inode_tid < HAMMER2_INODE_START)
				pmp->inode_tid = HAMMER2_INODE_START;
			pmp->modify_tid =
			    xop->head.cluster.focus->bref.modify_tid + 1;
			debug_hprintf("PFS nextino %016llx mod %016llx\n",
			    (long long)pmp->inode_tid,
			    (long long)pmp->modify_tid);

			wakeup(&pmp->iroot);
			hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

			/* Prime the mount info. */
			hammer2_statfs(mp, &mp->mnt_stat, curproc);
			break;
		}

		/* Loop, try again. */
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		hammer2_inode_unlock(pmp->iroot);
		error = tsleep(&pmp->iroot, PCATCH, "h2root", hz);
		hammer2_inode_lock(pmp->iroot, HAMMER2_RESOLVE_SHARED);
		if (error == EINTR)
			break;
	}

	if (error) {
		hammer2_inode_unlock(pmp->iroot);
		*vpp = NULL;
	} else {
		error = hammer2_igetv(pmp->iroot, vpp);
		hammer2_inode_unlock(pmp->iroot);
	}

	return (error);
}

static int
hammer2_quotactl(struct mount *mp, int cmd, uid_t uid, caddr_t arg,
    struct proc *p)
{
	return (EOPNOTSUPP);
}

static int
hammer2_statfs(struct mount *mp, struct statfs *sbp, struct proc *p)
{
	hammer2_pfs_t *pmp = MPTOPMP(mp);
	hammer2_dev_t *hmp;
	hammer2_blockref_t bref;
	struct ucred *cred = curproc->p_ucred;
	struct statfs tmp;
	uint64_t adj;
	int i;

	KKASSERT(mp->mnt_stat.f_iosize > 0);
	KKASSERT(mp->mnt_stat.f_bsize > 0);

	bzero(&tmp, sizeof(tmp));

	for (i = 0; i < pmp->iroot->cluster.nchains; ++i) {
		hmp = pmp->pfs_hmps[i];
		if (hmp == NULL)
			continue;
		if (pmp->iroot->cluster.array[i].chain)
			bref = pmp->iroot->cluster.array[i].chain->bref;
		else
			bzero(&bref, sizeof(bref));

		tmp.f_files = bref.embed.stats.inode_count;
		tmp.f_ffree = 0;
		tmp.f_blocks = hmp->voldata.allocator_size /
		    mp->mnt_stat.f_bsize;
		tmp.f_bfree = hmp->voldata.allocator_free /
		    mp->mnt_stat.f_bsize;
		tmp.f_bavail = tmp.f_bfree;

		if (cred && cred->cr_uid != 0) {
			/* 5% */
			adj = hmp->free_reserved / mp->mnt_stat.f_bsize;
			tmp.f_blocks -= adj;
			tmp.f_bfree -= adj;
			tmp.f_bavail -= adj;
		}

		mp->mnt_stat.f_blocks = tmp.f_blocks;
		mp->mnt_stat.f_bfree = tmp.f_bfree;
		mp->mnt_stat.f_bavail = tmp.f_bavail;
		mp->mnt_stat.f_files = tmp.f_files;
		mp->mnt_stat.f_ffree = tmp.f_ffree;

		*sbp = mp->mnt_stat;
		sbp->f_iosize = mp->mnt_stat.f_iosize;
		sbp->f_bsize = mp->mnt_stat.f_bsize;

		sbp->f_favail = 0;
		copy_statfs_info(sbp, mp);
	}
	return (0);
}

struct hfid {
	uint16_t hfid_len;	/* Length of structure. */
	uint16_t hfid_pad;	/* Force 32-bit alignment. */
	hammer2_tid_t hfid_data[2];
};

static int
hammer2_fhtovp(struct mount *mp, struct fid *fhp, struct vnode **vpp)
{
	hammer2_tid_t inum;
	struct hfid *hfhp;
	int error;

	hfhp = (struct hfid *)fhp;
	if (hfhp->hfid_len != sizeof(struct hfid))
		return (EINVAL);

	inum = hfhp->hfid_data[0] & HAMMER2_DIRHASH_USERMSK;
	if (vpp) {
		if (inum == 1)
			error = hammer2_root(mp, vpp);
		else
			error = hammer2_vget(mp, inum, vpp);
	} else {
		error = 0;
	}

	return (error);
}

static int
hammer2_vptofh(struct vnode *vp, struct fid *fhp)
{
	hammer2_inode_t *ip = VTOI(vp);
	struct hfid *hfhp;

	hfhp = (struct hfid *)fhp;
	hfhp->hfid_len = sizeof(struct hfid);
	hfhp->hfid_pad = 0;
	hfhp->hfid_data[0] = ip->meta.inum;
	hfhp->hfid_data[1] = 0;

	return (0);
}

static int
hammer2_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
    void *newp, size_t newlen, struct proc *p)
{
	return (sysctl_bounded_arr(hammer2_vars, nitems(hammer2_vars), name,
	    namelen, oldp, oldlenp, newp, newlen));
}

static int
hammer2_check_export(struct mount *mp, struct mbuf *nam, int *exflagsp,
    struct ucred **credanonp)
{
	struct netcred *np;
	hammer2_pfs_t *pmp = MPTOPMP(mp);

	/*
	 * Get the export permission structure for this <mp, client> tuple.
	 */
	np = vfs_export_lookup(mp, &pmp->pm_export, nam);
	if (np == NULL)
		return (EACCES);

	*exflagsp = np->netc_exflags;
	*credanonp = &np->netc_anon;
	return (0);
}

/*
 * Volume header data locks.
 */
void
hammer2_voldata_lock(hammer2_dev_t *hmp)
{
	hammer2_lk_ex(&hmp->vollk);
}

void
hammer2_voldata_unlock(hammer2_dev_t *hmp)
{
	hammer2_lk_unlock(&hmp->vollk);
}

/*
 * Caller indicates that the volume header is being modified.
 * Flag the related chain and adjust its transaction id.
 *
 * The transaction id is set to voldata.mirror_tid + 1, similar to
 * what hammer2_chain_modify() does.  Be very careful here, volume
 * data can be updated independently of the rest of the filesystem.
 */
void
hammer2_voldata_modify(hammer2_dev_t *hmp)
{
	if ((hmp->vchain.flags & HAMMER2_CHAIN_MODIFIED) == 0) {
		atomic_add_int(&hammer2_count_chain_modified, 1);
		atomic_set_int(&hmp->vchain.flags, HAMMER2_CHAIN_MODIFIED);
		hmp->vchain.bref.mirror_tid = hmp->voldata.mirror_tid + 1;
	}
}

/*
 * Returns 0 if the filesystem has tons of free space.
 * Returns 1 if the filesystem has less than 10% remaining.
 * Returns 2 if the filesystem has less than 2%/5% (user/root) remaining.
 */
int
hammer2_vfs_enospace(hammer2_inode_t *ip, off_t bytes, struct ucred *cred)
{
	hammer2_dev_t *hmp;
	hammer2_pfs_t *pmp = ip->pmp;
	hammer2_off_t free_reserved, free_nominal;
	int i;

	if (pmp->free_ticks == 0 || pmp->free_ticks != getticks()) {
		free_reserved = HAMMER2_SEGSIZE;
		free_nominal = 0x7FFFFFFFFFFFFFFFLLU;
		for (i = 0; i < pmp->iroot->cluster.nchains; ++i) {
			hmp = pmp->pfs_hmps[i];
			if (hmp == NULL)
				continue;
			if (pmp->pfs_types[i] != HAMMER2_PFSTYPE_MASTER &&
			    pmp->pfs_types[i] != HAMMER2_PFSTYPE_SOFT_MASTER)
				continue;
			if (free_nominal > hmp->voldata.allocator_free)
				free_nominal = hmp->voldata.allocator_free;
			if (free_reserved < hmp->free_reserved)
				free_reserved = hmp->free_reserved;
		}
		/* SMP races ok */
		pmp->free_reserved = free_reserved;
		pmp->free_nominal = free_nominal;
		pmp->free_ticks = getticks();
	} else {
		free_reserved = pmp->free_reserved;
		free_nominal = pmp->free_nominal;
	}

	if (cred && cred->cr_uid != 0) {
		if ((int64_t)(free_nominal - bytes) < (int64_t)free_reserved)
			return (2);
	} else {
		if ((int64_t)(free_nominal - bytes) < (int64_t)free_reserved / 2)
			return (2);
	}

	if ((int64_t)(free_nominal - bytes) < (int64_t)free_reserved * 2)
		return (1);

	return (0);
}

const struct vfsops hammer2_vfsops = {
	.vfs_mount = hammer2_mount,
	.vfs_start = hammer2_start,
	.vfs_unmount = hammer2_unmount,
	.vfs_root = hammer2_root,
	.vfs_quotactl = hammer2_quotactl,
	.vfs_statfs = hammer2_statfs,
	.vfs_sync = hammer2_sync,
	.vfs_vget = hammer2_vget,
	.vfs_fhtovp = hammer2_fhtovp,
	.vfs_vptofh = hammer2_vptofh,
	.vfs_init = hammer2_init,
	.vfs_sysctl = hammer2_sysctl,
	.vfs_checkexp = hammer2_check_export,
};

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

#include "hammer2.h"
#include "hammer2_mount.h"

#include <sys/sysctl.h>
#include <sys/specdev.h>

static int hammer2_unmount(struct mount *, int, struct proc *);
static int hammer2_statfs(struct mount *, struct statfs *, struct proc *);
static void hammer2_update_pmps(hammer2_dev_t *);
static void hammer2_mount_helper(struct mount *, hammer2_pfs_t *);
static void hammer2_unmount_helper(struct mount *, hammer2_pfs_t *,
    hammer2_dev_t *);

struct pool hammer2_inode_pool;
struct pool hammer2_xops_pool;

/* global list of HAMMER2 */
TAILQ_HEAD(hammer2_mntlist, hammer2_dev); /* <-> hammer2_dev::mntentry */
typedef struct hammer2_mntlist hammer2_mntlist_t;
static hammer2_mntlist_t hammer2_mntlist;

/* global list of PFS */
hammer2_pfslist_t hammer2_pfslist;
static hammer2_pfslist_t hammer2_spmplist;

/* mutex(9) is spinlock in OpenBSD */
struct rwlock hammer2_mntlk;

static int hammer2_supported_version = HAMMER2_VOL_VERSION_DEFAULT;
int hammer2_inode_allocs;
int hammer2_chain_allocs;
int hammer2_dio_allocs;
int hammer2_dio_limit = 256;
int hammer2_limit_scan_depth;
int hammer2_limit_saved_chains;
long hammer2_count_modified_chains;

static const struct sysctl_bounded_args hammer2_vars[] = {
	{ HAMMER2CTL_SUPPORTED_VERSION, &hammer2_supported_version, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_INODE_ALLOCS, &hammer2_inode_allocs, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_CHAIN_ALLOCS, &hammer2_chain_allocs, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_DIO_ALLOCS, &hammer2_dio_allocs, SYSCTL_INT_READONLY, },
	{ HAMMER2CTL_DIO_LIMIT, &hammer2_dio_limit, 0, INT_MAX, },
	{ HAMMER2CTL_LIMIT_SCAN_DEPTH, &hammer2_limit_scan_depth, 0, INT_MAX, },
	{ HAMMER2CTL_LIMIT_SAVED_CHAINS, &hammer2_limit_saved_chains, 0, INT_MAX, },
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

	if (hammer2_inode_allocs > 0) {
		hprintf("%d inode left\n", hammer2_inode_allocs);
		error = EINVAL;
	}
	KKASSERT(hammer2_inode_allocs == 0);

	if (hammer2_chain_allocs > 0) {
		hprintf("%d chain left\n", hammer2_chain_allocs);
		error = EINVAL;
	}
	KKASSERT(hammer2_chain_allocs == 0);

	if (hammer2_dio_allocs > 0) {
		hprintf("%d dio left\n", hammer2_dio_allocs);
		error = EINVAL;
	}
	KKASSERT(hammer2_dio_allocs == 0);

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
	long hammer2_limit_dirty_inodes; /* originally sysctl */

	KASSERT(sizeof(struct hammer2_mount_info) == sizeof(struct hammer2_args));
	KASSERT(sizeof(struct hammer2_mount_info) <= 160); /* union mount_info */

	hammer2_assert_clean();

	hammer2_dio_limit = buf_nbuf() * 2;
	if (hammer2_dio_limit > 100000 || hammer2_dio_limit < 0)
		hammer2_dio_limit = 100000;

	/*
	 * XXX A pool for read buffer with size of 65536 is usable,
	 * but subsequent pool_get(&hammer2_xops_pool, PR_WAITOK | ...)
	 * gets blocked and never returns.
	 */
	pool_init(&hammer2_inode_pool, sizeof(hammer2_inode_t), 0,
	    IPL_NONE, PR_WAITOK, "h2inopool", NULL);

	pool_init(&hammer2_xops_pool, sizeof(hammer2_xop_t), 0,
	    IPL_NONE, PR_WAITOK, "h2xopspool", NULL);

	rw_init(&hammer2_mntlk, "h2mntlk");

	TAILQ_INIT(&hammer2_mntlist);
	TAILQ_INIT(&hammer2_pfslist);
	TAILQ_INIT(&hammer2_spmplist);

#define desiredvnodes	maxvnodes
	hammer2_limit_dirty_chains = desiredvnodes / 10;
	if (hammer2_limit_dirty_chains > HAMMER2_LIMIT_DIRTY_CHAINS)
		hammer2_limit_dirty_chains = HAMMER2_LIMIT_DIRTY_CHAINS;
	if (hammer2_limit_dirty_chains < 1000)
		hammer2_limit_dirty_chains = 1000;

	hammer2_limit_dirty_inodes = desiredvnodes / 25;
	if (hammer2_limit_dirty_inodes < 100)
		hammer2_limit_dirty_inodes = 100;
	if (hammer2_limit_dirty_inodes > HAMMER2_LIMIT_DIRTY_INODES)
		hammer2_limit_dirty_inodes = HAMMER2_LIMIT_DIRTY_INODES;

	hammer2_limit_saved_chains = hammer2_limit_dirty_chains * 5;

	return (0);
}

/*
 * Core PFS allocator.  Used to allocate or reference the pmp structure
 * for PFS cluster mounts and the spmp structure for media (hmp) structures.
 */
static hammer2_pfs_t *
hammer2_pfsalloc(hammer2_chain_t *chain, const hammer2_inode_data_t *ripdata,
    hammer2_dev_t *force_local)
{
	hammer2_pfs_t *pmp = NULL;
	hammer2_inode_t *iroot;
	int i, j;

	KASSERTMSG(force_local, "only local mount allowed");

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
			    sizeof(pmp->pfs_clid)) == 0) {
				break;
			} else if (force_local && pmp->pfs_names[0] &&
			    strcmp(pmp->pfs_names[0], (const char *)ripdata->filename) == 0) {
				break;
			}
		}
	}

	if (pmp == NULL) {
		pmp = malloc(sizeof(*pmp), M_HAMMER2, M_WAITOK | M_ZERO);
		pmp->force_local = force_local;
		hammer2_spin_init(&pmp->inum_spin, "h2pmp_inosp");
		hammer2_spin_init(&pmp->lru_spin, "h2pmp_lrusp");
		hammer2_spin_init(&pmp->list_spin, "h2pmp_lssp");
		for (i = 0; i < HAMMER2_IHASH_SIZE; i++) {
			rw_init(&pmp->xop_lock[i], "h2pmp_xoplk");
			pmp->xop_cv[i] = kstrdup("h2pmp_xopcv");
			KKASSERT(i == 0 ||
			    (pmp->xop_cv[i] != pmp->xop_cv[i-1]));
		}
		rw_init(&pmp->trans_lock, "h2pmp_trlk");
		pmp->trans_cv = kstrdup("h2pmp_trcv");
		RB_INIT(&pmp->inum_tree);
		TAILQ_INIT(&pmp->syncq);
		TAILQ_INIT(&pmp->depq);
		TAILQ_INIT(&pmp->lru_list);

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
	 * When forcing local mode, mark the PFS as a MASTER regardless.
	 */
	hammer2_inode_ref(iroot);
	hammer2_mtx_ex(&iroot->lock);

	j = iroot->cluster.nchains; /* Currently always 0. */
	KASSERTMSG(j == 0, "nchains %d not 0", j);

	KKASSERT(chain->pmp == NULL);
	chain->pmp = pmp;
	hammer2_chain_ref(chain);
	iroot->cluster.array[j].chain = chain;
	if (force_local)
		pmp->pfs_types[j] = HAMMER2_PFSTYPE_MASTER;
	else
		pmp->pfs_types[j] = ripdata->meta.pfs_type;
	pmp->pfs_names[j] = kstrdup((const char *)ripdata->filename);
	pmp->pfs_hmps[j] = chain->hmp;
	hammer2_spin_ex(&pmp->inum_spin);
	pmp->pfs_iroot_blocksets[j] = chain->data->ipdata.u.blockset;
	hammer2_spin_unex(&pmp->inum_spin);

	/*
	 * If the PFS is already mounted we must account
	 * for the mount_count here.
	 */
	if (pmp->mp)
		++chain->hmp->mount_count;
	++j;

	iroot->cluster.nchains = j;
	hammer2_assert_cluster(&iroot->cluster);

	hammer2_mtx_unlock(&iroot->lock);
	hammer2_inode_drop(iroot);
done:
	return (pmp);
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

	/* Cleanup chains remaining on LRU list. */
	hammer2_spin_ex(&pmp->lru_spin);
	while ((chain = TAILQ_FIRST(&pmp->lru_list)) != NULL) {
		KKASSERT(chain->flags & HAMMER2_CHAIN_ONLRU);
		atomic_add_int(&pmp->lru_count, -1);
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_ONLRU);
		TAILQ_REMOVE(&pmp->lru_list, chain, entry);
		hammer2_chain_ref(chain);
		hammer2_spin_unex(&pmp->lru_spin);
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_RELEASE);
		hammer2_chain_drop(chain);
		hammer2_spin_ex(&pmp->lru_spin);
	}
	hammer2_spin_unex(&pmp->lru_spin);

	/* Clean up iroot. */
	iroot = pmp->iroot;
	if (iroot) {
		for (i = 0; i < iroot->cluster.nchains; ++i) {
			chain = iroot->cluster.array[i].chain;
			if (chain && !RB_EMPTY(&chain->core.rbtree))
				chains_still_present = 1;
		}
		KASSERTMSG(iroot->refs == 1,
		    "iroot inum %016jx refs %d not 1",
		    (intmax_t)iroot->meta.inum, iroot->refs);
		hammer2_inode_drop(iroot);
		pmp->iroot = NULL;
	}

	/* Free remaining pmp resources. */
	if (chains_still_present) {
		KKASSERT(pmp->mp);
		hprintf("PFS at %s still in use\n",
		    pmp->mp->mnt_stat.f_mntonname);
	} else {
		hammer2_spin_destroy(&pmp->inum_spin);
		hammer2_spin_destroy(&pmp->lru_spin);
		hammer2_spin_destroy(&pmp->list_spin);
		for (i = 0; i < HAMMER2_IHASH_SIZE; i++)
			kstrfree(pmp->xop_cv[i]);
		kstrfree(pmp->trans_cv);
		hashfree(pmp->ipdep_lists, HAMMER2_IHASH_SIZE, M_HAMMER2);
		if (pmp->fspec)
			free(pmp->fspec, M_HAMMER2, 0);
		free(pmp, M_HAMMER2, 0);
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
				kstrfree(pmp->pfs_names[i]);
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
	char devstr[MNAMELEN] = {0};
	char fnamestr[MNAMELEN] = {0};
	char *label = NULL;
	int i, error, devvp_found;
	size_t dlen;

	if (args == NULL) {
		hprintf("NULL args\n");
		return (EINVAL);
	}

	if (mp->mnt_flag & MNT_UPDATE) {
		pmp = MPTOPMP(mp);
		KASSERT(pmp);
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
		 * DragonFly uses either "BOOT", "ROOT" or "DATA" based
		 * on label[-1].  In OpenBSD, simply use "DATA" by default.
		 */
		label = __DECONST(char *, "DATA");
	} else {
		*label = '\0';
		label++;
	}

	debug_hprintf("device \"%s\" label \"%s\" rdonly %d\n",
	    devstr, label, (mp->mnt_flag & MNT_RDONLY) != 0);

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
	rw_enter_write(&hammer2_mntlk);
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
					rw_exit_write(&hammer2_mntlk);
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
			rw_exit_write(&hammer2_mntlk);
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
			rw_exit_write(&hammer2_mntlk);
			return (error);
		}

		/* Construct volumes and link with device vnodes. */
		hmp = malloc(sizeof(*hmp), M_HAMMER2, M_WAITOK | M_ZERO);
		hmp->devvp = NULL;
		error = hammer2_init_volumes(&devvpl, hmp->volumes,
		    &hmp->voldata, &hmp->volhdrno, &hmp->devvp);
		if (error) {
			hammer2_close_devvp(&devvpl, p);
			hammer2_cleanup_devvp(&devvpl);
			rw_exit_write(&hammer2_mntlk);
			free(hmp, M_HAMMER2, 0);
			return (error);
		}
		if (!hmp->devvp) {
			hprintf("failed to initialize root volume\n");
			hammer2_unmount_helper(mp, NULL, hmp);
			rw_exit_write(&hammer2_mntlk);
			hammer2_unmount(mp, MNT_FORCE, curproc);
			return (EINVAL);
		}

		hmp->hflags = args->hflags & HMNT2_DEVFLAGS;
		KKASSERT(hmp->hflags & HMNT2_LOCAL);

		TAILQ_INSERT_TAIL(&hammer2_mntlist, hmp, mntentry);
		RB_INIT(&hmp->iotree);
		hammer2_mtx_init(&hmp->iotree_lock, "h2hmp_iotlk");

		rw_init(&hmp->vollk, "h2vollk");
		rw_init(&hmp->bflk, "h2bflk");

		/*
		 * vchain setup.  vchain.data is embedded.
		 * vchain.refs is initialized and will never drop to 0.
		 */
		hmp->vchain.hmp = hmp;
		hmp->vchain.refs = 1;
		hmp->vchain.data = (void *)&hmp->voldata;
		hmp->vchain.bref.type = HAMMER2_BREF_TYPE_VOLUME;
		hmp->vchain.bref.data_off = 0 | HAMMER2_PBUFRADIX;
		hmp->vchain.bref.mirror_tid = hmp->voldata.mirror_tid;
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
		hmp->fchain.bref.mirror_tid = hmp->voldata.freemap_tid;
		hmp->fchain.bref.methods =
		    HAMMER2_ENC_CHECK(HAMMER2_CHECK_FREEMAP) |
		    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE);
		hammer2_chain_init(&hmp->fchain);

		/* Initialize volume header related fields. */
		KKASSERT(hmp->voldata.magic == HAMMER2_VOLUME_ID_HBO ||
		    hmp->voldata.magic == HAMMER2_VOLUME_ID_ABO);
		hmp->volsync = hmp->voldata;
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
			rw_exit_write(&hammer2_mntlk);
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
			rw_exit_write(&hammer2_mntlk);
			hammer2_unmount(mp, MNT_FORCE, curproc);
			return (EINVAL);
		}

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
		xop = pool_get(&hammer2_xops_pool, PR_WAITOK | PR_ZERO);
		hammer2_dummy_xop_from_chain(xop, schain);
		hammer2_inode_drop(spmp->iroot);
		spmp->iroot = hammer2_inode_get(spmp, xop, -1, -1);
		spmp->spmp_hmp = hmp;
		spmp->pfs_types[0] = ripdata->meta.pfs_type;
		spmp->pfs_hmps[0] = hmp;
		hammer2_inode_ref(spmp->iroot);
		hammer2_inode_unlock(spmp->iroot);
		hammer2_chain_unlock(schain);
		hammer2_chain_drop(schain);
		schain = NULL;
		pool_put(&hammer2_xops_pool, xop);
		/* Leave spmp->iroot with one ref. */
#ifdef INVARIANTS
		/*
		 * XXX rwlock(9) says "Callers must not recursively acquire
		 * read locks", so let's test it now.
		 */
		hammer2_mtx_sh(&spmp->iroot->lock);
		hammer2_mtx_sh(&spmp->iroot->lock);
		/* Recursively acquired read lock. */
		hammer2_mtx_unlock(&spmp->iroot->lock);
		hammer2_mtx_unlock(&spmp->iroot->lock);
#endif
		/*
		 * A false-positive lock order reversal may be detected.
		 * There are 2 directions of locking, which is a bad design.
		 * chain is locked -> hammer2_inode_get() -> lock inode
		 * inode is locked -> hammer2_inode_chain() -> lock chain
		 */
		hammer2_update_pmps(hmp);
	} else {
		/* hmp->devvp_list is already constructed. */
		hammer2_cleanup_devvp(&devvpl);
		spmp = hmp->spmp;
		/* XXX OpenBSD HAMMER2 always has HMNT2_LOCAL set, so ignore.
		if (args->hflags & HMNT2_DEVFLAGS)
			hprintf("WARNING: mount flags pertaining to the whole "
			    "device may only be specified on the first mount "
			    "of the device: %08x\n",
			    args->hflags & HMNT2_DEVFLAGS);
		*/
	}

	/*
	 * Force local mount (disassociate all PFSs from their clusters)
	 * if HMNT2_LOCAL.
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
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
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
		rw_exit_write(&hammer2_mntlk);
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
		rw_exit_write(&hammer2_mntlk);
		hammer2_unmount(mp, MNT_FORCE, curproc);
		return (EINVAL);
	}

	if (pmp->mp) {
		hprintf("PFS already mounted!\n");
		hammer2_unmount_helper(mp, NULL, hmp);
		rw_exit_write(&hammer2_mntlk);
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
	rw_exit_write(&hammer2_mntlk);

	/* Initial statfs to prime mnt_stat. */
	hammer2_statfs(mp, &mp->mnt_stat, p);

	/* Keep devstr string in PFS mount. */
	dlen = strlen(devstr) + strlen(label) + 1 + 1;
	pmp->fspec = malloc(dlen, M_HAMMER2, M_WAITOK | M_ZERO);
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
	 * Force local mount (disassociate all PFSs from their clusters)
	 * if HMNT2_LOCAL.
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
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
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

	KKASSERT(pmp->mp);
	KKASSERT(pmp->iroot);

	rw_enter_write(&hammer2_mntlk);

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;
	error = vflush(mp, NULLVP, flags);
	if (error) {
		hprintf("vflush failed %d\n", error);
		goto failed;
	}

	hammer2_unmount_helper(mp, pmp, NULL);
failed:
	rw_exit_write(&hammer2_mntlk);

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
		//pmp->mp = NULL; /* still uses pmp->mp->mnt_stat */
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

	hammer2_pfsfree_scan(hmp, 0);
	hammer2_pfsfree_scan(hmp, 1);
	KKASSERT(hmp->spmp == NULL);

	/* Finish up with the device vnode. */
	if (!TAILQ_EMPTY(&hmp->devvp_list)) {
		hammer2_close_devvp(&hmp->devvp_list, NULL);
		hammer2_cleanup_devvp(&hmp->devvp_list);
	}
	KKASSERT(TAILQ_EMPTY(&hmp->devvp_list));
#ifdef INVARIANTS
	hammer2_dump_chain(&hmp->vchain, 0, 0, -1, 'v');
	hammer2_dump_chain(&hmp->fchain, 0, 0, -1, 'f');
	/*
	 * Final drop of embedded volume/freemap root chain to clean up
	 * [vf]chain.core ([vf]chain structure is not flagged ALLOCATED so
	 * it is cleaned out and then left to rot).
	 */
	hammer2_chain_drop(&hmp->vchain);
	hammer2_chain_drop(&hmp->fchain);
#endif
	hammer2_mtx_ex(&hmp->iotree_lock);
	hammer2_io_cleanup(hmp, &hmp->iotree);
	if (hmp->iofree_count)
		debug_hprintf("%d I/O's left hanging\n", hmp->iofree_count);
	hammer2_mtx_unlock(&hmp->iotree_lock);

	TAILQ_REMOVE(&hammer2_mntlist, hmp, mntentry);
	hammer2_mtx_destroy(&hmp->iotree_lock);

	hammer2_print_iostat(&hmp->iostat_read, "read");
	hammer2_print_iostat(&hmp->iostat_write, "write");

	free(hmp, M_HAMMER2, 0);
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
hammer2_vfs_sync_pmp(hammer2_pfs_t *pmp, int waitfor)
{
	hammer2_inode_t *ip;
	hammer2_depend_t *depend, *depend_next;
	struct vnode *vp;
	uint32_t pass2;
	int error, dorestart;

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
		vp = ip->vp;
		if (vp) {
			vref(vp);
			if (vn_lock(vp, LK_EXCLUSIVE | LK_NOWAIT)) {
				/*
				 * Failed to get the vnode, requeue the inode
				 * (PASS2 is already set so it will be found
				 * again on the restart).
				 *
				 * Then unlock, possibly sleep, and retry
				 * later.  We sleep if PASS2 was *previously*
				 * set, before we set it again above.
				 */
				vrele(vp);
				vp = NULL;
				dorestart = 1;
				debug_hprintf("inum %016jx vn_lock failed\n",
				    (intmax_t)ip->meta.inum);
				hammer2_inode_delayed_sideq(ip);

				hammer2_mtx_unlock(&ip->lock);
				hammer2_inode_drop(ip);

				if (pass2 & HAMMER2_INODE_SYNCQ_PASS2)
					tsleep(&dorestart, 0, "h2syndel", 2);
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
			dorestart = 1;
			hammer2_spin_ex(&pmp->list_spin);
			continue;
		}

		/*
		 * Ok we have the inode exclusively locked and if vp is
		 * not NULL that will also be exclusively locked.  Do the
		 * meat of the flush.
		 *
		 * vp token needed for v_rbdirty_tree check / vclrisdirty
		 * sequencing.  Though we hold the vnode exclusively so
		 * we shouldn't need to hold the token also in this case.
		 */
		if (vp) {
			/* XXX vnode */
			//vfsync(vp, MNT_WAIT, 1, NULL, NULL);
			//bio_track_wait(&vp->v_track_write, 0, 0); /* XXX */
		}

		/*
		 * If the inode has not yet been inserted into the tree
		 * we must do so.  Then sync and flush it.  The flush should
		 * update the parent.
		 */
		if (ip->flags & HAMMER2_INODE_DELETING) {
			debug_hprintf("inum %016jx destroy\n",
			    (intmax_t)ip->meta.inum);
			KKASSERT(0); /* XXX vnode */
		} else if (ip->flags & HAMMER2_INODE_CREATING) {
			debug_hprintf("inum %016jx insert\n",
			    (intmax_t)ip->meta.inum);
			KKASSERT(0); /* XXX vnode */
		}
		debug_hprintf("inum %016jx chain-sync\n",
		    (intmax_t)ip->meta.inum);

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
		hammer2_inode_chain_sync(ip);
		if (ip == pmp->iroot)
			hammer2_inode_chain_flush(ip, HAMMER2_XOP_INODE_STOP);
		else
			hammer2_inode_chain_flush(ip,
			    HAMMER2_XOP_INODE_STOP | HAMMER2_XOP_FSSYNC);
		if (vp) {
			/* XXX vnode */
			vput(vp);
			vrele(vp); /* from hammer2_inode_delayed_sideq() */
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

/*
 * Volume header data locks.
 */
void
hammer2_voldata_lock(hammer2_dev_t *hmp)
{
	rw_enter_write(&hmp->vollk);
}

void
hammer2_voldata_unlock(hammer2_dev_t *hmp)
{
	rw_exit_write(&hmp->vollk);
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
		atomic_add_long(&hammer2_count_modified_chains, 1);
		atomic_set_int(&hmp->vchain.flags, HAMMER2_CHAIN_MODIFIED);
		hmp->vchain.bref.mirror_tid = hmp->voldata.mirror_tid + 1;
	}
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
		error = hammer2_igetv(mp, ip, vpp);
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
		error = hammer2_igetv(mp, ip, vpp);
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
			debug_hprintf("PFS nextino %016jx mod %016jx\n",
			    (intmax_t)pmp->inode_tid, (intmax_t)pmp->modify_tid);

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
		error = hammer2_igetv(mp, pmp->iroot, vpp);
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
	hammer2_cluster_t *cluster;
	hammer2_chain_t *chain;

	KKASSERT(mp->mnt_stat.f_iosize > 0);
	KKASSERT(mp->mnt_stat.f_bsize > 0);

	hmp = pmp->pfs_hmps[0];
	if (hmp == NULL)
		return (EINVAL);

	cluster = &pmp->iroot->cluster;
	hammer2_assert_cluster(cluster);

	chain = cluster->array[0].chain;

	sbp->f_bsize = mp->mnt_stat.f_bsize;
	sbp->f_iosize = mp->mnt_stat.f_iosize;
	sbp->f_blocks = hmp->voldata.allocator_size / mp->mnt_stat.f_bsize;
	sbp->f_bfree = hmp->voldata.allocator_free / mp->mnt_stat.f_bsize;
	sbp->f_bavail = sbp->f_bfree;
	sbp->f_files = chain ? chain->bref.embed.stats.inode_count : 0;
	sbp->f_ffree = 0;
	sbp->f_favail = 0;
	copy_statfs_info(sbp, mp);

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

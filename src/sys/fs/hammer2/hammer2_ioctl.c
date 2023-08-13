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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/buf.h>
#include <sys/dkio.h>
#include <sys/disklabel.h>

#include "hammer2.h"
#include "hammer2_ioctl.h"
#include "hammer2_mount.h"

#if 0
/*
 * Return 1 if read-only mounted otherwise 0.  DragonFly allows bwrite(9)
 * against a read-only mounted device, but FreeBSD does not.
 */
static int
hammer2_is_rdonly(const struct mount *mp)
{
	if (mp->mnt_flag & MNT_RDONLY) {
		hprintf("PFS read-only mounted\n");
		return (1);
	}

	return (0);
}
#endif

/*
 * Retrieve ondisk version.
 */
static int
hammer2_ioctl_version_get(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_version_t *v = data;
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];

	if (hmp == NULL)
		return (EINVAL);

	if (hmp)
		v->version = hmp->voldata.version;
	else
		v->version = -1;

	return (0);
}

/*
 * Used to scan and retrieve PFS information.  PFS's are directories under
 * the super-root.
 *
 * To scan PFSs pass name_key=0.  The function will scan for the next
 * PFS and set all fields, as well as set name_next to the next key.
 * When no PFSs remain, name_next is set to (hammer2_key_t)-1.
 *
 * To retrieve a particular PFS by key, specify the key but note that
 * the ioctl will return the lowest key >= specified_key, so the caller
 * must verify the key.
 *
 * To retrieve the PFS associated with the file descriptor, pass
 * name_key set to (hammer2_key_t)-1.
 */
static int
hammer2_ioctl_pfs_get(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_pfs_t *pfs = data;
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];
	const hammer2_inode_data_t *ripdata;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t key_next, save_key;
	int error = 0;

	if (hmp == NULL)
		return (EINVAL);

	save_key = pfs->name_key;

	if (save_key == (hammer2_key_t)-1) {
		hammer2_inode_lock(ip->pmp->iroot, 0);
		parent = NULL;
		chain = hammer2_inode_chain(ip->pmp->iroot, 0,
		    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	} else {
		hammer2_inode_lock(hmp->spmp->iroot, 0);
		parent = hammer2_inode_chain(hmp->spmp->iroot, 0,
		    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
		chain = hammer2_chain_lookup(&parent, &key_next, pfs->name_key,
		    HAMMER2_KEY_MAX, &error, HAMMER2_LOOKUP_SHARED);
	}

	/* Locate next PFS. */
	while (chain) {
		if (chain->bref.type == HAMMER2_BREF_TYPE_INODE)
			break;
		if (parent == NULL) {
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
			chain = NULL;
			break;
		}
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    HAMMER2_KEY_MAX, &error, HAMMER2_LOOKUP_SHARED);
	}
	error = hammer2_error_to_errno(error);

	/* Load the data being returned by the ioctl. */
	if (chain && chain->error == 0) {
		ripdata = &chain->data->ipdata;
		pfs->name_key = ripdata->meta.name_key;
		pfs->pfs_type = ripdata->meta.pfs_type;
		pfs->pfs_subtype = ripdata->meta.pfs_subtype;
		pfs->pfs_clid = ripdata->meta.pfs_clid;
		pfs->pfs_fsid = ripdata->meta.pfs_fsid;
		KKASSERT(ripdata->meta.name_len < sizeof(pfs->name));
		bcopy(ripdata->filename, pfs->name, ripdata->meta.name_len);
		pfs->name[ripdata->meta.name_len] = 0;

		/*
		 * Calculate name_next, if any.  We are only accessing
		 * chain->bref so we can ignore chain->error (if the key
		 * is used later it will error then).
		 */
		if (parent == NULL) {
			pfs->name_next = (hammer2_key_t)-1;
		} else {
			chain = hammer2_chain_next(&parent, chain, &key_next,
			    key_next, HAMMER2_KEY_MAX, &error,
			    HAMMER2_LOOKUP_SHARED);
			if (chain)
				pfs->name_next = chain->bref.key;
			else
				pfs->name_next = (hammer2_key_t)-1;
		}
	} else {
		pfs->name_next = (hammer2_key_t)-1;
		error = ENOENT;
	}

	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}

	if (save_key == (hammer2_key_t)-1)
		hammer2_inode_unlock(ip->pmp->iroot);
	else
		hammer2_inode_unlock(hmp->spmp->iroot);

	return (error);
}

/*
 * Find a specific PFS by name.
 */
static int
hammer2_ioctl_pfs_lookup(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_pfs_t *pfs = data;
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];
	const hammer2_inode_data_t *ripdata;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t key_next, lhc;
	size_t len;
	int error = 0;

	if (hmp == NULL)
		return (EINVAL);

	hammer2_inode_lock(hmp->spmp->iroot, HAMMER2_RESOLVE_SHARED);
	parent = hammer2_inode_chain(hmp->spmp->iroot, 0,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);

	pfs->name[sizeof(pfs->name) - 1] = 0;
	len = strlen(pfs->name);
	lhc = hammer2_dirhash(pfs->name, len);

	chain = hammer2_chain_lookup(&parent, &key_next, lhc,
	    lhc + HAMMER2_DIRHASH_LOMASK, &error, HAMMER2_LOOKUP_SHARED);
	while (chain) {
		if (hammer2_chain_dirent_test(chain, pfs->name, len))
			break;
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    lhc + HAMMER2_DIRHASH_LOMASK, &error,
		    HAMMER2_LOOKUP_SHARED);
	}
	error = hammer2_error_to_errno(error);

	/* Load the data being returned by the ioctl. */
	if (chain && chain->error == 0) {
		KKASSERT(chain->bref.type == HAMMER2_BREF_TYPE_INODE);
		ripdata = &chain->data->ipdata;
		pfs->name_key = ripdata->meta.name_key;
		pfs->pfs_type = ripdata->meta.pfs_type;
		pfs->pfs_subtype = ripdata->meta.pfs_subtype;
		pfs->pfs_clid = ripdata->meta.pfs_clid;
		pfs->pfs_fsid = ripdata->meta.pfs_fsid;

		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	} else if (error == 0) {
		error = ENOENT;
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}

	hammer2_inode_unlock(hmp->spmp->iroot);

	return (error);
}

/*
 * Retrieve the raw inode structure, non-inclusive of node-specific data.
 */
static int
hammer2_ioctl_inode_get(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_inode_t *ino = data;

	hammer2_inode_lock(ip, HAMMER2_RESOLVE_SHARED);

	ino->data_count = hammer2_inode_data_count(ip);
	ino->inode_count = hammer2_inode_inode_count(ip);
	bzero(&ino->ip_data, sizeof(ino->ip_data));
	ino->ip_data.meta = ip->meta;

	hammer2_inode_unlock(ip);

	return (0);
}

/*
 * Recursively dump chains of a given inode.
 */
static int
hammer2_ioctl_debug_dump(hammer2_inode_t *ip, unsigned int flags)
{
#ifdef INVARIANTS
	hammer2_chain_t *chain;
	int i, count = 100000;

	for (i = 0; i < ip->cluster.nchains; ++i) {
		chain = ip->cluster.array[i].chain;
		if (chain) {
			hprintf("cluster #%d\n", i);
			hammer2_dump_chain(chain, 0, 0, &count, 'i', flags);
		}
	}

	return (0);
#else
	return (EOPNOTSUPP);
#endif
}

/*
 * Turn on or off emergency mode on a filesystem.
 */
static int
hammer2_ioctl_emerg_mode(hammer2_inode_t *ip, u_int mode)
{
	hammer2_pfs_t *pmp = ip->pmp;
	hammer2_dev_t *hmp;
	int i;

	if (mode) {
		hprintf("WARNING: Emergency mode enabled\n");
		atomic_set_int(&pmp->flags, HAMMER2_PMPF_EMERG);
	} else {
		hprintf("WARNING: Emergency mode disabled\n");
		atomic_clear_int(&pmp->flags, HAMMER2_PMPF_EMERG);
	}

	for (i = 0; i < HAMMER2_MAXCLUSTER; ++i) {
		hmp = pmp->pfs_hmps[i];
		if (hmp == NULL)
			continue;
		if (mode)
			atomic_set_int(&hmp->hflags, HMNT2_EMERG);
		else
			atomic_clear_int(&hmp->hflags, HMNT2_EMERG);
	}

	return (0);
}

/*
 * Do a bulkfree scan on media related to the PFS.  This routine will
 * flush all PFSs associated with the media before doing the bulkfree
 * scan.
 *
 * This version can only run on non-clustered media.  A new ioctl or a
 * temporary mount of @LOCAL will be needed to run on clustered media.
 */
static int
hammer2_ioctl_bulkfree_scan(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_bulkfree_t *bfi = data;
	hammer2_dev_t *hmp;
	hammer2_pfs_t *pmp;
	hammer2_chain_t *vchain;
	int error = 0, didsnap, etmp, i;

	ip = ip->pmp->iroot;

	hmp = ip->pmp->pfs_hmps[0];
	if (hmp == NULL)
		return (EINVAL);
	if (bfi == NULL)
		return (EINVAL);

	/*
	 * Bulkfree has to be serialized to guarantee at least one sync
	 * inbetween bulkfrees.
	 */
	rw_enter_write(&hmp->bflk);

	/* Sync all mounts related to the media. */
	rw_enter_write(&hammer2_mntlk);
	TAILQ_FOREACH(pmp, &hammer2_pfslist, mntentry) {
		for (i = 0; i < HAMMER2_MAXCLUSTER; ++i) {
			if (pmp->pfs_hmps[i] != hmp)
				continue;
			etmp = hammer2_vfs_sync_pmp(pmp, MNT_WAIT);
			if (etmp && (error == 0 || error == ENOSPC))
				error = etmp;
			break;
		}
	}
	rw_exit_write(&hammer2_mntlk);

	if (error && error != ENOSPC)
		goto failed;

	/*
	 * If we have an ENOSPC error we have to bulkfree on the live
	 * topology.  Otherwise we can bulkfree on a snapshot.
	 */
	if (error) {
		hprintf("WARNING: bulkfree forced to use live topology due to "
		    "ENOSPC\n");
		vchain = &hmp->vchain;
		hammer2_chain_ref(vchain);
		didsnap = 0;
	} else {
		vchain = hammer2_chain_bulksnap(hmp);
		didsnap = 1;
	}

	/*
	 * Normal bulkfree operations do not require a transaction because
	 * they operate on a snapshot, and so can run concurrently with
	 * any operation except another bulkfree.
	 *
	 * If we are running bulkfree on the live topology we have to be
	 * in a FLUSH transaction.
	 */
	if (didsnap == 0)
		hammer2_trans_init(hmp->spmp, HAMMER2_TRANS_ISFLUSH);

	error = hammer2_bulkfree_pass(hmp, vchain, bfi);
	if (didsnap) {
		hammer2_chain_bulkdrop(vchain);
	} else {
		hammer2_chain_drop(vchain);
		hammer2_trans_done(hmp->spmp, HAMMER2_TRANS_ISFLUSH |
		    HAMMER2_TRANS_SIDEQ);
	}
	error = hammer2_error_to_errno(error);

failed:
	rw_exit_write(&hmp->bflk);
	return (error);
}

/*
 * Grow a filesystem into its partition size.
 */
static int
hammer2_ioctl_growfs(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_growfs_t *grow = data;
	hammer2_dev_t *hmp;
	hammer2_off_t size, delta;
	hammer2_tid_t mtid;
	struct disklabel dl;
	struct buf *bp;
	int i, error;
	daddr_t blkno;

	hmp = ip->pmp->pfs_hmps[0];
	if (hmp == NULL)
		return (EINVAL);

	if (hmp->nvolumes > 1) {
		hprintf("growfs currently unsupported with multiple volumes\n");
		return (EOPNOTSUPP);
	}
	KKASSERT(hmp->total_size == hmp->voldata.volu_size);

	/* Get media size. */
	error = VOP_IOCTL(hmp->devvp, DIOCGDINFO, &dl, FREAD, FSCRED, curproc);
	if (error) {
		hprintf("failed to get media size\n");
		return (error);
	}
	size = (hammer2_off_t)dl.d_secperunit * dl.d_secsize;
	hprintf("growfs partition-auto to %016jx\n", (intmax_t)size);

	/* Expand to devvp size unless specified. */
	grow->modified = 0;
	if (grow->size == 0) {
		grow->size = size;
	} else if (grow->size > size) {
		hprintf("growfs size %016jx exceeds device size %016jx\n",
		    (intmax_t)grow->size, (intmax_t)size);
		return (EINVAL);
	}

	/*
	 * This is typically ~8MB alignment to avoid edge cases accessing
	 * reserved blocks at the base of each 2GB zone.
	 */
	grow->size &= ~HAMMER2_VOLUME_ALIGNMASK64;
	delta = grow->size - hmp->voldata.volu_size;

	/* Maximum allowed size is 2^63. */
	if (grow->size > 0x7FFFFFFFFFFFFFFFLU) {
		hprintf("growfs failure, limit is 2^63 - 1 bytes\n");
		return (EINVAL);
	}

	/* We can't shrink a filesystem. */
	if (grow->size < hmp->voldata.volu_size) {
		hprintf("growfs failure, would shrink from %016jx to %016jx\n",
		    (intmax_t)hmp->voldata.volu_size, (intmax_t)grow->size);
		return (EINVAL);
	}

	if (delta == 0) {
		hprintf("growfs - size did not change\n");
		return (0);
	}

	/*
	 * Clear any new volume header backups that we extend into.
	 * Skip volume headers that are already part of the filesystem.
	 */
	for (i = 0; i < HAMMER2_NUM_VOLHDRS; ++i) {
		if (i * HAMMER2_ZONE_BYTES64 < hmp->voldata.volu_size)
			continue;
		if (i * HAMMER2_ZONE_BYTES64 >= grow->size)
			break;
		hprintf("growfs - clear volhdr %d\n", i);
		blkno = i * HAMMER2_ZONE_BYTES64 / DEV_BSIZE;
		error = bread(hmp->devvp, blkno, HAMMER2_VOLUME_BYTES, &bp);
		if (error) {
			brelse(bp);
			hprintf("I/O error %d\n", error);
			return (EINVAL);
		}
		bzero(bp->b_data, HAMMER2_VOLUME_BYTES);
		error = bwrite(bp);
		if (error) {
			hprintf("I/O error %d\n", error);
			return (EINVAL);
		}
	}

	hammer2_trans_init(hmp->spmp, HAMMER2_TRANS_ISFLUSH);
	mtid = hammer2_trans_sub(hmp->spmp);

	hprintf("growfs - expand by %016jx to %016jx mtid %016jx\n",
	    (intmax_t)delta, (intmax_t)grow->size, (intmax_t)mtid);

	hammer2_voldata_lock(hmp);
	hammer2_voldata_modify(hmp);

	/*
	 * NOTE: Just adjusting total_size for a single-volume filesystem
	 *	 or for the last volume in a multi-volume filesystem, is
	 *	 fine.  But we can't grow any other partition in a multi-volume
	 *	 filesystem.  For now we just punt (at the top) on any
	 *	 multi-volume filesystem.
	 */
	hmp->voldata.volu_size = grow->size;
	hmp->voldata.total_size += delta;
	hmp->voldata.allocator_size += delta;
	hmp->voldata.allocator_free += delta;
	hmp->total_size += delta;
	hmp->volumes[0].size += delta; /* note: indexes first (only) volume */

	hammer2_voldata_unlock(hmp);

	hammer2_trans_done(hmp->spmp,
	    HAMMER2_TRANS_ISFLUSH | HAMMER2_TRANS_SIDEQ);
	grow->modified = 1;

	/*
	 * Flush the mess right here and now.  We could just let the
	 * filesystem syncer do it, but this was a sensitive operation
	 * so don't take any chances.
	 */
	hammer2_vfs_sync(ip->pmp->mp, MNT_WAIT);

	return (0);
}

/*
 * Get a list of volumes.
 */
static int
hammer2_ioctl_volume_list(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_volume_list_t *vollist = data;
	hammer2_ioc_volume_t entry;
	hammer2_volume_t *vol;
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];
	int i, error = 0, cnt = 0;

	if (hmp == NULL)
		return (EINVAL);

	for (i = 0; i < hmp->nvolumes; ++i) {
		if (cnt >= vollist->nvolumes)
			break;
		vol = &hmp->volumes[i];
		bzero(&entry, sizeof(entry));
		/* Copy hammer2_volume_t fields. */
		entry.id = vol->id;
		bcopy(vol->dev->path, entry.path, sizeof(entry.path));
		entry.offset = vol->offset;
		entry.size = vol->size;
		error = copyout(&entry, &vollist->volumes[cnt], sizeof(entry));
		if (error)
			return (error);
		cnt++;
	}
	vollist->nvolumes = cnt;
	vollist->version = hmp->voldata.version;
	bcopy(ip->pmp->pfs_names[0], vollist->pfs_name,
	    sizeof(vollist->pfs_name));

	return (error);
}

int
hammer2_ioctl_impl(hammer2_inode_t *ip, unsigned long com, void *data,
    int fflag, struct ucred *cred)
{
	int error;

	switch (com) {
	case HAMMER2IOC_VERSION_GET:
		error = hammer2_ioctl_version_get(ip, data);
		break;
	case HAMMER2IOC_PFS_GET:
		error = hammer2_ioctl_pfs_get(ip, data);
		break;
	case HAMMER2IOC_PFS_LOOKUP:
		error = hammer2_ioctl_pfs_lookup(ip, data);
		break;
	case HAMMER2IOC_INODE_GET:
		error = hammer2_ioctl_inode_get(ip, data);
		break;
	case HAMMER2IOC_DEBUG_DUMP:
		error = hammer2_ioctl_debug_dump(ip, *(unsigned int *)data);
		break;
	case HAMMER2IOC_EMERG_MODE:
		error = hammer2_ioctl_emerg_mode(ip, *(unsigned int *)data);
		break;
	case HAMMER2IOC_BULKFREE_SCAN:
		error = hammer2_ioctl_bulkfree_scan(ip, data);
		break;
	case HAMMER2IOC_GROWFS:
		error = hammer2_ioctl_growfs(ip, data);
		break;
	case HAMMER2IOC_VOLUME_LIST:
		error = hammer2_ioctl_volume_list(ip, data);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

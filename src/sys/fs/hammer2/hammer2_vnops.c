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

#include "hammer2.h"

#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/specdev.h>

#include <miscfs/fifofs/fifo.h>

#ifdef DIAGNOSTIC
extern int prtactive;
#endif

static int
hammer2_inactive(void *v)
{
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		struct proc *a_p;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

#ifdef DIAGNOSTIC
	if (prtactive && vp->v_usecount != 0)
		vprint("hammer2_inactive: pushing active", vp);
#endif
	VOP_UNLOCK(vp);

	if (ip->meta.mode == 0) {
		/*
		 * If we are done with the inode, reclaim it
		 * so that it can be reused immediately.
		 */
		vrecycle(vp, ap->a_p);
	}

	return (0);
}

static int
hammer2_reclaim(void *v)
{
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
		struct proc *a_p;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_dev_t *hmp;
	hammer2_devvp_t *e;
	hammer2_inode_t *ip = VTOI(vp);

#ifdef DIAGNOSTIC
	if (prtactive && vp->v_usecount != 0)
		vprint("hammer2_reclaim: pushing active", vp);
#endif
	/*
	 * Purge old data structures associated with the inode.
	 */
	cache_purge(vp);

	hmp = ip->pmp->pfs_hmps[0];
	KASSERT(hmp);
	TAILQ_FOREACH(e, &hmp->devvp_list, entry)
		vrele(e->devvp);

	vp->v_data = NULL;
	ip->vp = NULL;

	hammer2_inode_drop(ip);

	return (0);
}

static int
hammer2_access(void *v)
{
	struct vop_access_args /* {
		struct vnode *a_vp;
		int a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	return (vaccess(vp->v_type, ip->meta.mode & ALLPERMS,
	    hammer2_to_unix_xid(&ip->meta.uid),
	    hammer2_to_unix_xid(&ip->meta.gid),
	    ap->a_mode, ap->a_cred));
}

static int
hammer2_getattr(void *v)
{
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	hammer2_inode_t *ip = VTOI(vp);
	hammer2_pfs_t *pmp = ip->pmp;

	vap->va_fsid = pmp->mp->mnt_stat.f_fsid.val[0];
	vap->va_fileid = ip->meta.inum;
	vap->va_mode = ip->meta.mode;
	vap->va_nlink = ip->meta.nlinks;
	vap->va_uid = hammer2_to_unix_xid(&ip->meta.uid);
	vap->va_gid = hammer2_to_unix_xid(&ip->meta.gid);
	vap->va_rdev = NODEV;
	vap->va_size = ip->meta.size;
	vap->va_flags = ip->meta.uflags;
	hammer2_time_to_timespec(ip->meta.ctime, &vap->va_ctime);
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_mtime);
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_atime);
	vap->va_gen = 1;
	vap->va_blocksize = vp->v_mount->mnt_stat.f_iosize;
	if (ip->meta.type == HAMMER2_OBJTYPE_DIRECTORY) {
		/*
		 * Can't really calculate directory use sans the files under
		 * it, just assume one block for now.
		 */
		vap->va_bytes = HAMMER2_INODE_BYTES;
	} else {
		vap->va_bytes = hammer2_inode_data_count(ip);
	}
	vap->va_type = hammer2_get_vtype(ip->meta.type);
	vap->va_filerev = 0;

	return (0);
}

static int
hammer2_setattr(void *v)
{
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;

	if (vap->va_type != VNON
	    || vap->va_nlink != (nlink_t)VNOVAL
	    || vap->va_fsid != (dev_t)VNOVAL
	    || vap->va_fileid != (ino_t)VNOVAL
	    || vap->va_blocksize != (long)VNOVAL
	    || vap->va_rdev != (dev_t)VNOVAL
	    || vap->va_bytes != (u_quad_t)VNOVAL
	    || vap->va_gen != (u_long)VNOVAL
	    || vap->va_flags != (u_long)VNOVAL
	    || vap->va_uid != (uid_t)VNOVAL
	    || vap->va_gid != (gid_t)VNOVAL
	    || vap->va_atime.tv_sec != (time_t)VNOVAL
	    || vap->va_mtime.tv_sec != (time_t)VNOVAL
	    || vap->va_mode != (mode_t)VNOVAL)
		return (EROFS);

	if (vap->va_size != (u_quad_t)VNOVAL) {
		switch (vp->v_type) {
		case VDIR:
			return (EISDIR);
		case VLNK:
		case VREG:
			return (EROFS);
		case VCHR:
		case VBLK:
		case VSOCK:
		case VFIFO:
			return (0);
		default:
			return (EINVAL);
		}
	}

	return (EINVAL);
}

static int
hammer2_write_dirent(struct uio *uio, ino_t d_fileno, uint8_t d_type,
    uint16_t d_namlen, const char *d_name, int *errorp)
{
	struct dirent dirent;

	bzero(&dirent, sizeof(dirent));
	dirent.d_fileno = d_fileno;
	dirent.d_type = d_type;
	dirent.d_namlen = d_namlen;
	dirent.d_reclen = DIRENT_SIZE(&dirent);
	if (dirent.d_reclen > uio->uio_resid)
		return (1); /* uio has no space left, end this readdir */
	dirent.d_off = uio->uio_offset + dirent.d_reclen;
	bcopy(d_name, dirent.d_name, d_namlen);

	*errorp = uiomove(&dirent, dirent.d_reclen, uio);

	return (0); /* uio has space left */
}

static int
hammer2_readdir(void *v)
{
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
		int *a_eofflag;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;

	hammer2_xop_readdir_t *xop;
	hammer2_inode_t *ip = VTOI(vp);
	const hammer2_inode_data_t *ripdata;
	hammer2_blockref_t bref;
	hammer2_tid_t inum;
	off_t saveoff = uio->uio_offset;
	int r, dtype, eofflag = 0, error = 0;
	uint16_t namlen;
	const char *dname;

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	hammer2_inode_lock(ip, HAMMER2_RESOLVE_SHARED);

	/*
	 * Handle artificial entries.  To ensure that only positive 64 bit
	 * quantities are returned to userland we always strip off bit 63.
	 * The hash code is designed such that codes 0x0000-0x7FFF are not
	 * used, allowing us to use these codes for articial entries.
	 *
	 * Entry 0 is used for '.' and entry 1 is used for '..'.  Do not
	 * allow '..' to cross the mount point into (e.g.) the super-root.
	 */
	if (saveoff == 0) {
		inum = ip->meta.inum & HAMMER2_DIRHASH_USERMSK;
		r = hammer2_write_dirent(uio, inum, DT_DIR, 1, ".", &error);
		if (r)
			goto done;
		++saveoff;
	}
	if (error)
		goto done;

	if (saveoff == 1) {
		inum = ip->meta.inum & HAMMER2_DIRHASH_USERMSK;
		if (ip != ip->pmp->iroot)
			inum = ip->meta.iparent & HAMMER2_DIRHASH_USERMSK;
		r = hammer2_write_dirent(uio, inum, DT_DIR, 2, "..", &error);
		if (r)
			goto done;
		++saveoff;
	}
	if (error)
		goto done;

	/* Use XOP for remaining entries. */
	xop = hammer2_xop_alloc(ip, 0);
	xop->lkey = saveoff | HAMMER2_DIRHASH_VISIBLE;
	hammer2_xop_start(&xop->head, &hammer2_readdir_desc);

	for (;;) {
		error = hammer2_xop_collect(&xop->head, 0);
		error = hammer2_error_to_errno(error);
		if (error)
			break;
		hammer2_cluster_bref(&xop->head.cluster, &bref);

		if (bref.type == HAMMER2_BREF_TYPE_INODE) {
			ripdata = &hammer2_xop_gdata(&xop->head)->ipdata;
			dtype = hammer2_get_dtype(ripdata->meta.type);
			saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
			r = hammer2_write_dirent(uio,
			    ripdata->meta.inum & HAMMER2_DIRHASH_USERMSK,
			    dtype, ripdata->meta.name_len, ripdata->filename,
			    &error);
			hammer2_xop_pdata(&xop->head);
			if (r)
				break;
		} else if (bref.type == HAMMER2_BREF_TYPE_DIRENT) {
			dtype = hammer2_get_dtype(bref.embed.dirent.type);
			saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
			namlen = bref.embed.dirent.namlen;
			if (namlen <= sizeof(bref.check.buf))
				dname = bref.check.buf;
			else
				dname = hammer2_xop_gdata(&xop->head)->buf;
			r = hammer2_write_dirent(uio, bref.embed.dirent.inum,
			    dtype, namlen, dname, &error);
			if (namlen > sizeof(bref.check.buf))
				hammer2_xop_pdata(&xop->head);
			if (r)
				break;
		} else {
			/* XXX chain error */
			hprintf("bad blockref type %d\n", bref.type);
		}
	}
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	if (error == ENOENT) {
		error = 0;
		eofflag = 1;
		saveoff = (hammer2_key_t)-1;
	} else {
		saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
	}
done:
	hammer2_inode_unlock(ip);

	if (ap->a_eofflag)
		*ap->a_eofflag = eofflag;
	/*
	 * XXX uio_offset value of 0x7fffffffffffffff known to not work with
	 * some user space libraries on 32 bit platforms.
	 */
	uio->uio_offset = saveoff & ~HAMMER2_DIRHASH_VISIBLE;

	return (error);
}

/*
 * Perform read operations on a file or symlink given an unlocked
 * inode and uio.
 */
static int
hammer2_read_file(hammer2_inode_t *ip, struct uio *uio, int ioflag)
{
	struct buf *bp;
	hammer2_off_t isize = ip->meta.size;
	hammer2_key_t lbase;
	daddr_t lbn;
	size_t n;
	int lblksize, loff, error = 0;

	while (uio->uio_resid > 0 && (hammer2_off_t)uio->uio_offset < isize) {
		lblksize = hammer2_calc_logical(ip, uio->uio_offset, &lbase,
		    NULL);
		lbn = lbase / lblksize;
		bp = NULL;

		if ((hammer2_off_t)(lbn + 1) * lblksize >= isize)
			error = bread(ip->vp, lbn, lblksize, &bp);
		else
			error = bread(ip->vp, lbn, lblksize, &bp);
		if (error) {
			brelse(bp);
			bp = NULL;
			break;
		}

		loff = (int)(uio->uio_offset - lbase);
		n = lblksize - loff;
		if (n > uio->uio_resid)
			n = uio->uio_resid;
		if (n > isize - uio->uio_offset)
			n = (int)(isize - uio->uio_offset);
		error = uiomove(bp->b_data + loff, n, uio);
		if (error) {
			brelse(bp);
			bp = NULL;
			break;
		}
		brelse(bp);
	}

	return (error);
}

static int
hammer2_readlink(void *v)
{
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (vp->v_type != VLNK)
		return (EINVAL);

	return (hammer2_read_file(ip, ap->a_uio, 0));
}

static int
hammer2_read(void *v)
{
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type != VREG)
		return (EINVAL);

	return (hammer2_read_file(ip, ap->a_uio, ap->a_ioflag));
}

static int
hammer2_bmap(void *v)
{
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap = v;
	hammer2_xop_bmap_t *xop;
	hammer2_dev_t *hmp;
	hammer2_inode_t *ip = VTOI(ap->a_vp);
	hammer2_volume_t *vol;
	int error;

	hmp = ip->pmp->pfs_hmps[0];
	if (ap->a_bnp == NULL)
		return (0);
	if (ap->a_runp != NULL)
		*ap->a_runp = 0; /* unsupported */

	/* Initialize with error or nonexistent case first. */
	if (ap->a_vpp != NULL)
		*ap->a_vpp = NULL;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = -1;

	xop = hammer2_xop_alloc(ip, 0);
	xop->lbn = ap->a_bn; /* logical block number */
	hammer2_xop_start(&xop->head, &hammer2_bmap_desc);

	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error) {
		/* No physical block assigned. */
		if (error == ENOENT)
			error = 0;
		goto done;
	}

	if (xop->offset != HAMMER2_OFF_MASK) {
		/* Get volume from the result offset. */
		KKASSERT((xop->offset & HAMMER2_OFF_MASK_RADIX) == 0);
		vol = hammer2_get_volume(hmp, xop->offset);
		KKASSERT(vol);
		KKASSERT(vol->dev);
		KKASSERT(vol->dev->devvp);

		/* Return devvp for this volume. */
		if (ap->a_vpp != NULL)
			*ap->a_vpp = vol->dev->devvp;
		/* Return physical block number within devvp. */
		if (ap->a_bnp != NULL)
			*ap->a_bnp = (xop->offset - vol->offset) / DEV_BSIZE;
	}
done:
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

static int
hammer2_nresolve(void *v)
{
	struct vop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct vnode *vp, *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	hammer2_xop_nresolve_t *xop;
	hammer2_inode_t *ip, *dip = VTOI(dvp);
	int lockparent, error;

	//KASSERT(VOP_ISLOCKED(dvp)); /* not true in OpenBSD */
	KKASSERT(ap->a_vpp);
	*ap->a_vpp = NULL;

	cnp->cn_flags &= ~PDIRUNLOCK; /* XXX why this ?? */
	lockparent = cnp->cn_flags & LOCKPARENT;

	/* Check accessibility of directory. */
	error = VOP_ACCESS(dvp, VEXEC, cnp->cn_cred, cnp->cn_proc);
	if (error)
		return (error);

	if ((cnp->cn_flags & ISLASTCN) &&
	    (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return (EROFS);

	/*
	 * We now have a segment name to search for, and a directory to search.
	 *
	 * Before tediously performing a linear scan of the directory,
	 * check the name cache to see if the directory/name pair
	 * we are looking for is known already.
	 */
	error = cache_lookup(dvp, ap->a_vpp, cnp);
	if (error >= 0)
		return (error);

	/* OpenBSD needs "." and ".." handling. */
	if (cnp->cn_flags & ISDOTDOT) {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == RENAME)
			return (EINVAL);
		VOP_UNLOCK(dvp); /* race to get the inode */
		cnp->cn_flags |= PDIRUNLOCK;
		error = VFS_VGET(dip->pmp->mp, dip->meta.iparent, &vp);
		if (error) {
			if (vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY) == 0)
				cnp->cn_flags &= ~PDIRUNLOCK;
			return (error);
		}
		if (lockparent && (cnp->cn_flags & ISLASTCN)) {
			if ((error = vn_lock(dvp, LK_EXCLUSIVE)) != 0) {
				vput(vp);
				return (error);
			}
			cnp->cn_flags &= ~PDIRUNLOCK;
		}
		*ap->a_vpp = vp;
		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, vp, cnp);
		return (0);
	} else if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == RENAME)
			return (EISDIR);
		vref(dvp); /* We want ourself, i.e. ".". */
		*ap->a_vpp = dvp;
		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, dvp, cnp);
		return (0);
	}

	xop = hammer2_xop_alloc(dip, 0);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);

	hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);
	hammer2_xop_start(&xop->head, &hammer2_nresolve_desc);

	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error)
		ip = NULL;
	else
		ip = hammer2_inode_get(dip->pmp, &xop->head, -1, -1);
	hammer2_inode_unlock(dip);

	if (ip) {
		error = hammer2_igetv(dip->pmp->mp, ip, &vp);
		if (error == 0) {
			if (!lockparent || !(cnp->cn_flags & ISLASTCN)) {
				VOP_UNLOCK(dvp);
				cnp->cn_flags |= PDIRUNLOCK;
			}
			*ap->a_vpp = vp;
			if (cnp->cn_flags & MAKEENTRY)
				cache_enter(dvp, vp, cnp);
		} else if (error == ENOENT) {
			if (cnp->cn_flags & MAKEENTRY)
				cache_enter(dvp, NULLVP, cnp);
		}
		hammer2_inode_unlock(ip);
	} else {
		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, NULLVP, cnp);
		if ((cnp->cn_flags & ISLASTCN) &&
		    (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME))
			error = EJUSTRETURN;
		else
			error = ENOENT;
	}
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

static int
hammer2_open(void *v)
{
	struct vop_open_args /* {
		struct vnode *a_vp;
		int a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap __unused = v;

	return (0);
}

static int
hammer2_close(void *v)
{
	struct vop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap __unused = v;

	return (0);
}

static int
hammer2_ioctl(void *v)
{
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		void *a_data;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap = v;
	hammer2_inode_t *ip = VTOI(ap->a_vp);

	return (hammer2_ioctl_impl(ip, ap->a_command, ap->a_data, ap->a_fflag,
	    ap->a_cred));
}

static int
hammer2_print(void *v)
{
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap = v;
	hammer2_inode_t *ip = VTOI(ap->a_vp);

	printf("tag VT_HAMMER2, ino %ju", (uintmax_t)ip->meta.inum);
	printf("\n");

	return (0);
}

static int
hammer2_pathconf(void *v)
{
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	int error = 0;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = INT_MAX;
		break;
	case _PC_NAME_MAX:
		*ap->a_retval = HAMMER2_INODE_MAXNAME;
		break;
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		break;
	case _PC_PIPE_BUF:
		if (vp->v_type == VDIR || vp->v_type == VFIFO)
			*ap->a_retval = PIPE_BUF;
		else
			error = EINVAL;
		break;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		break;
	case _PC_NO_TRUNC:
		*ap->a_retval = 0;
		break;
	case _PC_SYNC_IO:
		*ap->a_retval = 0;
		break;
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;
		break;
	case _PC_SYMLINK_MAX:
		*ap->a_retval = HAMMER2_INODE_MAXNAME;
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

static int
hammer2_link(void *v)
{
	struct vop_link_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap = v;

	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
	vput(ap->a_dvp);

	return (EROFS);
}

static int
hammer2_symlink(void *v)
{
	struct vop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
		char *a_target;
	} */ *ap = v;

	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
	vput(ap->a_dvp);

	return (EROFS);
}

static int
hammer2_lock(void *v)
{
	struct vop_lock_args /* {
		struct vnode *a_vp;
		int a_flags;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;

	return (rrw_enter(&VTOI(vp)->vnlock, ap->a_flags & LK_RWFLAGS));
}

static int
hammer2_unlock(void *v)
{
	struct vop_unlock_args /* {
		struct vnode *a_vp;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;

	rrw_exit(&VTOI(vp)->vnlock);

	return (0);
}

static int
hammer2_islocked(void *v)
{
	struct vop_islocked_args /* {
		struct vnode *a_vp;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;

	return (rrw_status(&VTOI(vp)->vnlock));
}

static void filt_hammer2detach(struct knote *);
static int filt_hammer2read(struct knote *, long);
static int filt_hammer2write(struct knote *, long);
static int filt_hammer2vnode(struct knote *, long);

static const struct filterops hammer2read_filtops = {
	.f_flags	= FILTEROP_ISFD,
	.f_attach	= NULL,
	.f_detach	= filt_hammer2detach,
	.f_event	= filt_hammer2read,
};

static const struct filterops hammer2write_filtops = {
	.f_flags	= FILTEROP_ISFD,
	.f_attach	= NULL,
	.f_detach	= filt_hammer2detach,
	.f_event	= filt_hammer2write,
};

static const struct filterops hammer2vnode_filtops = {
	.f_flags	= FILTEROP_ISFD,
	.f_attach	= NULL,
	.f_detach	= filt_hammer2detach,
	.f_event	= filt_hammer2vnode,
};

static int
hammer2_kqfilter(void *v)
{
	struct vop_kqfilter_args /* {
		struct vnode *a_vp;
		int a_fflag;
		struct knote *a_kn;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct knote *kn = ap->a_kn;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &hammer2read_filtops;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &hammer2write_filtops;
		break;
	case EVFILT_VNODE:
		kn->kn_fop = &hammer2vnode_filtops;
		break;
	default:
		return (EINVAL);
	}

	kn->kn_hook = (caddr_t)vp;
	klist_insert_locked(&vp->v_selectinfo.si_note, kn);

	return (0);
}

static void
filt_hammer2detach(struct knote *kn)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;

	klist_remove_locked(&vp->v_selectinfo.si_note, kn);
}

static int
filt_hammer2read(struct knote *kn, long hint)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;
	hammer2_inode_t *ip = VTOI(vp);

	/*
	 * filesystem is gone, so set the EOF flag and schedule
	 * the knote for deletion.
	 */
	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}

	kn->kn_data = ip->meta.size - foffset(kn->kn_fp);
	if (kn->kn_data == 0 && kn->kn_sfflags & NOTE_EOF) {
		kn->kn_fflags |= NOTE_EOF;
		return (1);
	}

	if (kn->kn_flags & (__EV_POLL | __EV_SELECT))
		return (1);

	return (kn->kn_data != 0);
}

static int
filt_hammer2write(struct knote *kn, long hint)
{
	/*
	 * filesystem is gone, so set the EOF flag and schedule
	 * the knote for deletion.
	 */
	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}

	kn->kn_data = 0;
	return (1);
}

static int
filt_hammer2vnode(struct knote *kn, long hint)
{
	if (kn->kn_sfflags & hint)
		kn->kn_fflags |= hint;
	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	return (kn->kn_fflags != 0);
}

/*
 * Initialize the vnode associated with a new inode, handle aliased vnodes.
 */
int
hammer2_vinit(struct mount *mp, struct vnode **vpp)
{
	struct vnode *vp = *vpp, *nvp;
	hammer2_inode_t *ip = VTOI(vp);

	vp->v_type = hammer2_get_vtype(ip->meta.type);
	switch (vp->v_type) {
	case VCHR:
	case VBLK:
		vp->v_op = &hammer2_specvops;
		nvp = checkalias(vp, (dev_t)(uintptr_t)vp, mp);
		if (nvp != NULL) {
			/*
			 * Discard unneeded vnode, but save its inode. Note
			 * that the lock is carried over in the inode to the
			 * replacement vnode.
			 */
			nvp->v_data = vp->v_data;
			vp->v_data = NULL;
			vp->v_op = &spec_vops;
#ifdef VFSLCKDEBUG
			vp->v_flag &= ~VLOCKSWORK;
#endif
			vrele(vp);
			vgone(vp);
			/* Reinitialize aliased vnode. */
			vp = nvp;
			ip->vp = vp;
		}
		break;
	case VFIFO:
#ifdef FIFO
		vp->v_op = &hammer2_fifovops;
		break;
#else
		return (EOPNOTSUPP);
#endif /* FIFO */
	default:
		break;
	}

	if (ip->meta.inum == 1)
                vp->v_flag |= VROOT;
	*vpp = vp;

	return (0);
}

/* Global vfs data structures for hammer2. */
const struct vops hammer2_vops = {
	.vop_lookup	= hammer2_nresolve,
	.vop_create	= eopnotsupp,
	.vop_mknod	= eopnotsupp,
	.vop_open	= hammer2_open,
	.vop_close	= hammer2_close,
	.vop_access	= hammer2_access,
	.vop_getattr	= hammer2_getattr,
	.vop_setattr	= hammer2_setattr,
	.vop_read	= hammer2_read,
	.vop_write	= eopnotsupp,
	.vop_ioctl	= hammer2_ioctl,
	.vop_kqfilter	= hammer2_kqfilter,
	.vop_revoke	= vop_generic_revoke,
	.vop_fsync	= nullop,
	.vop_remove	= eopnotsupp,
	.vop_link	= hammer2_link,
	.vop_rename	= eopnotsupp,
	.vop_mkdir	= eopnotsupp,
	.vop_rmdir	= eopnotsupp,
	.vop_symlink	= hammer2_symlink,
	.vop_readdir	= hammer2_readdir,
	.vop_readlink	= hammer2_readlink,
	.vop_abortop	= vop_generic_abortop,
	.vop_inactive	= hammer2_inactive,
	.vop_reclaim	= hammer2_reclaim,
	.vop_lock	= hammer2_lock,
	.vop_unlock	= hammer2_unlock,
	.vop_bmap	= hammer2_bmap,
	.vop_strategy	= hammer2_strategy,
	.vop_print	= hammer2_print,
	.vop_islocked	= hammer2_islocked,
	.vop_pathconf	= hammer2_pathconf,
	.vop_advlock	= eopnotsupp,
	.vop_bwrite	= vop_generic_bwrite, /* XXX why ? */
};

/* Special device vnode ops */
const struct vops hammer2_specvops = {
	.vop_access	= hammer2_access,
	.vop_getattr	= hammer2_getattr,
	.vop_setattr	= hammer2_setattr,
	.vop_inactive	= hammer2_inactive,
	.vop_reclaim	= hammer2_reclaim,
	.vop_lock	= hammer2_lock,
	.vop_unlock	= hammer2_unlock,
	.vop_print	= hammer2_print,
	.vop_islocked	= hammer2_islocked,

	/* XXX: Keep in sync with spec_vops. */
	.vop_lookup	= vop_generic_lookup,
	.vop_create	= vop_generic_badop,
	.vop_mknod	= vop_generic_badop,
	.vop_open	= spec_open,
	.vop_close	= spec_close,
	.vop_read	= spec_read,
	.vop_write	= spec_write,
	.vop_ioctl	= spec_ioctl,
	.vop_kqfilter	= spec_kqfilter,
	.vop_revoke	= vop_generic_revoke,
	.vop_fsync	= spec_fsync,
	.vop_remove	= vop_generic_badop,
	.vop_link	= vop_generic_badop,
	.vop_rename	= vop_generic_badop,
	.vop_mkdir	= vop_generic_badop,
	.vop_rmdir	= vop_generic_badop,
	.vop_symlink	= vop_generic_badop,
	.vop_readdir	= vop_generic_badop,
	.vop_readlink	= vop_generic_badop,
	.vop_abortop	= vop_generic_badop,
	.vop_bmap	= vop_generic_bmap,
	.vop_strategy	= spec_strategy,
	.vop_pathconf	= spec_pathconf,
	.vop_advlock	= spec_advlock,
	.vop_bwrite	= vop_generic_bwrite,
};

#ifdef FIFO
const struct vops hammer2_fifovops = {
	.vop_access	= hammer2_access,
	.vop_getattr	= hammer2_getattr,
	.vop_setattr	= hammer2_setattr,
	.vop_inactive	= hammer2_inactive,
	.vop_reclaim	= hammer2_reclaim,
	.vop_lock	= hammer2_lock,
	.vop_unlock	= hammer2_unlock,
	.vop_print	= hammer2_print,
	.vop_islocked	= hammer2_islocked,
	.vop_bwrite	= vop_generic_bwrite,

	/* XXX: Keep in sync with fifo_vops. */
	.vop_lookup	= vop_generic_lookup,
	.vop_create	= vop_generic_badop,
	.vop_mknod	= vop_generic_badop,
	.vop_open	= fifo_open,
	.vop_close	= fifo_close,
	.vop_read	= fifo_read,
	.vop_write	= fifo_write,
	.vop_ioctl	= fifo_ioctl,
	.vop_kqfilter	= fifo_kqfilter,
	.vop_revoke	= vop_generic_revoke,
	.vop_fsync	= nullop,
	.vop_remove	= vop_generic_badop,
	.vop_link	= vop_generic_badop,
	.vop_rename	= vop_generic_badop,
	.vop_mkdir	= vop_generic_badop,
	.vop_rmdir	= vop_generic_badop,
	.vop_symlink	= vop_generic_badop,
	.vop_readdir	= vop_generic_badop,
	.vop_readlink	= vop_generic_badop,
	.vop_abortop	= vop_generic_badop,
	.vop_bmap	= vop_generic_bmap,
	.vop_strategy	= vop_generic_badop,
	.vop_pathconf	= fifo_pathconf,
	.vop_advlock	= fifo_advlock,
};
#endif /* FIFO */

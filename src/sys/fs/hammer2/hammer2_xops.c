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

/*
 * Determine if the specified directory is empty.
 *
 *	Returns 0 on success.
 *
 *	Returns HAMMER_ERROR_EAGAIN if caller must re-lookup the entry and
 *	retry. (occurs if we race a ripup on oparent or ochain).
 *
 *	Or returns a permanent HAMMER2_ERROR_* error mask.
 *
 * The caller must pass in an exclusively locked oparent and ochain.  This
 * function will handle the case where the chain is a directory entry or
 * the inode itself.  The original oparent,ochain will be locked upon return.
 *
 * This function will unlock the underlying oparent,ochain temporarily when
 * doing an inode lookup to avoid deadlocks.  The caller MUST handle the EAGAIN
 * result as this means that oparent is no longer the parent of ochain, or
 * that ochain was destroyed while it was unlocked.
 */
static int
checkdirempty(hammer2_chain_t *oparent, hammer2_chain_t *ochain, int clindex)
{
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next, inum;
	int error = 0, didunlock = 0;

	/*
	 * Find the inode, set it up as a locked 'chain'.  ochain can be the
	 * inode itself, or it can be a directory entry.
	 */
	if (ochain->bref.type == HAMMER2_BREF_TYPE_DIRENT) {
		inum = ochain->bref.embed.dirent.inum;
		hammer2_chain_unlock(ochain);
		hammer2_chain_unlock(oparent);

		parent = NULL;
		chain = NULL;
		error = hammer2_chain_inode_find(ochain->pmp, inum, clindex, 0,
		    &parent, &chain);
		if (parent) {
			hammer2_chain_unlock(parent);
			hammer2_chain_drop(parent);
		}
		didunlock = 1;
	} else {
		/* The directory entry *is* the directory inode. */
		chain = hammer2_chain_lookup_init(ochain, 0);
	}

	/*
	 * Determine if the directory is empty or not by checking its
	 * visible namespace (the area which contains directory entries).
	 */
	if (error == 0) {
		parent = chain;
		chain = NULL;
		if (parent)
			chain = hammer2_chain_lookup(&parent, &key_next,
			    HAMMER2_DIRHASH_VISIBLE, HAMMER2_KEY_MAX, &error,
			    0);
		if (chain) {
			error = HAMMER2_ERROR_ENOTEMPTY;
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
		}
		hammer2_chain_lookup_done(parent);
	} else {
		if (chain) {
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
			chain = NULL; /* safety */
		}
	}

	if (didunlock) {
		hammer2_chain_lock(oparent, HAMMER2_RESOLVE_ALWAYS);
		hammer2_chain_lock(ochain, HAMMER2_RESOLVE_ALWAYS);
		if ((ochain->flags & HAMMER2_CHAIN_DELETED) ||
		    (oparent->flags & HAMMER2_CHAIN_DELETED) ||
		    ochain->parent != oparent) {
			hprintf("CHECKDIR inum %016jx RETRY\n", (intmax_t)inum);
			error = HAMMER2_ERROR_EAGAIN;
		}
	}
	return (error);
}

/*
 * Backend for hammer2_vfs_root().
 *
 * This is called when a newly mounted PFS has not yet synchronized
 * to the inode_tid and modify_tid.
 */
void
hammer2_xop_ipcluster(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_ipcluster_t *xop = &arg->xop_ipcluster;
	hammer2_chain_t *chain;
	int error;

	chain = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	if (chain)
		error = chain->error;
	else
		error = HAMMER2_ERROR_EIO;

	hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

/*
 * Backend for hammer2_readdir().
 */
void
hammer2_xop_readdir(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_readdir_t *xop = &arg->xop_readdir;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t lkey, key_next;
	int error = 0;

	lkey = xop->lkey;

	/*
	 * The inode's chain is the iterator.  If we cannot acquire it our
	 * contribution ends here.
	 */
	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	if (parent == NULL) {
		hprintf("NULL parent\n");
		goto done;
	}

	/*
	 * Directory scan [re]start and loop, the feed inherits the chain's
	 * lock so do not unlock it on the iteration.
	 */
	chain = hammer2_chain_lookup(&parent, &key_next, lkey, lkey, &error,
	    HAMMER2_LOOKUP_SHARED);
	if (chain == NULL)
		chain = hammer2_chain_lookup(&parent, &key_next, lkey,
		    HAMMER2_KEY_MAX, &error, HAMMER2_LOOKUP_SHARED);
	while (chain) {
		error = hammer2_xop_feed(&xop->head, chain, clindex, 0);
		if (error)
			goto break2;
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    HAMMER2_KEY_MAX, &error, HAMMER2_LOOKUP_SHARED);
	}
break2:
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	hammer2_chain_unlock(parent);
	hammer2_chain_drop(parent);
done:
	hammer2_xop_feed(&xop->head, NULL, clindex, error);
}

/*
 * Backend for hammer2_nresolve().
 */
void
hammer2_xop_nresolve(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_nresolve_t *xop = &arg->xop_nresolve;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t lhc, key_next;
	const char *name;
	size_t name_len;
	int error;

	chain = NULL;
	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	if (parent == NULL) {
		hprintf("NULL parent\n");
		error = HAMMER2_ERROR_EIO;
		goto done;
	}
	name = xop->head.name1;
	name_len = xop->head.name1_len;

	/* Lookup the directory entry. */
	lhc = hammer2_dirhash(name, name_len);
	chain = hammer2_chain_lookup(&parent, &key_next, lhc,
	    lhc + HAMMER2_DIRHASH_LOMASK, &error,
	    HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_SHARED);
	while (chain) {
		if (hammer2_chain_dirent_test(chain, name, name_len))
			break;
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    lhc + HAMMER2_DIRHASH_LOMASK, &error,
		    HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_SHARED);
	}

	/* Locate the target inode for a directory entry. */
	if (chain && chain->error == 0) {
		if (chain->bref.type == HAMMER2_BREF_TYPE_DIRENT) {
			lhc = chain->bref.embed.dirent.inum;
			error = hammer2_chain_inode_find(chain->pmp, lhc,
			    clindex, HAMMER2_LOOKUP_SHARED, &parent, &chain);
		}
	} else if (chain && error == 0) {
		error = chain->error;
	}
done:
	error = hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
}

/*
 * Backend for hammer2_vop_nremove(), hammer2_vop_nrmdir(), and
 * backend for pfs_delete.
 *
 * This function locates and removes a directory entry, and will lookup
 * and return the underlying inode.  For directory entries the underlying
 * inode is not removed.  If the directory entry is the actual inode itself,
 * it may be conditonally removed and returned.
 *
 * WARNING!  Any target inode's nlinks may not be synchronized to the
 *	     in-memory inode.  The frontend's hammer2_inode_unlink_finisher()
 *	     is responsible for the final disposition of the actual inode.
 */
void
hammer2_xop_unlink(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_unlink_t *xop = &arg->xop_unlink;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next, lhc;
	const char *name;
	size_t name_len;
	uint8_t type;
	int error, error2, dopermanent, doforce;
again:
	/* Requires exclusive lock. */
	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	chain = NULL;
	if (parent == NULL) {
		hprintf("NULL parent\n");
		error = HAMMER2_ERROR_EIO;
		goto done;
	}
	name = xop->head.name1;
	name_len = xop->head.name1_len;

	/* Lookup the directory entry. */
	lhc = hammer2_dirhash(name, name_len);
	chain = hammer2_chain_lookup(&parent, &key_next, lhc,
	    lhc + HAMMER2_DIRHASH_LOMASK, &error, HAMMER2_LOOKUP_ALWAYS);
	while (chain) {
		if (hammer2_chain_dirent_test(chain, name, name_len))
			break;
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    lhc + HAMMER2_DIRHASH_LOMASK, &error,
		    HAMMER2_LOOKUP_ALWAYS);
	}

	/*
	 * The directory entry will either be a BREF_TYPE_DIRENT or a
	 * BREF_TYPE_INODE.  We always permanently delete DIRENTs, but
	 * must go by xop->dopermanent for BREF_TYPE_INODE.
	 *
	 * Note that the target chain's nlinks may not be synchronized with
	 * the in-memory hammer2_inode_t structure, so we don't try to do
	 * anything fancy here.  The frontend deals with nlinks
	 * synchronization.
	 */
	if (chain && chain->error == 0) {
		dopermanent = xop->dopermanent & H2DOPERM_PERMANENT;
		doforce = xop->dopermanent & H2DOPERM_FORCE;

		/*
		 * If the directory entry is the actual inode then use its
		 * type for the directory typing tests, otherwise if it is
		 * a directory entry, pull the type field from the entry.
		 *
		 * Directory entries are always permanently deleted
		 * (because they aren't the actual inode).
		 */
		if (chain->bref.type == HAMMER2_BREF_TYPE_DIRENT) {
			type = chain->bref.embed.dirent.type;
			dopermanent |= HAMMER2_DELETE_PERMANENT;
		} else {
			type = chain->data->ipdata.meta.type;
		}

		/*
		 * Check directory typing and delete the entry.  Note that
		 * nlinks adjustments are made on the real inode by the
		 * frontend, not here.
		 *
		 * Unfortunately, checkdirempty() may have to unlock (parent).
		 * If it no longer matches chain->parent after re-locking,
		 * EAGAIN is returned.
		 */
		if (type == HAMMER2_OBJTYPE_DIRECTORY && doforce) {
			/*
			 * If doforce then execute the operation even if
			 * the directory is not empty or errored.  We
			 * ignore chain->error here, allowing an errored
			 * chain (aka directory entry) to still be deleted.
			 */
			error = hammer2_chain_delete(parent, chain,
			    xop->head.mtid, dopermanent);
		} else if (type == HAMMER2_OBJTYPE_DIRECTORY &&
		    xop->isdir == 0) {
			error = HAMMER2_ERROR_EISDIR;
		} else if (type == HAMMER2_OBJTYPE_DIRECTORY &&
		    (error = checkdirempty(parent, chain, clindex)) != 0) {
			/* error may be EAGAIN or ENOTEMPTY. */
			if (error == HAMMER2_ERROR_EAGAIN) {
				hammer2_chain_unlock(chain);
				hammer2_chain_drop(chain);
				hammer2_chain_unlock(parent);
				hammer2_chain_drop(parent);
				goto again;
			}
		} else if (type != HAMMER2_OBJTYPE_DIRECTORY &&
		    xop->isdir >= 1) {
			error = HAMMER2_ERROR_ENOTDIR;
		} else {
			/*
			 * Delete the directory entry.  chain might also
			 * be a directly-embedded inode.
			 *
			 * Allow the deletion to proceed even if the chain
			 * is errored.  Give priority to error-on-delete over
			 * chain->error.
			 */
			error = hammer2_chain_delete(parent, chain,
			    xop->head.mtid, dopermanent);
			if (error == 0)
				error = chain->error;
		}
	} else {
		if (chain && error == 0)
			error = chain->error;
	}

	/*
	 * If chain is a directory entry we must resolve it.  We do not try
	 * to manipulate the contents as it might not be synchronized with
	 * the frontend hammer2_inode_t, nor do we try to lookup the
	 * frontend hammer2_inode_t here (we are the backend!).
	 */
	if (chain && chain->bref.type == HAMMER2_BREF_TYPE_DIRENT &&
	    (xop->dopermanent & H2DOPERM_IGNINO) == 0) {
		lhc = chain->bref.embed.dirent.inum;
		error2 = hammer2_chain_inode_find(chain->pmp, lhc, clindex, 0,
		    &parent, &chain);
		if (error2) {
			hprintf("lhc %016jx failed\n", (intmax_t)lhc);
			error2 = 0; /* silently ignore */
		}
		if (error == 0)
			error = error2;
	}

	/*
	 * Return the inode target for further action.  Typically used by
	 * hammer2_inode_unlink_finisher().
	 */
done:
	hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		chain = NULL;
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
		parent = NULL;
	}
}

/*
 * Directory collision resolver scan helper (backend, threaded).
 *
 * Used by the inode create code to locate an unused lhc.
 */
void
hammer2_xop_scanlhc(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_scanlhc_t *xop = &arg->xop_scanlhc;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	int error = 0;

	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	if (parent == NULL) {
		hprintf("NULL parent\n");
		chain = NULL;
		error = HAMMER2_ERROR_EIO;
		goto done;
	}

	/*
	 * Lookup all possibly conflicting directory entries, the feed
	 * inherits the chain's lock so do not unlock it on the iteration.
	 */
	chain = hammer2_chain_lookup(&parent, &key_next, xop->lhc,
	    xop->lhc + HAMMER2_DIRHASH_LOMASK, &error,
	    HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_SHARED);
	while (chain) {
		error = hammer2_xop_feed(&xop->head, chain, clindex, 0);
		if (error) {
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
			chain = NULL; /* safety */
			goto done;
		}
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    xop->lhc + HAMMER2_DIRHASH_LOMASK, &error,
		    HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_SHARED);
	}
done:
	hammer2_xop_feed(&xop->head, NULL, clindex, error);
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
}

/*
 * Generic lookup of a specific key.
 */
void
hammer2_xop_lookup(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_lookup_t *xop = &arg->xop_lookup;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t key_next;
	int error = 0;

	chain = NULL;
	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	if (parent == NULL) {
		hprintf("NULL parent\n");
		error = HAMMER2_ERROR_EIO;
		goto done;
	}

	/*
	 * Lookup all possibly conflicting directory entries, the feed
	 * inherits the chain's lock so do not unlock it on the iteration.
	 */
	chain = hammer2_chain_lookup(&parent, &key_next, xop->lhc, xop->lhc,
	    &error, HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_SHARED);
	if (error == 0) {
		if (chain)
			error = chain->error;
		else
			error = HAMMER2_ERROR_ENOENT;
	}
	hammer2_xop_feed(&xop->head, chain, clindex, error);
done:
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
}

void
hammer2_xop_delete(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_lookup_t *xop = &arg->xop_lookup;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	int error = 0;

	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	chain = NULL;
	if (parent == NULL) {
		error = HAMMER2_ERROR_EIO;
		goto done;
	}

	/*
	 * Lookup all possibly conflicting directory entries, the feed
	 * inherits the chain's lock so do not unlock it on the iteration.
	 */
	chain = hammer2_chain_lookup(&parent, &key_next, xop->lhc, xop->lhc,
	    &error, HAMMER2_LOOKUP_NODATA);
	if (error == 0) {
		if (chain)
			error = chain->error;
		else
			error = HAMMER2_ERROR_ENOENT;
	}
	if (chain)
		error = hammer2_chain_delete(parent, chain, xop->head.mtid,
		    HAMMER2_DELETE_PERMANENT);
	hammer2_xop_feed(&xop->head, NULL, clindex, error);
done:
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
}

/*
 * Generic scan
 *
 * WARNING! Fed chains must be locked shared so ownership can be transfered
 *	    and to prevent frontend/backend stalls that would occur with an
 *	    exclusive lock.  The shared lock also allows chain->data to be
 *	    retained.
 */
void
hammer2_xop_scanall(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_scanall_t *xop = &arg->xop_scanall;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	int error = 0;

	/* Assert required flags. */
	KKASSERT(xop->resolve_flags & HAMMER2_RESOLVE_SHARED);
	KKASSERT(xop->lookup_flags & HAMMER2_LOOKUP_SHARED);

	/*
	 * The inode's chain is the iterator.  If we cannot acquire it our
	 * contribution ends here.
	 */
	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    xop->resolve_flags);
	if (parent == NULL) {
		hprintf("NULL parent\n");
		goto done;
	}

	/*
	 * Generic scan of exact records.  Note that indirect blocks are
	 * automatically recursed and will not be returned.
	 */
	chain = hammer2_chain_lookup(&parent, &key_next, xop->key_beg,
	    xop->key_end, &error, xop->lookup_flags);
	while (chain) {
		error = hammer2_xop_feed(&xop->head, chain, clindex, 0);
		if (error)
			goto break2;
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    xop->key_end, &error, xop->lookup_flags);
	}
break2:
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	hammer2_chain_unlock(parent);
	hammer2_chain_drop(parent);
done:
	hammer2_xop_feed(&xop->head, NULL, clindex, error);
}

/*
 * Helper to create a directory entry.
 */
void
hammer2_xop_inode_mkdirent(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_mkdirent_t *xop = &arg->xop_mkdirent;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	size_t data_len;
	int error;

	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	if (parent == NULL) {
		error = HAMMER2_ERROR_EIO;
		chain = NULL;
		goto fail;
	}

	chain = hammer2_chain_lookup(&parent, &key_next, xop->lhc, xop->lhc,
	    &error, 0);
	if (chain) {
		error = HAMMER2_ERROR_EEXIST;
		goto fail;
	}

	/*
	 * We may be able to embed the directory entry directly in the
	 * blockref.
	 */
	if (xop->dirent.namlen <= sizeof(chain->bref.check.buf))
		data_len = 0;
	else
		data_len = HAMMER2_ALLOC_MIN;
	error = hammer2_chain_create(&parent, &chain, NULL, xop->head.ip1->pmp,
	    HAMMER2_METH_DEFAULT, xop->lhc, 0, HAMMER2_BREF_TYPE_DIRENT,
	    data_len, xop->head.mtid, 0, 0);
	if (error == 0) {
		/*
		 * WARNING: chain->data->buf is sized to chain->bytes,
		 *	    do not use sizeof(chain->data->buf), which
		 *	    will be much larger.
		 */
		error = hammer2_chain_modify(chain, xop->head.mtid, 0, 0);
		if (error == 0) {
			chain->bref.embed.dirent = xop->dirent;
			if (xop->dirent.namlen <= sizeof(chain->bref.check.buf))
				bcopy(xop->head.name1, chain->bref.check.buf,
				    xop->dirent.namlen);
			else
				bcopy(xop->head.name1, chain->data->buf,
				    xop->dirent.namlen);
		}
	}
fail:
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

/*
 * Inode create helper (threaded, backend).
 *
 * Used by ncreate, nmknod, nsymlink, nmkdir.
 * Used by nlink and rename to create HARDLINK pointers.
 *
 * Frontend holds the parent directory ip locked exclusively.  We
 * create the inode and feed the exclusively locked chain to the
 * frontend.
 */
void
hammer2_xop_inode_create(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_create_t *xop = &arg->xop_create;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	int error;

	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	if (parent == NULL) {
		error = HAMMER2_ERROR_EIO;
		chain = NULL;
		goto fail;
	}

	chain = hammer2_chain_lookup(&parent, &key_next, xop->lhc, xop->lhc,
	    &error, 0);
	if (chain) {
		error = HAMMER2_ERROR_EEXIST;
		goto fail;
	}

	error = hammer2_chain_create(&parent, &chain, NULL, xop->head.ip1->pmp,
	    HAMMER2_METH_DEFAULT, xop->lhc, 0, HAMMER2_BREF_TYPE_INODE,
	    HAMMER2_INODE_BYTES, xop->head.mtid, 0, xop->flags);
	if (error == 0) {
		error = hammer2_chain_modify(chain, xop->head.mtid, 0, 0);
		if (error == 0) {
			chain->data->ipdata.meta = xop->meta;
			if (xop->head.name1) {
				bcopy(xop->head.name1,
				    chain->data->ipdata.filename,
				    xop->head.name1_len);
				chain->data->ipdata.meta.name_len =
				    xop->head.name1_len;
			}
			chain->data->ipdata.meta.name_key = xop->lhc;
		}
	}
fail:
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

/*
 * Create inode as above but leave it detached from the hierarchy.
 */
void
hammer2_xop_inode_create_det(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_create_t *xop = &arg->xop_create;
	hammer2_chain_t *parent, *chain, *null_parent;
	hammer2_inode_t *pip, *iroot;
	hammer2_key_t key_next;
	int error;

	pip = xop->head.ip1;
	iroot = pip->pmp->iroot;

	parent = hammer2_inode_chain(iroot, clindex, HAMMER2_RESOLVE_ALWAYS);
	if (parent == NULL) {
		error = HAMMER2_ERROR_EIO;
		chain = NULL;
		goto fail;
	}

	chain = hammer2_chain_lookup(&parent, &key_next, xop->lhc, xop->lhc,
	    &error, 0);
	if (chain) {
		error = HAMMER2_ERROR_EEXIST;
		goto fail;
	}

	/*
	 * Create as a detached chain with no parent.  We must specify
	 * methods.
	 */
	null_parent = NULL;
	error = hammer2_chain_create(&null_parent, &chain, parent->hmp,
	    pip->pmp, HAMMER2_ENC_COMP(pip->meta.comp_algo) +
	    HAMMER2_ENC_CHECK(pip->meta.check_algo), xop->lhc, 0,
	    HAMMER2_BREF_TYPE_INODE, HAMMER2_INODE_BYTES,
	    xop->head.mtid, 0, xop->flags);
	if (error == 0) {
		error = hammer2_chain_modify(chain, xop->head.mtid, 0, 0);
		if (error == 0) {
			chain->data->ipdata.meta = xop->meta;
			if (xop->head.name1) {
				bcopy(xop->head.name1,
				    chain->data->ipdata.filename,
				    xop->head.name1_len);
				chain->data->ipdata.meta.name_len =
				    xop->head.name1_len;
			}
			chain->data->ipdata.meta.name_key = xop->lhc;
		}
	}
fail:
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

/*
 * Take a detached chain and insert it into the topology.
 */
void
hammer2_xop_inode_create_ins(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_create_t *xop = &arg->xop_create;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	int error;

	/* (parent) will be the insertion point for inode under iroot. */
	parent = hammer2_inode_chain(xop->head.ip1->pmp->iroot, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	if (parent == NULL) {
		error = HAMMER2_ERROR_EIO;
		chain = NULL;
		goto fail;
	}

	chain = hammer2_chain_lookup(&parent, &key_next, xop->lhc, xop->lhc,
	    &error, 0);
	if (chain) {
		error = HAMMER2_ERROR_EEXIST;
		goto fail;
	}

	/* (chain) is the detached inode that is being inserted. */
	chain = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	if (chain == NULL) {
		error = HAMMER2_ERROR_EIO;
		chain = NULL;
		goto fail;
	}

	/*
	 * This create call will insert the non-NULL chain into parent.
	 * Most of the auxillary fields are ignored since the chain already
	 * exists.
	 */
	error = hammer2_chain_create(&parent, &chain, NULL, xop->head.ip1->pmp,
	    HAMMER2_METH_DEFAULT, xop->lhc, 0, HAMMER2_BREF_TYPE_INODE,
	    HAMMER2_INODE_BYTES, xop->head.mtid, 0, xop->flags);
fail:
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

/*
 * Inode delete helper (backend, threaded).
 */
void
hammer2_xop_inode_destroy(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_destroy_t *xop = &arg->xop_destroy;
	hammer2_chain_t *parent, *chain;
	hammer2_inode_t *ip;
	int error;

	/* We need the precise parent chain to issue the deletion. */
	ip = xop->head.ip1;

	chain = hammer2_inode_chain(ip, clindex, HAMMER2_RESOLVE_ALWAYS);
	if (chain == NULL) {
		parent = NULL;
		error = HAMMER2_ERROR_EIO;
		goto done;
	}

	if (ip->flags & HAMMER2_INODE_CREATING) {
		/*
		 * Inode's chains are not linked into the media topology
		 * because it is a new inode (which is now being destroyed).
		 */
		parent = NULL;
	} else {
		/* Inode's chains are linked into the media topology. */
		parent = hammer2_chain_getparent(chain, HAMMER2_RESOLVE_ALWAYS);
		if (parent == NULL) {
			error = HAMMER2_ERROR_EIO;
			goto done;
		}
	}
	KKASSERT(chain->parent == parent);

	/* We have the correct parent, we can issue the deletion. */
	hammer2_chain_delete(parent, chain, xop->head.mtid, 0);
	error = 0;
done:
	hammer2_xop_feed(&xop->head, NULL, clindex, error);
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

void
hammer2_xop_inode_unlinkall(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_unlinkall_t *xop = &arg->xop_unlinkall;
	hammer2_chain_t *parent, *chain;
	hammer2_key_t key_next;
	int error;

	/* We need the precise parent chain to issue the deletion. */
	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	chain = NULL;
	if (parent == NULL) {
		error = 0;
		goto done;
	}
	chain = hammer2_chain_lookup(&parent, &key_next, xop->key_beg,
	    xop->key_end, &error, HAMMER2_LOOKUP_ALWAYS);
	while (chain) {
		hammer2_chain_delete(parent, chain, xop->head.mtid,
		    HAMMER2_DELETE_PERMANENT);
		hammer2_xop_feed(&xop->head, chain, clindex, chain->error);
		/* Depend on function to unlock the shared lock. */
		chain = hammer2_chain_next(&parent, chain, &key_next, key_next,
		    xop->key_end, &error, HAMMER2_LOOKUP_ALWAYS);
	}
done:
	if (error == 0)
		error = HAMMER2_ERROR_ENOENT;
	hammer2_xop_feed(&xop->head, NULL, clindex, error);
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

/*
 * Backend for hammer2_bmap().
 */
void
hammer2_xop_bmap(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_bmap_t *xop = &arg->xop_bmap;
	hammer2_inode_t *ip = xop->head.ip1;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t lbase, key_dummy;
	int error = 0;

	lbase = (hammer2_key_t)xop->lbn * hammer2_get_logical();
	KKASSERT(((int)lbase & HAMMER2_PBUFMASK) == 0);

	chain = NULL;
	parent = hammer2_inode_chain(ip, clindex,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	if (parent == NULL) {
		hprintf("NULL parent\n");
		error = HAMMER2_ERROR_EIO;
		goto done;
	}

	/*
	 * NULL chain isn't necessarily an error.
	 * It could be a zero filled data without physical block assigned.
	 */
	xop->offset = HAMMER2_OFF_MASK;
	chain = hammer2_chain_lookup(&parent, &key_dummy, lbase, lbase,
	    &error, HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_SHARED);
	if (error == 0) {
		if (chain) {
			error = chain->error;
			if (error == 0)
				xop->offset = chain->bref.data_off &
				    ~HAMMER2_OFF_MASK_RADIX;
		} else {
			error = HAMMER2_ERROR_ENOENT;
		}
	}
done:
	error = hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
}

/*
 * Synchronize the in-memory inode with the chain.  This does not flush
 * the chain to disk.  Instead, it makes front-end inode changes visible
 * in the chain topology, thus visible to the backend.  This is done in an
 * ad-hoc manner outside of the filesystem vfs_sync, and in a controlled
 * manner inside the vfs_sync.
 */
void
hammer2_xop_inode_chain_sync(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_fsync_t *xop = &arg->xop_fsync;
	hammer2_chain_t *parent, *chain = NULL;
	hammer2_key_t lbase, key_next;
	int error = 0;

	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS);
	if (parent == NULL) {
		error = HAMMER2_ERROR_EIO;
		goto done;
	}
	if (parent->error) {
		error = parent->error;
		goto done;
	}

	if ((xop->ipflags & HAMMER2_INODE_RESIZED) == 0) {
		/* osize must be ignored */
	} else if (xop->meta.size < xop->osize) {
		/*
		 * We must delete any chains beyond the EOF.  The chain
		 * straddling the EOF will be pending in the bioq.
		 */
		lbase = (xop->meta.size + HAMMER2_PBUFMASK64) &
		    ~HAMMER2_PBUFMASK64;
		chain = hammer2_chain_lookup(&parent, &key_next, lbase,
		    HAMMER2_KEY_MAX, &error,
		    HAMMER2_LOOKUP_NODATA | HAMMER2_LOOKUP_NODIRECT);
		while (chain) {
			/* Degenerate embedded case, nothing to loop on. */
			switch (chain->bref.type) {
			case HAMMER2_BREF_TYPE_DIRENT:
			case HAMMER2_BREF_TYPE_INODE:
				KKASSERT(0);
				break;
			case HAMMER2_BREF_TYPE_DATA:
				hammer2_chain_delete(parent, chain,
				    xop->head.mtid, HAMMER2_DELETE_PERMANENT);
				break;
			}
			chain = hammer2_chain_next(&parent, chain, &key_next,
			    key_next, HAMMER2_KEY_MAX, &error,
			    HAMMER2_LOOKUP_NODATA | HAMMER2_LOOKUP_NODIRECT);
		}

		/* Reset to point at inode for following code, if necessary. */
		if (parent->bref.type != HAMMER2_BREF_TYPE_INODE) {
			hammer2_chain_unlock(parent);
			hammer2_chain_drop(parent);
			parent = hammer2_inode_chain(xop->head.ip1, clindex,
			    HAMMER2_RESOLVE_ALWAYS);
			hprintf("truncate reset on '%s'\n",
			    parent->data->ipdata.filename);
		}
	}

	/*
	 * Sync the inode meta-data, potentially clear the blockset area
	 * of direct data so it can be used for blockrefs.
	 */
	if (error == 0) {
		error = hammer2_chain_modify(parent, xop->head.mtid, 0, 0);
		if (error == 0) {
			parent->data->ipdata.meta = xop->meta;
			if (xop->clear_directdata)
				bzero(&parent->data->ipdata.u.blockset,
				    sizeof(parent->data->ipdata.u.blockset));
		}
	}
done:
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_xop_feed(&xop->head, NULL, clindex, error);
}

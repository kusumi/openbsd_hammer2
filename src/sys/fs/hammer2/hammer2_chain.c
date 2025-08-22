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
#include "hammer2_mount.h"
#include "hammer2_xxhash.h"

#include <crypto/sha2.h>

static hammer2_chain_t *hammer2_chain_create_indirect(hammer2_chain_t *,
    hammer2_key_t, int, hammer2_tid_t, int, int *);
static int hammer2_chain_delete_obref(hammer2_chain_t *, hammer2_chain_t *,
    hammer2_tid_t, int, hammer2_blockref_t *);
static hammer2_chain_t *hammer2_combined_find(hammer2_chain_t *,
    hammer2_blockref_t *, int, hammer2_key_t *, hammer2_key_t, hammer2_key_t,
    hammer2_blockref_t **);
static hammer2_chain_t *hammer2_chain_lastdrop(hammer2_chain_t *, int);
static void hammer2_chain_load_data(hammer2_chain_t *);
static int hammer2_chain_testcheck(const hammer2_chain_t *, void *);

/*
 * Basic RBTree for chains.
 */
int
hammer2_chain_cmp(const hammer2_chain_t *chain1, const hammer2_chain_t *chain2)
{
	hammer2_key_t c1_beg, c1_end, c2_beg, c2_end;

	/*
	 * Compare chains.  Overlaps are not supposed to happen and catch
	 * any software issues early we count overlaps as a match.
	 */
	c1_beg = chain1->bref.key;
	c1_end = c1_beg + ((hammer2_key_t)1 << chain1->bref.keybits) - 1;
	c2_beg = chain2->bref.key;
	c2_end = c2_beg + ((hammer2_key_t)1 << chain2->bref.keybits) - 1;

	if (c1_end < c2_beg)	/* fully to the left */
		return (-1);
	if (c1_beg > c2_end)	/* fully to the right */
		return (1);
	return (0);		/* overlap (must not cross edge boundary) */
}

RB_GENERATE(hammer2_chain_tree, hammer2_chain, rbnode, hammer2_chain_cmp);
RB_GENERATE_SCAN(hammer2_chain_tree, hammer2_chain, rbnode);

/*
 * Assert that a chain has no media data associated with it.
 */
static __inline void
hammer2_chain_assert_no_data(const hammer2_chain_t *chain)
{
	KKASSERT(chain->dio == NULL);

	if (chain->bref.type != HAMMER2_BREF_TYPE_VOLUME &&
	    chain->bref.type != HAMMER2_BREF_TYPE_FREEMAP &&
	    chain->data)
		hpanic("%s chain %016llx/%d still has data",
		    hammer2_breftype_to_str(chain->bref.type),
		    (long long)chain->bref.key, chain->bref.keybits);
}

/*
 * Make a chain visible to the flusher.  The flusher operates using a top-down
 * recursion based on the ONFLUSH flag.  It locates MODIFIED and UPDATE chains,
 * flushes them, and updates blocks back to the volume root.
 *
 * This routine sets the ONFLUSH flag upward from the triggering chain until
 * it hits an inode root or the volume root.  Inode chains serve as inflection
 * points, requiring the flusher to bridge across trees.  Inodes include
 * regular inodes, PFS roots (pmp->iroot), and the media super root
 * (spmp->iroot).
 */
void
hammer2_chain_setflush(hammer2_chain_t *chain)
{
	hammer2_chain_t *parent;

	if ((chain->flags & HAMMER2_CHAIN_ONFLUSH) == 0) {
		hammer2_spin_sh(&chain->core.spin);
		while ((chain->flags & HAMMER2_CHAIN_ONFLUSH) == 0) {
			atomic_set_int(&chain->flags, HAMMER2_CHAIN_ONFLUSH);
			if (chain->bref.type == HAMMER2_BREF_TYPE_INODE)
				break;
			if ((parent = chain->parent) == NULL)
				break;
			hammer2_spin_sh(&parent->core.spin);
			hammer2_spin_unsh(&chain->core.spin);
			chain = parent;
		}
		hammer2_spin_unsh(&chain->core.spin);
	}
}

/*
 * Allocate a new disconnected chain element representing the specified
 * bref.  chain->refs is set to 1 and the passed bref is copied to
 * chain->bref.  chain->bytes is derived from the bref.
 *
 * Returns a referenced but unlocked (because there is no core) chain.
 */
static hammer2_chain_t *
hammer2_chain_alloc(hammer2_dev_t *hmp, hammer2_pfs_t *pmp,
    hammer2_blockref_t *bref)
{
	hammer2_chain_t *chain;
	unsigned int bytes;

	/*
	 * Special case - radix of 0 indicates a chain that does not
	 * need a data reference (context is completely embedded in the bref).
	 */
	if ((int)(bref->data_off & HAMMER2_OFF_MASK_RADIX))
		bytes = 1U << (int)(bref->data_off & HAMMER2_OFF_MASK_RADIX);
	else
		bytes = 0;

	switch (bref->type) {
	case HAMMER2_BREF_TYPE_INODE:
	case HAMMER2_BREF_TYPE_INDIRECT:
	case HAMMER2_BREF_TYPE_DATA:
	case HAMMER2_BREF_TYPE_DIRENT:
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
	case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
	case HAMMER2_BREF_TYPE_FREEMAP:
	case HAMMER2_BREF_TYPE_VOLUME:
		chain = hmalloc(sizeof(*chain), M_HAMMER2, M_WAITOK | M_ZERO);
		atomic_add_int(&hammer2_count_chain_allocated, 1);
		break;
	case HAMMER2_BREF_TYPE_EMPTY:
	default:
		hpanic("bad blockref type %d", bref->type);
		break;
	}

	/*
	 * Initialize the new chain structure.  pmp must be set to NULL for
	 * chains belonging to the super-root topology of a device mount.
	 */
	if (pmp == hmp->spmp)
		chain->pmp = NULL;
	else
		chain->pmp = pmp;

	chain->hmp = hmp;
	chain->bref = *bref;
	chain->bytes = bytes;
	chain->refs = 1;
	chain->flags = HAMMER2_CHAIN_ALLOCATED;

	/* Set the PFS boundary flag if this chain represents a PFS root. */
	if (bref->flags & HAMMER2_BREF_FLAG_PFSROOT)
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_PFSBOUNDARY);
	hammer2_chain_init(chain);

	return (chain);
}

/*
 * A common function to initialize chains including fchain and vchain.
 */
void
hammer2_chain_init(hammer2_chain_t *chain)
{
	RB_INIT(&chain->core.rbtree);
	hammer2_mtx_init_recurse(&chain->lock, "h2ch");
	hammer2_mtx_init(&chain->diolk, "h2ch_dio");
	hammer2_lk_init(&chain->inp_lock, "h2ch_inp");
	hammer2_lkc_init(&chain->inp_cv, "h2ch_inp_cv");
	hammer2_spin_init(&chain->core.spin, "h2ch_core");
}

/*
 * Add a reference to a chain element, preventing its destruction.
 * Undone via hammer2_chain_drop().
 * Can be called with spinlock held.
 */
void
hammer2_chain_ref(hammer2_chain_t *chain)
{
	if (atomic_fetchadd_int(&chain->refs, 1) == 0) {
		/* NOP */
	}
}

/*
 * Ref a locked chain and force the data to be held across an unlock.
 * Chain must be currently locked.
 */
void
hammer2_chain_ref_hold(hammer2_chain_t *chain)
{
	hammer2_mtx_assert_locked(&chain->lock);

	atomic_add_int(&chain->lockcnt, 1);
	hammer2_chain_ref(chain);
}

/*
 * Insert the chain in the core rbtree.
 *
 * Normal insertions are placed in the live rbtree.  Insertion of a deleted
 * chain is a special case used by the flush code that is placed on the
 * unstaged deleted list to avoid confusing the live view.
 */
#define HAMMER2_CHAIN_INSERT_SPIN	0x0001
#define HAMMER2_CHAIN_INSERT_LIVE	0x0002
#define HAMMER2_CHAIN_INSERT_RACE	0x0004

static int
hammer2_chain_insert(hammer2_chain_t *parent, hammer2_chain_t *chain, int flags,
    int generation)
{
	hammer2_chain_t *xchain __diagused;
	int error = 0;

	if (flags & HAMMER2_CHAIN_INSERT_SPIN)
		hammer2_spin_ex(&parent->core.spin);

	/* Interlocked by spinlock, check for race. */
	if ((flags & HAMMER2_CHAIN_INSERT_RACE) &&
	    parent->core.generation != generation) {
		error = HAMMER2_ERROR_EAGAIN;
		goto failed;
	}

	/* Insert chain. */
	xchain = RB_INSERT(hammer2_chain_tree, &parent->core.rbtree, chain);
	KASSERTMSG(xchain == NULL, "collision %016llx/%d",
	    (long long)chain->bref.key, chain->bref.keybits);

	atomic_set_int(&chain->flags, HAMMER2_CHAIN_ONRBTREE);
	chain->parent = parent;
	++parent->core.chain_count;
	++parent->core.generation; /* XXX incs for _get() too */

	/*
	 * We have to keep track of the effective live-view blockref count
	 * so the create code knows when to push an indirect block.
	 */
	if (flags & HAMMER2_CHAIN_INSERT_LIVE)
		atomic_add_int(&parent->core.live_count, 1);
failed:
	if (flags & HAMMER2_CHAIN_INSERT_SPIN)
		hammer2_spin_unex(&parent->core.spin);

	return (error);
}

/*
 * Drop the caller's reference to the chain.  When the ref count drops to
 * zero this function will try to disassociate the chain from its parent and
 * deallocate it, then recursely drop the parent using the implied ref
 * from the chain's chain->parent.
 *
 * Nobody should own chain's mutex on the 1->0 transition, unless this drop
 * races an acquisition by another cpu.  Therefore we can loop if we are
 * unable to acquire the mutex, and refs is unlikely to be 1 unless we again
 * race against another drop.
 */
void
hammer2_chain_drop(hammer2_chain_t *chain)
{
	unsigned int refs;

	KKASSERT(chain->refs > 0);

	while (chain) {
		refs = chain->refs;
		cpu_ccfence();

		KKASSERT(refs > 0);
		if (refs == 1) {
			if (hammer2_mtx_ex_try(&chain->lock) == 0)
				chain = hammer2_chain_lastdrop(chain, 0);
			/* Retry the same chain, or chain from lastdrop. */
		} else {
			if (atomic_cmpset_int(&chain->refs, refs, refs - 1))
				break;
			/* Retry the same chain. */
		}
		cpu_pause();
	}
}

/*
 * Unhold a held and probably not-locked chain, ensure that the data is
 * dropped on the 1->0 transition of lockcnt by obtaining an exclusive
 * lock and then simply unlocking the chain.
 */
void
hammer2_chain_unhold(hammer2_chain_t *chain)
{
	unsigned int lockcnt;
	int iter = 0;

	for (;;) {
		lockcnt = chain->lockcnt;
		cpu_ccfence();

		if (lockcnt > 1) {
			if (atomic_cmpset_int(&chain->lockcnt, lockcnt,
			    lockcnt - 1))
				break;
		} else if (hammer2_mtx_ex_try(&chain->lock) == 0) {
			hammer2_chain_unlock(chain);
			break;
		} else {
			/*
			 * This situation can easily occur on SMP due to
			 * the gap inbetween the 1->0 transition and the
			 * final unlock.  We cannot safely block on the
			 * mutex because lockcnt might go above 1.
			 */
			if (++iter > 1000) {
				if (iter > 1000 + hz) {
					hprintf("h2race1\n");
					iter = 1000;
				}
				tsleep(chain, PINOD, "h2race1", 1);
			}
			cpu_pause();
		}
	}
}

void
hammer2_chain_drop_unhold(hammer2_chain_t *chain)
{
	hammer2_chain_unhold(chain);
	hammer2_chain_drop(chain);
}

void
hammer2_chain_rehold(hammer2_chain_t *chain)
{
	hammer2_chain_lock(chain, HAMMER2_RESOLVE_SHARED);
	atomic_add_int(&chain->lockcnt, 1);
	hammer2_chain_unlock(chain);
}

/*
 * Handles the (potential) last drop of chain->refs from 1->0.  Called with
 * the mutex exclusively locked, refs == 1, and lockcnt 0.  SMP races are
 * possible against refs and lockcnt.  We must dispose of the mutex on chain.
 *
 * This function returns an unlocked chain for recursive drop or NULL.
 * It can return the same chain if it determines it has raced another ref.
 *
 * --
 * When two chains need to be recursively dropped we use the chain we
 * would otherwise free to placehold the additional chain.  It's a bit
 * convoluted but we can't just recurse without potentially blowing out
 * the kernel stack.
 *
 * The chain cannot be freed if it has any children.
 * The chain cannot be freed if flagged MODIFIED unless we can dispose of it.
 * The chain cannot be freed if flagged UPDATE unless we can dispose of it.
 * Any dedup registration can remain intact.
 *
 * The core spinlock is allowed to nest child-to-parent (not parent-to-child).
 */
static hammer2_chain_t *
hammer2_chain_lastdrop(hammer2_chain_t *chain, int depth)
{
	hammer2_chain_t *parent, *rdrop;

	hammer2_mtx_assert_ex(&chain->lock);

	/*
	 * We need chain's spinlock to interlock the sub-tree test.
	 * We already have chain's mutex, protecting chain->parent.
	 * Remember that chain->refs can be in flux.
	 */
	hammer2_spin_ex(&chain->core.spin);

	if (chain->parent != NULL) {
		/*
		 * If the chain has a parent the UPDATE bit prevents scrapping
		 * as the chain is needed to properly flush the parent.  Try
		 * to complete the 1->0 transition and return NULL.  Retry
		 * (return chain) if we are unable to complete the 1->0
		 * transition, else return NULL (nothing more to do).
		 *
		 * If the chain has a parent the MODIFIED bit prevents
		 * scrapping.
		 */
		if (chain->flags &
		    (HAMMER2_CHAIN_UPDATE | HAMMER2_CHAIN_MODIFIED)) {
			if (atomic_cmpset_int(&chain->refs, 1, 0)) {
				hammer2_spin_unex(&chain->core.spin);
				hammer2_chain_assert_no_data(chain);
				hammer2_mtx_unlock(&chain->lock);
				chain = NULL;
			} else {
				hammer2_spin_unex(&chain->core.spin);
				hammer2_mtx_unlock(&chain->lock);
			}
			return (chain);
		}
		/* spinlock still held */
	} else if (chain->bref.type == HAMMER2_BREF_TYPE_VOLUME ||
	    chain->bref.type == HAMMER2_BREF_TYPE_FREEMAP) {
		/*
		 * Retain the static vchain and fchain.  Clear bits that
		 * are not relevant.  Do not clear the MODIFIED bit,
		 * and certainly do not put it on the delayed-flush queue.
		 */
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_UPDATE);
	} else {
		/*
		 * The chain has no parent and can be flagged for destruction.
		 * Since it has no parent, UPDATE can also be cleared.
		 *
		 * This can happen for e.g. via
		 *  hammer2_chain_lookup()
		 *    hammer2_chain_get()
		 *      hammer2_chain_insert() -> HAMMER2_ERROR_EAGAIN
		 *      hammer2_chain_drop() (chain->parent still NULL)
		 *        hammer2_chain_lastdrop()
		 */
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_DESTROY);
		if (chain->flags & HAMMER2_CHAIN_UPDATE)
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_UPDATE);

		/*
		 * If the chain has children we must propagate the DESTROY
		 * flag downward and rip the disconnected topology apart.
		 * This is accomplished by calling hammer2_flush() on the
		 * chain.
		 *
		 * Any dedup is already handled by the underlying DIO, so
		 * we do not have to specifically flush it here.
		 */
		if (chain->core.chain_count) {
			hammer2_spin_unex(&chain->core.spin);
			hammer2_flush(chain,
			    HAMMER2_FLUSH_TOP | HAMMER2_FLUSH_ALL);
			hammer2_mtx_unlock(&chain->lock);
			return (chain); /* retry drop */
		}

		/*
		 * Otherwise we can scrap the MODIFIED bit if it is set,
		 * and continue along the freeing path.
		 *
		 * Be sure to clean-out any dedup bits.  Without a parent
		 * this chain will no longer be visible to the flush code.
		 * Easy check data_off to avoid the volume root.
		 */
		if (chain->flags & HAMMER2_CHAIN_MODIFIED) {
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_MODIFIED);
			atomic_add_int(&hammer2_count_chain_modified, -1);
		}
		/* spinlock still held */
	}
	/* spinlock still held */

	/*
	 * If any children exist we must leave the chain intact with refs == 0.
	 * They exist because chains are retained below us which have refs or
	 * may require flushing.
	 *
	 * Retry (return chain) if we fail to transition the refs to 0, else
	 * return NULL indication nothing more to do.
	 */
	if (chain->core.chain_count) {
		if (atomic_cmpset_int(&chain->refs, 1, 0)) {
			hammer2_spin_unex(&chain->core.spin);
			hammer2_chain_assert_no_data(chain);
			hammer2_mtx_unlock(&chain->lock);
			chain = NULL;
		} else {
			hammer2_spin_unex(&chain->core.spin);
			hammer2_mtx_unlock(&chain->lock);
		}
		return (chain);
	}
	/* Spinlock still held. */
	/* No chains left under us. */

	/*
	 * chain->core has no children left so no accessors can get to our
	 * chain from there.  Now we have to lock the parent core to interlock
	 * remaining possible accessors that might bump chain's refs before
	 * we can safely drop chain's refs with intent to free the chain.
	 */
	rdrop = NULL;
	parent = chain->parent;

	/*
	 * WARNING! chain's spin lock is still held here, and other spinlocks
	 *	    will be acquired and released in the code below.  We
	 *	    cannot be making fancy procedure calls!
	 */

	/*
	 * Spinlock the parent and try to drop the last ref on chain.
	 * On success determine if we should dispose of the chain
	 * (remove the chain from its parent, etc).
	 *
	 * Normal core locks are top-down recursive but we define
	 * core spinlocks as bottom-up recursive, so this is safe.
	 */
	if (parent) {
		hammer2_spin_ex(&parent->core.spin);
		if (atomic_cmpset_int(&chain->refs, 1, 0) == 0) {
			/* 1->0 transition failed, retry. */
			hammer2_spin_unex(&parent->core.spin);
			hammer2_spin_unex(&chain->core.spin);
			hammer2_mtx_unlock(&chain->lock);
			return (chain);
		}

		/*
		 * 1->0 transition successful, parent spin held to prevent
		 * new lookups, chain spinlock held to protect parent field.
		 * Remove chain from the parent.
		 *
		 * If the chain is being removed from the parent's rbtree but
		 * is not blkmapped, we have to adjust live_count downward.  If
		 * it is blkmapped then the blockref is retained in the parent
		 * as is its associated live_count.  This case can occur when
		 * a chain added to the topology is unable to flush and is
		 * then later deleted.
		 */
		if (chain->flags & HAMMER2_CHAIN_ONRBTREE) {
			if ((parent->flags & HAMMER2_CHAIN_COUNTEDBREFS) &&
			    (chain->flags & HAMMER2_CHAIN_BLKMAPPED) == 0)
				atomic_add_int(&parent->core.live_count, -1);
			RB_REMOVE(hammer2_chain_tree, &parent->core.rbtree,
			    chain);
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_ONRBTREE);
			--parent->core.chain_count;
			chain->parent = NULL;
		}

		/*
		 * If our chain was the last chain in the parent's core the
		 * core is now empty and its parent might have to be
		 * re-dropped if it has 0 refs.
		 */
		if (parent->core.chain_count == 0) {
			rdrop = parent;
			atomic_add_int(&rdrop->refs, 1);
		}
		hammer2_spin_unex(&parent->core.spin);
		parent = NULL; /* safety */
	} else {
		/* No-parent case. */
		if (atomic_cmpset_int(&chain->refs, 1, 0) == 0) {
			/* 1->0 transition failed, retry. */
			hammer2_spin_unex(&parent->core.spin);
			hammer2_spin_unex(&chain->core.spin);
			hammer2_mtx_unlock(&chain->lock);
			return (chain);
		}
	}

	/*
	 * Successful 1->0 transition, no parent, no children... no way for
	 * anyone to ref this chain any more.  We can clean-up and free it.
	 *
	 * We still have the core spinlock, and core's chain_count is 0.
	 * Any parent spinlock is gone.
	 */
	hammer2_spin_unex(&chain->core.spin);
	hammer2_chain_assert_no_data(chain);
	hammer2_mtx_unlock(&chain->lock);
	KKASSERT(RB_EMPTY(&chain->core.rbtree) && chain->core.chain_count == 0);

	/*
	 * All locks are gone, no pointers remain to the chain, finish
	 * freeing it.
	 */
	KKASSERT((chain->flags &
	    (HAMMER2_CHAIN_UPDATE | HAMMER2_CHAIN_MODIFIED)) == 0);

	/*
	 * Once chain resources are gone we can use the now dead chain
	 * structure to placehold what might otherwise require a recursive
	 * drop, because we have potentially two things to drop and can only
	 * return one directly.
	 */
	if (chain->flags & HAMMER2_CHAIN_ALLOCATED) {
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_ALLOCATED);
		hammer2_mtx_destroy(&chain->lock);
		hammer2_mtx_destroy(&chain->diolk);
		hammer2_lk_destroy(&chain->inp_lock);
		hammer2_lkc_destroy(&chain->inp_cv);
		hammer2_spin_destroy(&chain->core.spin);
		chain->hmp = NULL;
		hfree(chain, M_HAMMER2, sizeof(*chain));
		atomic_add_int(&hammer2_count_chain_allocated, -1);
	}

	/* Possible chaining loop when parent re-drop needed. */
	return (rdrop);
}

/*
 * On last lock release.
 */
static hammer2_io_t *
hammer2_chain_drop_data(hammer2_chain_t *chain)
{
	hammer2_io_t *dio;

	if ((dio = chain->dio) != NULL) {
		chain->dio = NULL;
		chain->data = NULL;
	} else {
		switch (chain->bref.type) {
		case HAMMER2_BREF_TYPE_VOLUME:
		case HAMMER2_BREF_TYPE_FREEMAP:
			break;
		default:
			if (chain->data != NULL)
				hpanic("%s chain %016llx/%d data not NULL",
				    hammer2_breftype_to_str(chain->bref.type),
				    (long long)chain->bref.key,
				    chain->bref.keybits);
			KKASSERT(chain->data == NULL);
			break;
		}
	}
	return (dio);
}

/*
 * Lock a referenced chain element, acquiring its data with I/O if necessary,
 * and specify how you would like the data to be resolved.
 *
 * If an I/O or other fatal error occurs, chain->error will be set to non-zero.
 *
 * The lock is allowed to recurse, multiple locking ops will aggregate
 * the requested resolve types.  Once data is assigned it will not be
 * removed until the last unlock.
 *
 * HAMMER2_RESOLVE_NEVER - Do not resolve the data element.
 *			   (typically used to avoid device/logical buffer
 *			    aliasing for data)
 *
 * HAMMER2_RESOLVE_MAYBE - Do not resolve data elements for chains in
 *			   the INITIAL-create state (indirect blocks only).
 *
 *			   Do not resolve data elements for DATA chains.
 *			   (typically used to avoid device/logical buffer
 *			    aliasing for data)
 *
 * HAMMER2_RESOLVE_ALWAYS- Always resolve the data element.
 *
 * HAMMER2_RESOLVE_SHARED- (flag) The chain is locked shared, otherwise
 *			   it will be locked exclusive.
 *
 * HAMMER2_RESOLVE_NONBLOCK- (flag) The chain is locked non-blocking.
 *			   If the lock fails, EAGAIN is returned.
 *
 * NOTE: Embedded elements (volume header, inodes) are always resolved
 *	 regardless.
 *
 * NOTE: Specifying HAMMER2_RESOLVE_ALWAYS on a newly-created non-embedded
 *	 element will instantiate and zero its buffer, and flush it on
 *	 release.
 *
 * NOTE: (data) elements are normally locked RESOLVE_MAYBE
 *	 so as not to instantiate a device buffer, which could alias against
 *	 a logical file buffer.  However, if ALWAYS is specified the
 *	 device buffer will be instantiated anyway.
 *
 * NOTE: The return value is always 0 unless NONBLOCK is specified, in which
 *	 case it can be either 0 or EAGAIN.
 *
 * WARNING! This function blocks on I/O if data needs to be fetched.  This
 *	    blocking can run concurrent with other compatible lock holders
 *	    who do not need data returning.
 */
int
hammer2_chain_lock(hammer2_chain_t *chain, int how)
{
	KKASSERT(chain->refs > 0);

	if (how & HAMMER2_RESOLVE_NONBLOCK) {
		/*
		 * We still have to bump lockcnt before acquiring the lock,
		 * even for non-blocking operation, because the unlock code
		 * live-loops on lockcnt == 1 when dropping the last lock.
		 *
		 * If the non-blocking operation fails we have to use an
		 * unhold sequence to undo the mess.
		 *
		 * NOTE: LOCKAGAIN must always succeed without blocking,
		 *	 even if NONBLOCK is specified.
		 */
		atomic_add_int(&chain->lockcnt, 1);
		if (how & HAMMER2_RESOLVE_SHARED) {
			if (how & HAMMER2_RESOLVE_LOCKAGAIN) {
				hammer2_mtx_assert_locked(&chain->lock);
				hammer2_mtx_assert_sh(&chain->lock);
				hammer2_mtx_sh(&chain->lock);
				hammer2_mtx_assert_sh(&chain->lock);
			} else {
				if (hammer2_mtx_sh_try(&chain->lock) != 0) {
					hammer2_chain_unhold(chain);
					return (EAGAIN);
				}
			}
		} else {
			if (hammer2_mtx_ex_try(&chain->lock) != 0) {
				hammer2_chain_unhold(chain);
				return (EAGAIN);
			}
		}
	} else {
		/*
		 * Get the appropriate lock.  If LOCKAGAIN is flagged with
		 * SHARED the caller expects a shared lock to already be
		 * present and we are giving it another ref.  This case must
		 * importantly not block if there is a pending exclusive lock
		 * request.
		 */
		atomic_add_int(&chain->lockcnt, 1);
		if (how & HAMMER2_RESOLVE_SHARED) {
			if (how & HAMMER2_RESOLVE_LOCKAGAIN) {
				hammer2_mtx_assert_locked(&chain->lock);
				hammer2_mtx_assert_sh(&chain->lock);
				hammer2_mtx_sh(&chain->lock);
				hammer2_mtx_assert_sh(&chain->lock);
			} else {
				hammer2_mtx_sh(&chain->lock);
			}
		} else {
			hammer2_mtx_ex(&chain->lock);
		}
	}

	/*
	 * If we already have a valid data pointer no further action is
	 * necessary.
	 */
	if (chain->data)
		return (0);

	/*
	 * Do we have to resolve the data?  This is generally only
	 * applicable to HAMMER2_BREF_TYPE_DATA which is special-cased.
	 * Other bref types expects the data to be there.
	 */
	switch (how & HAMMER2_RESOLVE_MASK) {
	case HAMMER2_RESOLVE_NEVER:
		return (0);
	case HAMMER2_RESOLVE_MAYBE:
		if (chain->flags & HAMMER2_CHAIN_INITIAL)
			return (0);
		if (chain->bref.type == HAMMER2_BREF_TYPE_DATA)
			return (0);
		/* fall through */
	case HAMMER2_RESOLVE_ALWAYS:
	default:
		break;
	}

	/* Caller requires data. */
	hammer2_chain_load_data(chain);

	return (0);
}

/*
 * Issue I/O and install chain->data.  Caller must hold a chain lock, lock
 * may be of any type.
 *
 * Once chain->data is set it cannot be disposed of until all locks are
 * released.
 */
static void
hammer2_chain_load_data(hammer2_chain_t *chain)
{
	hammer2_dev_t *hmp;
	hammer2_blockref_t *bref;
	char *bdata;
	int error;

	/*
	 * Degenerate case, data already present, or chain has no media
	 * reference to load.
	 */
	if (chain->data)
		return;
	if ((chain->bref.data_off & ~HAMMER2_OFF_MASK_RADIX) == 0)
		return;

	hmp = chain->hmp;
	KKASSERT(hmp != NULL);

	/*
	 * inp_lock protects HAMMER2_CHAIN_{IOINPROG,SIGNAL} bits.
	 * DragonFly uses tsleep_interlock(9) here without taking mutex.
	 */
	hammer2_lk_ex(&chain->inp_lock);
again:
	if (chain->flags & HAMMER2_CHAIN_IOINPROG) {
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_IOSIGNAL);
		hammer2_lkc_sleep(&chain->inp_cv, &chain->inp_lock, "h2ch_inp",
		    0);
		goto again;
	}
	atomic_set_int(&chain->flags, HAMMER2_CHAIN_IOINPROG);
	hammer2_lk_unlock(&chain->inp_lock);

	/*
	 * We own CHAIN_IOINPROG.
	 * Degenerate case if we raced another load.
	 */
	if (chain->data)
		goto done;

	/*
	 * The getblk() optimization can only be used on newly created
	 * elements if the physical block size matches the request.
	 */
	bref = &chain->bref;
	if (chain->flags & HAMMER2_CHAIN_INITIAL)
		error = hammer2_io_new(hmp, bref->type, bref->data_off,
		    chain->bytes, &chain->dio);
	else
		error = hammer2_io_bread(hmp, bref->type, bref->data_off,
		    chain->bytes, &chain->dio);
	if (error) {
		hprintf("%s blockref I/O error %d at %016llx\n",
		    hammer2_breftype_to_str(bref->type), error,
		    (long long)bref->data_off);
		chain->error = HAMMER2_ERROR_EIO;
		hammer2_io_bqrelse(&chain->dio);
		goto done;
	}
	chain->error = 0;

	/*
	 * NOTE: A locked chain's data cannot be modified without first
	 *	 calling hammer2_chain_modify().
	 */
	bdata = hammer2_io_data(chain->dio, bref->data_off);

	if (chain->flags & HAMMER2_CHAIN_INITIAL) {
		/*
		 * Clear INITIAL.  In this case we used io_new() and the
		 * buffer has been zero'd and marked dirty.
		 *
		 * CHAIN_MODIFIED has not been set yet, and we leave it
		 * that way for now.  Set a temporary CHAIN_NOTTESTED flag
		 * to prevent hammer2_chain_testcheck() from trying to match
		 * a check code that has not yet been generated.  This bit
		 * should NOT end up on the actual media.
		 */
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_NOTTESTED);
	} else if (chain->flags & HAMMER2_CHAIN_MODIFIED) {
		/*
		 * Check data not currently synchronized due to
		 * modification.  XXX assumes data stays in the buffer
		 * cache, which might not be true (need biodep on flush
		 * to calculate crc?  or simple crc?).
		 */
	} else if ((chain->flags & HAMMER2_CHAIN_TESTEDGOOD) == 0) {
		if (hammer2_chain_testcheck(chain, bdata) == 0)
			chain->error = HAMMER2_ERROR_CHECK;
		else
			atomic_set_int(&chain->flags, HAMMER2_CHAIN_TESTEDGOOD);
	}

	/* Setup the data pointer by pointing it into the buffer. */
	switch (bref->type) {
	case HAMMER2_BREF_TYPE_VOLUME:
	case HAMMER2_BREF_TYPE_FREEMAP:
		hpanic("unresolved volume header");
		break;
	case HAMMER2_BREF_TYPE_DIRENT:
		KKASSERT(chain->bytes != 0);
		/* fall through */
	case HAMMER2_BREF_TYPE_INODE:
	case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
	case HAMMER2_BREF_TYPE_INDIRECT:
	case HAMMER2_BREF_TYPE_DATA:
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
	default:
		/* Point data at the device buffer and leave dio intact. */
		chain->data = (void *)bdata;
		break;
	}
done:
	/* Release HAMMER2_CHAIN_IOINPROG and signal waiters if requested. */
	KKASSERT(chain->flags & HAMMER2_CHAIN_IOINPROG);
	hammer2_lk_ex(&chain->inp_lock);
	atomic_clear_int(&chain->flags, HAMMER2_CHAIN_IOINPROG);
	if (chain->flags & HAMMER2_CHAIN_IOSIGNAL) {
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_IOSIGNAL);
		hammer2_lkc_wakeup(&chain->inp_cv);
	}
	hammer2_lk_unlock(&chain->inp_lock);
}

/*
 * Unlock and deref a chain element.
 *
 * Remember that the presence of children under chain prevent the chain's
 * destruction but do not add additional references, so the dio will still
 * be dropped.
 */
void
hammer2_chain_unlock(hammer2_chain_t *chain)
{
	hammer2_io_t *dio;
	unsigned int lockcnt;
	int iter = 0;

	/*
	 * If multiple locks are present (or being attempted) on this
	 * particular chain we can just unlock, drop refs, and return.
	 *
	 * Otherwise fall-through on the 1->0 transition.
	 */
	for (;;) {
		lockcnt = chain->lockcnt;
		KKASSERT(lockcnt > 0);
		cpu_ccfence();

		if (lockcnt > 1) {
			if (atomic_cmpset_int(&chain->lockcnt, lockcnt,
			    lockcnt - 1)) {
				hammer2_mtx_unlock(&chain->lock);
				return;
			}
		} else if (hammer2_mtx_upgrade_try(&chain->lock) == 0) {
			/* While holding the mutex exclusively. */
			if (atomic_cmpset_int(&chain->lockcnt, 1, 0))
				break;
		} else {
			/*
			 * This situation can easily occur on SMP due to
			 * the gap inbetween the 1->0 transition and the
			 * final unlock.  We cannot safely block on the
			 * mutex because lockcnt might go above 1.
			 */
			if (++iter > 1000) {
				if (iter > 1000 + hz) {
					hprintf("h2race2\n");
					iter = 1000;
				}
				tsleep(chain, PINOD, "h2race2", 1);
			}
			cpu_pause();
		}
	}

	/*
	 * Last unlock / mutex upgraded to exclusive.  Drop the data
	 * reference.
	 */
	dio = hammer2_chain_drop_data(chain);
	if (dio)
		hammer2_io_bqrelse(&dio);
	hammer2_mtx_unlock(&chain->lock);
}

/*
 * Helper to obtain the blockref[] array base and count for a chain.
 *
 * XXX Not widely used yet, various use cases need to be validated and
 *     converted to use this function.
 */
static hammer2_blockref_t *
hammer2_chain_base_and_count(hammer2_chain_t *parent, int *countp)
{
	hammer2_blockref_t *base = NULL;
	int count;

	if (parent->flags & HAMMER2_CHAIN_INITIAL) {
		switch (parent->bref.type) {
		case HAMMER2_BREF_TYPE_INODE:
			count = HAMMER2_SET_COUNT;
			break;
		case HAMMER2_BREF_TYPE_INDIRECT:
		case HAMMER2_BREF_TYPE_FREEMAP_NODE:
			count = parent->bytes / sizeof(hammer2_blockref_t);
			break;
		case HAMMER2_BREF_TYPE_VOLUME:
			count = HAMMER2_SET_COUNT;
			break;
		case HAMMER2_BREF_TYPE_FREEMAP:
			count = HAMMER2_SET_COUNT;
			break;
		default:
			hpanic("bad blockref type %d", parent->bref.type);
			break;
		}
	} else {
		switch (parent->bref.type) {
		case HAMMER2_BREF_TYPE_INODE:
			base = &parent->data->ipdata.u.blockset.blockref[0];
			count = HAMMER2_SET_COUNT;
			break;
		case HAMMER2_BREF_TYPE_INDIRECT:
		case HAMMER2_BREF_TYPE_FREEMAP_NODE:
			base = &parent->data->npdata[0];
			count = parent->bytes / sizeof(hammer2_blockref_t);
			break;
		case HAMMER2_BREF_TYPE_VOLUME:
			base = &parent->data->voldata.sroot_blockset.blockref[0];
			count = HAMMER2_SET_COUNT;
			break;
		case HAMMER2_BREF_TYPE_FREEMAP:
			base = &parent->data->blkset.blockref[0];
			count = HAMMER2_SET_COUNT;
			break;
		default:
			hpanic("bad blockref type %d", parent->bref.type);
			break;
		}
	}
	*countp = count;

	return (base);
}

/*
 * This counts the number of live blockrefs in a block array and
 * also calculates the point at which all remaining blockrefs are empty.
 * This routine can only be called on a live chain.
 *
 * Caller holds the chain locked, but possibly with a shared lock.  We
 * must use an exclusive spinlock to prevent corruption.
 *
 * NOTE: Flag is not set until after the count is complete, allowing
 *	 callers to test the flag without holding the spinlock.
 *
 * NOTE: If base is NULL the related chain is still in the INITIAL
 *	 state and there are no blockrefs to count.
 *
 * NOTE: live_count may already have some counts accumulated due to
 *	 creation and deletion and could even be initially negative.
 */
static void
hammer2_chain_countbrefs(hammer2_chain_t *chain, hammer2_blockref_t *base,
    int count)
{
	hammer2_mtx_assert_locked(&chain->lock);

	hammer2_spin_ex(&chain->core.spin);
	if ((chain->flags & HAMMER2_CHAIN_COUNTEDBREFS) == 0) {
		if (base) {
			while (--count >= 0)
				if (base[count].type != HAMMER2_BREF_TYPE_EMPTY)
					break;
			chain->core.live_zero = count + 1;
			while (count >= 0) {
				if (base[count].type != HAMMER2_BREF_TYPE_EMPTY)
					atomic_add_int(&chain->core.live_count,
					    1);
				--count;
			}
		} else {
			chain->core.live_zero = 0;
		}
		/* else do not modify live_count */
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_COUNTEDBREFS);
	}
	hammer2_spin_unex(&chain->core.spin);
}

/*
 * Resize the chain's physical storage allocation in-place.  This function does
 * not usually adjust the data pointer and must be followed by (typically) a
 * hammer2_chain_modify() call to copy any old data over and adjust the
 * data pointer.
 *
 * Chains can be resized smaller without reallocating the storage.  Resizing
 * larger will reallocate the storage.  Excess or prior storage is reclaimed
 * asynchronously at a later time.
 *
 * An nradix value of 0 is special-cased to mean that the storage should
 * be disassociated, that is the chain is being resized to 0 bytes (not 1
 * byte).
 *
 * Must be passed an exclusively locked parent and chain.
 *
 * This function is mostly used with DATA blocks locked RESOLVE_NEVER in order
 * to avoid instantiating a device buffer that conflicts with the vnode data
 * buffer.  However, because H2 can compress or encrypt data, the chain may
 * have a dio assigned to it in those situations, and they do not conflict.
 *
 * XXX return error if cannot resize.
 */
int
hammer2_chain_resize(hammer2_chain_t *chain, hammer2_tid_t mtid,
    hammer2_off_t dedup_off, int nradix, int flags)
{
	size_t obytes, nbytes;
	int error;

	/*
	 * Only data and indirect blocks can be resized for now.
	 * (The volu root, inodes, and freemap elements use a fixed size).
	 */
	KKASSERT(chain != &chain->hmp->vchain);
	KKASSERT(chain->bref.type == HAMMER2_BREF_TYPE_DATA ||
	    chain->bref.type == HAMMER2_BREF_TYPE_INDIRECT ||
	    chain->bref.type == HAMMER2_BREF_TYPE_DIRENT);

	/* Nothing to do if the element is already the proper size. */
	obytes = chain->bytes;
	nbytes = (nradix) ? (1U << nradix) : 0;
	if (obytes == nbytes)
		return (chain->error);

	/*
	 * Make sure the old data is instantiated so we can copy it.  If this
	 * is a data block, the device data may be superfluous since the data
	 * might be in a logical block, but compressed or encrypted data is
	 * another matter.
	 *
	 * NOTE: The modify will set BLKMAPUPD for us if BLKMAPPED is set.
	 */
	error = hammer2_chain_modify(chain, mtid, dedup_off, 0);
	if (error)
		return (error);

	/*
	 * Reallocate the block, even if making it smaller (because different
	 * block sizes may be in different regions).
	 *
	 * NOTE: Operation does not copy the data and may only be used
	 *	 to resize data blocks in-place, or directory entry blocks
	 *	 which are about to be modified in some manner.
	 */
	error = hammer2_freemap_alloc(chain, nbytes);
	if (error)
		return (error);

	chain->bytes = nbytes;

	/*
	 * We don't want the followup chain_modify() to try to copy data
	 * from the old (wrong-sized) buffer.  It won't know how much to
	 * copy.  This case should only occur during writes when the
	 * originator already has the data to write in-hand.
	 */
	if (chain->dio) {
		KKASSERT(chain->bref.type == HAMMER2_BREF_TYPE_DATA ||
		    chain->bref.type == HAMMER2_BREF_TYPE_DIRENT);
		hammer2_io_brelse(&chain->dio);
		chain->data = NULL;
	}
	return (chain->error);
}

/*
 * Set the chain modified so its data can be changed by the caller, or
 * install deduplicated data.  The caller must call this routine for each
 * set of modifications it makes, even if the chain is already flagged
 * MODIFIED.
 *
 * Sets bref.modify_tid to mtid only if mtid != 0.  Note that bref.modify_tid
 * is a CLC (cluster level change) field and is not updated by parent
 * propagation during a flush.
 *
 * Returns an appropriate HAMMER2_ERROR_* code, which will generally reflect
 * chain->error except for HAMMER2_ERROR_ENOSPC.  If the allocation fails
 * due to no space available, HAMMER2_ERROR_ENOSPC is returned and the chain
 * remains unmodified with its old data ref intact and chain->error
 * unchanged.
 *
 *		Dedup Handling
 *
 * If the DEDUPABLE flag is set in the chain the storage must be reallocated
 * even if the chain is still flagged MODIFIED.  In this case the chain's
 * DEDUPABLE flag will be cleared once the new storage has been assigned.
 *
 * If the caller passes a non-zero dedup_off we will use it to assign the
 * new storage.  The MODIFIED flag will be *CLEARED* in this case, and
 * DEDUPABLE will be set (NOTE: the UPDATE flag is always set).  The caller
 * must not modify the data content upon return.
 */
int
hammer2_chain_modify(hammer2_chain_t *chain, hammer2_tid_t mtid,
    hammer2_off_t dedup_off, int flags)
{
	hammer2_dev_t *hmp = chain->hmp;
	hammer2_io_t *dio, *tio;
	int wasinitial, setmodified, setupdate, newmod, error = 0;
	char *bdata;

	hammer2_mtx_assert_ex(&chain->lock);

	/*
	 * Data is not optional for freemap chains (we must always be sure
	 * to copy the data on COW storage allocations).
	 */
	if (chain->bref.type == HAMMER2_BREF_TYPE_FREEMAP_NODE ||
	    chain->bref.type == HAMMER2_BREF_TYPE_FREEMAP_LEAF)
		KKASSERT((chain->flags & HAMMER2_CHAIN_INITIAL) ||
		    (flags & HAMMER2_MODIFY_OPTDATA) == 0);

	/*
	 * Data must be resolved if already assigned, unless explicitly
	 * flagged otherwise.  If we cannot safety load the data the
	 * modification fails and we return early.
	 */
	if (chain->data == NULL && chain->bytes != 0 &&
	    (flags & HAMMER2_MODIFY_OPTDATA) == 0 &&
	    (chain->bref.data_off & ~HAMMER2_OFF_MASK_RADIX)) {
		hammer2_chain_load_data(chain);
		if (chain->error)
			return (chain->error);
	}

	/*
	 * Set MODIFIED to indicate that the chain has been modified.  A new
	 * allocation is required when modifying a chain.
	 *
	 * Set UPDATE to ensure that the blockref is updated in the parent.
	 *
	 * If MODIFIED is already set determine if we can reuse the assigned
	 * data block or if we need a new data block.
	 */
	if ((chain->flags & HAMMER2_CHAIN_MODIFIED) == 0) {
		/* Must set modified bit. */
		atomic_add_int(&hammer2_count_chain_modified, 1);
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_MODIFIED);
		setmodified = 1;

		/*
		 * We may be able to avoid a copy-on-write if the chain's
		 * check mode is set to NONE and the chain's current
		 * modify_tid is beyond the last explicit snapshot tid.
		 *
		 * This implements HAMMER2's overwrite-in-place feature.
		 *
		 * NOTE! This data-block cannot be used as a de-duplication
		 *	 source when the check mode is set to NONE.
		 */
		if ((chain->bref.type == HAMMER2_BREF_TYPE_DATA ||
		    chain->bref.type == HAMMER2_BREF_TYPE_DIRENT) &&
		    (chain->flags & HAMMER2_CHAIN_INITIAL) == 0 &&
		    (chain->flags & HAMMER2_CHAIN_DEDUPABLE) == 0 &&
		    HAMMER2_DEC_CHECK(chain->bref.methods) ==
		    HAMMER2_CHECK_NONE && chain->pmp &&
		    chain->bref.modify_tid >
		    chain->pmp->iroot->meta.pfs_lsnap_tid) {
			/* Sector overwrite allowed. */
			newmod = 0;
		} else if ((hmp->hflags & HMNT2_EMERG) && chain->pmp &&
		    chain->bref.modify_tid >
		    chain->pmp->iroot->meta.pfs_lsnap_tid) {
			/*
			 * If in emergency delete mode then do a modify-in-
			 * place on any chain type belonging to the PFS as
			 * long as it doesn't mess up a snapshot.  We might
			 * be forced to do this anyway a little further down
			 * in the code if the allocation fails.
			 *
			 * Also note that in emergency mode, these modify-in-
			 * place operations are NOT SAFE.  A storage failure,
			 * power failure, or panic can corrupt the filesystem.
			 */
			newmod = 0;
		} else {
			/* Sector overwrite not allowed, must copy-on-write. */
			newmod = 1;
		}
	} else if (chain->flags & HAMMER2_CHAIN_DEDUPABLE) {
		/*
		 * If the modified chain was registered for dedup we need
		 * a new allocation.  This only happens for delayed-flush
		 * chains (i.e. which run through the front-end buffer
		 * cache).
		 */
		newmod = 1;
		setmodified = 0;
	} else {
		/* Already flagged modified, no new allocation is needed. */
		newmod = 0;
		setmodified = 0;
	}

	/* Flag parent update required. */
	if ((chain->flags & HAMMER2_CHAIN_UPDATE) == 0) {
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_UPDATE);
		setupdate = 1;
	} else {
		setupdate = 0;
	}

	/*
	 * The XOP code returns held but unlocked focus chains.  This
	 * prevents the chain from being destroyed but does not prevent
	 * it from being modified.  diolk is used to interlock modifications
	 * against XOP frontend accesses to the focus.
	 *
	 * This allows us to theoretically avoid deadlocking the frontend
	 * if one of the backends lock up by not formally locking the
	 * focused chain in the frontend.  In addition, the synchronization
	 * code relies on this mechanism to avoid deadlocking concurrent
	 * synchronization threads.
	 */
	hammer2_mtx_ex(&chain->diolk);

	/*
	 * The modification or re-modification requires an allocation and
	 * possible COW.  If an error occurs, the previous content and data
	 * reference is retained and the modification fails.
	 *
	 * If dedup_off is non-zero, the caller is requesting a deduplication
	 * rather than a modification.  The MODIFIED bit is not set and the
	 * data offset is set to the deduplication offset.  The data cannot
	 * be modified.
	 *
	 * NOTE: The dedup offset is allowed to be in a partially free state
	 *	 and we must be sure to reset it to a fully allocated state
	 *	 to force two bulkfree passes to free it again.
	 *
	 * NOTE: Only applicable when chain->bytes != 0.
	 *
	 * XXX Can a chain already be marked MODIFIED without a data
	 * assignment?  If not, assert here instead of testing the case.
	 */
	if (chain != &hmp->vchain && chain != &hmp->fchain && chain->bytes) {
		if ((chain->bref.data_off & ~HAMMER2_OFF_MASK_RADIX) == 0 ||
		    newmod) {
			/*
			 * NOTE: We do not have to remove the dedup
			 *	 registration because the area is still
			 *	 allocated and the underlying DIO will
			 *	 still be flushed.
			 */
			if (dedup_off) {
				chain->bref.data_off = dedup_off;
				if ((int)(dedup_off & HAMMER2_OFF_MASK_RADIX))
					chain->bytes = 1 <<
					    (int)(dedup_off &
					    HAMMER2_OFF_MASK_RADIX);
				else
					chain->bytes = 0;
				chain->error = 0;
				atomic_clear_int(&chain->flags,
				    HAMMER2_CHAIN_MODIFIED);
				atomic_add_int(&hammer2_count_chain_modified,
				    -1);
				hammer2_freemap_adjust(hmp, &chain->bref,
				    HAMMER2_FREEMAP_DORECOVER);
				atomic_set_int(&chain->flags,
				    HAMMER2_CHAIN_DEDUPABLE);
			} else {
				error = hammer2_freemap_alloc(chain,
				    chain->bytes);
				atomic_clear_int(&chain->flags,
				    HAMMER2_CHAIN_DEDUPABLE);

				/*
				 * If we are unable to allocate a new block
				 * but we are in emergency mode, issue a
				 * warning to the console and reuse the same
				 * block.
				 *
				 * We behave as if the allocation were
				 * successful.
				 *
				 * THIS IS IMPORTANT: These modifications
				 * are virtually guaranteed to corrupt any
				 * snapshots related to this filesystem.
				 */
				if (error && (hmp->hflags & HMNT2_EMERG)) {
					error = 0;
					chain->bref.flags |=
					    HAMMER2_BREF_FLAG_EMERG_MIP;
				} else if (error == 0) {
					chain->bref.flags &=
					    ~HAMMER2_BREF_FLAG_EMERG_MIP;
				}
			}
			if (dedup_off)
				debug_hprintf("%s %s chain %016llx %016llx/%d\n",
				    dedup_off ? "dedup" : "alloc",
				    hammer2_breftype_to_str(chain->bref.type),
				    (long long)chain->bref.data_off,
				    (long long)chain->bref.key,
				    chain->bref.keybits);
		}
	}

	/*
	 * Stop here if error.  We have to undo any flag bits we might
	 * have set above.
	 */
	if (error) {
		if (setmodified) {
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_MODIFIED);
			atomic_add_int(&hammer2_count_chain_modified, -1);
		}
		if (setupdate)
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_UPDATE);
		hammer2_mtx_unlock(&chain->diolk);
		return (error);
	}

	/*
	 * Update mirror_tid and modify_tid.  modify_tid is only updated
	 * if not passed as zero (during flushes, parent propagation passes
	 * the value 0).
	 *
	 * NOTE: chain->pmp could be the device spmp.
	 */
	chain->bref.mirror_tid = hmp->voldata.mirror_tid + 1;
	if (mtid)
		chain->bref.modify_tid = mtid;

	/*
	 * Set BLKMAPUPD to tell the flush code that an existing blockmap entry
	 * requires updating as well as to tell the delete code that the
	 * chain's blockref might not exactly match (in terms of physical size
	 * or block offset) the one in the parent's blocktable.  The base key
	 * of course will still match.
	 */
	if (chain->flags & HAMMER2_CHAIN_BLKMAPPED)
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_BLKMAPUPD);

	/*
	 * Short-cut data block handling when the caller does not need an
	 * actual data reference to (aka OPTDATA), as long as the chain does
	 * not already have a data pointer to the data and no de-duplication
	 * occurred.
	 *
	 * This generally means that the modifications are being done via the
	 * logical buffer cache.
	 *
	 * NOTE: If deduplication occurred we have to run through the data
	 *	 stuff to clear INITIAL, and the caller will likely want to
	 *	 assign the check code anyway.  Leaving INITIAL set on a
	 *	 dedup can be deadly (it can cause the block to be zero'd!).
	 *
	 * This code also handles bytes == 0 (most dirents).
	 */
	if (chain->bref.type == HAMMER2_BREF_TYPE_DATA &&
	    (flags & HAMMER2_MODIFY_OPTDATA) && chain->data == NULL) {
		if (dedup_off == 0) {
			KKASSERT(chain->dio == NULL);
			goto skip;
		}
	}

	/*
	 * Clearing the INITIAL flag (for indirect blocks) indicates that
	 * we've processed the uninitialized storage allocation.
	 *
	 * If this flag is already clear we are likely in a copy-on-write
	 * situation but we have to be sure NOT to bzero the storage if
	 * no data is present.
	 *
	 * Clearing of NOTTESTED is allowed if the MODIFIED bit is set.
	 */
	if (chain->flags & HAMMER2_CHAIN_INITIAL) {
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
		wasinitial = 1;
	} else {
		wasinitial = 0;
	}

	/* Instantiate data buffer and possibly execute COW operation. */
	switch (chain->bref.type) {
	case HAMMER2_BREF_TYPE_VOLUME:
	case HAMMER2_BREF_TYPE_FREEMAP:
		/* The data is embedded, no copy-on-write operation needed. */
		KKASSERT(chain->dio == NULL);
		break;
	case HAMMER2_BREF_TYPE_DIRENT:
		/* The data might be fully embedded. */
		if (chain->bytes == 0) {
			KKASSERT(chain->dio == NULL);
			break;
		}
		/* fall through */
	case HAMMER2_BREF_TYPE_INODE:
	case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
	case HAMMER2_BREF_TYPE_DATA:
	case HAMMER2_BREF_TYPE_INDIRECT:
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
		/*
		 * Perform the copy-on-write operation
		 *
		 * zero-fill or copy-on-write depending on whether
		 * chain->data exists or not and set the dirty state for
		 * the new buffer.  hammer2_io_new() will handle the
		 * zero-fill.
		 *
		 * If a dedup_off was supplied this is an existing block
		 * and no COW, copy, or further modification is required.
		 */
		KKASSERT(chain != &hmp->vchain && chain != &hmp->fchain);

		if (wasinitial && dedup_off == 0)
			error = hammer2_io_new(hmp, chain->bref.type,
			    chain->bref.data_off, chain->bytes, &dio);
		else
			error = hammer2_io_bread(hmp, chain->bref.type,
			    chain->bref.data_off, chain->bytes, &dio);

		/*
		 * If an I/O error occurs make sure callers cannot accidently
		 * modify the old buffer's contents and corrupt the filesystem.
		 */
		if (error) {
			hprintf("%s blockref I/O error %d at %016llx\n",
			    hammer2_breftype_to_str(chain->bref.type), error,
			    (long long)chain->bref.data_off);
			chain->error = HAMMER2_ERROR_EIO;
			hammer2_io_brelse(&dio);
			hammer2_io_brelse(&chain->dio);
			chain->data = NULL;
			break;
		}
		chain->error = 0;
		bdata = hammer2_io_data(dio, chain->bref.data_off);

		if (chain->data) {
			/* COW (unless a dedup) */
			KKASSERT(chain->dio != NULL);
			if (chain->data != (void *)bdata && dedup_off == 0)
				bcopy(chain->data, bdata, chain->bytes);
		} else if (wasinitial == 0 && dedup_off == 0) {
			/*
			 * We have a problem.  We were asked to COW but
			 * we don't have any data to COW with!
			 */
			hpanic("no CoW data for %s chain %016llx/%d",
			    hammer2_breftype_to_str(chain->bref.type),
			    (long long)chain->bref.key, chain->bref.keybits);
		}

		/*
		 * Retire the old buffer, replace with the new.  Dirty or
		 * redirty the new buffer.
		 *
		 * WARNING! The system buffer cache may have already flushed
		 *	    the buffer, so we must be sure to [re]dirty it
		 *	    for further modification.
		 *
		 *	    If dedup_off was supplied, the caller is not
		 *	    expected to make any further modification to the
		 *	    buffer.
		 *
		 * WARNING! hammer2_get_gdata() assumes dio never transitions
		 *	    through NULL in order to optimize away unnecessary
		 *	    diolk operations.
		 */
		if ((tio = chain->dio) != NULL)
			hammer2_io_bqrelse(&tio);
		chain->data = (void *)bdata;
		chain->dio = dio;
		if (dedup_off == 0)
			hammer2_io_setdirty(dio);
		break;
	default:
		hpanic("bad blockref type %d", chain->bref.type);
		break;
	}
skip:
	/*
	 * setflush on parent indicating that the parent must recurse down
	 * to us.  Do not call on chain itself which might already have it set.
	 */
	if (chain->parent)
		hammer2_chain_setflush(chain->parent);
	hammer2_mtx_unlock(&chain->diolk);

	return (chain->error);
}

/*
 * Modify the chain associated with an inode.
 */
int
hammer2_chain_modify_ip(hammer2_inode_t *ip, hammer2_chain_t *chain,
    hammer2_tid_t mtid, int flags)
{
	int error;

	hammer2_inode_modify(ip);
	error = hammer2_chain_modify(chain, mtid, 0, flags);

	return (error);
}

/*
 * This function returns the chain at the nearest key within the specified
 * range.  The returned chain will be referenced but not locked.
 *
 * This function will recurse through chain->rbtree as necessary and will
 * return a *key_nextp suitable for iteration.  *key_nextp is only set if
 * the iteration value is less than the current value of *key_nextp.
 *
 * The caller should use (*key_nextp) to calculate the actual range of
 * the returned element, which will be (key_beg to *key_nextp - 1), because
 * there might be another element which is superior to the returned element
 * and overlaps it.
 *
 * (*key_nextp) can be passed as key_beg in an iteration only while non-NULL
 * chains continue to be returned.  On EOF (*key_nextp) may overflow since
 * it will wind up being (key_end + 1).
 *
 * WARNING!  Must be called with child's spinlock held.  Spinlock remains
 *	     held through the operation.
 */
struct hammer2_chain_find_info {
	hammer2_chain_t		*best;
	hammer2_key_t		key_beg;
	hammer2_key_t		key_end;
	hammer2_key_t		key_next;
};

static int hammer2_chain_find_cmp(hammer2_chain_t *, void *);
static int hammer2_chain_find_callback(hammer2_chain_t *, void *);

static hammer2_chain_t *
hammer2_chain_find(hammer2_chain_t *parent, hammer2_key_t *key_nextp,
    hammer2_key_t key_beg, hammer2_key_t key_end)
{
	struct hammer2_chain_find_info info;

	info.best = NULL;
	info.key_beg = key_beg;
	info.key_end = key_end;
	info.key_next = *key_nextp;

	RB_SCAN(hammer2_chain_tree, &parent->core.rbtree,
	    hammer2_chain_find_cmp, hammer2_chain_find_callback, &info);
	*key_nextp = info.key_next;

	return (info.best);
}

static int
hammer2_chain_find_cmp(hammer2_chain_t *child, void *data)
{
	struct hammer2_chain_find_info *info = data;
	hammer2_key_t child_beg, child_end;

	child_beg = child->bref.key;
	child_end = child_beg + ((hammer2_key_t)1 << child->bref.keybits) - 1;

	if (child_end < info->key_beg)
		return (-1);
	if (child_beg > info->key_end)
		return (1);
	return (0);
}

static int
hammer2_chain_find_callback(hammer2_chain_t *child, void *data)
{
	struct hammer2_chain_find_info *info = data;
	hammer2_chain_t *best;
	hammer2_key_t child_end;

	if ((best = info->best) == NULL) {
		/* No previous best.  Assign best. */
		info->best = child;
	} else if (best->bref.key <= info->key_beg &&
	    child->bref.key <= info->key_beg) {
		/* Illegal overlap. */
		KKASSERT(0);
	} else if (child->bref.key < best->bref.key) {
		/*
		 * Child has a nearer key and best is not flush with key_beg.
		 * Set best to child.  Truncate key_next to the old best key.
		 */
		info->best = child;
		if (info->key_next > best->bref.key || info->key_next == 0)
			info->key_next = best->bref.key;
	} else if (child->bref.key == best->bref.key) {
		/*
		 * If our current best is flush with the child then this
		 * is an illegal overlap.
		 *
		 * key_next will automatically be limited to the smaller of
		 * the two end-points.
		 */
		KKASSERT(0);
	} else {
		/*
		 * Keep the current best but truncate key_next to the child's
		 * base.
		 *
		 * key_next will also automatically be limited to the smaller
		 * of the two end-points (probably not necessary for this case
		 * but we do it anyway).
		 */
		if (info->key_next > child->bref.key || info->key_next == 0)
			info->key_next = child->bref.key;
	}

	/* Always truncate key_next based on child's end-of-range. */
	child_end = child->bref.key + ((hammer2_key_t)1 << child->bref.keybits);
	if (child_end && (info->key_next > child_end || info->key_next == 0))
		info->key_next = child_end;

	return (0);
}

/*
 * Retrieve the specified chain from a media blockref, creating the
 * in-memory chain structure which reflects it.  The returned chain is
 * held and locked according to (how) (HAMMER2_RESOLVE_*).  The caller must
 * handle crc-checks and so forth, and should check chain->error before
 * assuming that the data is good.
 *
 * To handle insertion races pass the INSERT_RACE flag along with the
 * generation number of the core.  NULL will be returned if the generation
 * number changes before we have a chance to insert the chain.  Insert
 * races can occur because the parent might be held shared.
 *
 * Caller must hold the parent locked shared or exclusive since we may
 * need the parent's bref array to find our block.
 *
 * WARNING! chain->pmp is always set to NULL for any chain representing
 *	    part of the super-root topology.
 */
static hammer2_chain_t *
hammer2_chain_get(hammer2_chain_t *parent, int generation,
    hammer2_blockref_t *bref, int how)
{
	hammer2_dev_t *hmp = parent->hmp;
	hammer2_chain_t *chain;
	int error;

	hammer2_mtx_assert_locked(&parent->lock);

	/*
	 * Allocate a chain structure representing the existing media
	 * entry.  Resulting chain has one ref and is not locked.
	 */
	if (bref->flags & HAMMER2_BREF_FLAG_PFSROOT)
		chain = hammer2_chain_alloc(hmp, NULL, bref);
	else
		chain = hammer2_chain_alloc(hmp, parent->pmp, bref);
	/* Ref'd chain returned. */

	/*
	 * Flag that the chain is in the parent's blockmap so delete/flush
	 * knows what to do with it.
	 */
	atomic_set_int(&chain->flags, HAMMER2_CHAIN_BLKMAPPED);

	/* Chain must be locked to avoid unexpected ripouts. */
	hammer2_chain_lock(chain, how);

	/*
	 * Link the chain into its parent.  A spinlock is required to safely
	 * access the RBTREE, and it is possible to collide with another
	 * hammer2_chain_get() operation because the caller might only hold
	 * a shared lock on the parent.
	 */
	KKASSERT(parent->refs > 0);
	error = hammer2_chain_insert(parent, chain,
	    HAMMER2_CHAIN_INSERT_SPIN | HAMMER2_CHAIN_INSERT_RACE, generation);
	if (error) {
		KKASSERT((chain->flags & HAMMER2_CHAIN_ONRBTREE) == 0);
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		chain = NULL;
	} else {
		KKASSERT(chain->flags & HAMMER2_CHAIN_ONRBTREE);
	}

	/*
	 * Return our new chain referenced but not locked, or NULL if
	 * a race occurred.
	 */
	return (chain);
}

/*
 * Lookup initialization/completion API.
 */
hammer2_chain_t *
hammer2_chain_lookup_init(hammer2_chain_t *parent, int flags)
{
	hammer2_chain_ref(parent);

	if (flags & HAMMER2_LOOKUP_SHARED)
		hammer2_chain_lock(parent,
		    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	else
		hammer2_chain_lock(parent, HAMMER2_RESOLVE_ALWAYS);

	return (parent);
}

void
hammer2_chain_lookup_done(hammer2_chain_t *parent)
{
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
}

/*
 * Take the locked chain and return a locked parent.  The chain remains
 * locked on return, but may have to be temporarily unlocked to acquire
 * the parent.  Because of this, (chain) must be stable and cannot be
 * deleted while it was temporarily unlocked (typically means that (chain)
 * is an inode).
 *
 * Pass HAMMER2_RESOLVE_* flags in flags.
 *
 * This will work even if the chain is errored, and the caller can check
 * parent->error on return if desired since the parent will be locked.
 *
 * This function handles the lock order reversal.
 */
hammer2_chain_t *
hammer2_chain_getparent(hammer2_chain_t *chain, int flags)
{
	hammer2_chain_t *parent;

	/*
	 * Be careful of order, chain must be unlocked before parent
	 * is locked below to avoid a deadlock.  Try it trivially first.
	 */
	parent = chain->parent;
	if (parent == NULL)
		hpanic("no parent");

	hammer2_chain_ref(parent);
	if (hammer2_chain_lock(parent, flags|HAMMER2_RESOLVE_NONBLOCK) == 0)
		return (parent);

	for (;;) {
		hammer2_chain_unlock(chain);
		hammer2_chain_lock(parent, flags);
		hammer2_chain_lock(chain, flags);

		/*
		 * Parent relinking races are quite common.  We have to get
		 * it right or we will blow up the block table.
		 */
		if (chain->parent == parent)
			break;
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
		cpu_ccfence();
		parent = chain->parent;
		if (parent == NULL)
			hpanic("no parent");
		hammer2_chain_ref(parent);
	}
	return (parent);
}

/*
 * Take the locked chain and return a locked parent.  The chain is unlocked
 * and dropped.  *chainp is set to the returned parent as a convenience.
 * Pass HAMMER2_RESOLVE_* flags in flags.
 *
 * This will work even if the chain is errored, and the caller can check
 * parent->error on return if desired since the parent will be locked.
 *
 * The chain does NOT need to be stable.  We use a tracking structure
 * to track the expected parent if the chain is deleted out from under us.
 */
static hammer2_chain_t *
hammer2_chain_repparent(hammer2_chain_t **chainp, int flags)
{
	hammer2_chain_t *chain, *parent;
	hammer2_reptrack_t reptrack, **repp;

	chain = *chainp;
	hammer2_mtx_assert_locked(&chain->lock);

	parent = chain->parent;
	KKASSERT(parent);

	hammer2_chain_ref(parent);
	if (hammer2_chain_lock(parent, flags|HAMMER2_RESOLVE_NONBLOCK) == 0) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		*chainp = parent;
		return (parent);
	}

	/*
	 * Ok, now it gets a bit nasty.  There are multiple situations where
	 * the parent might be in the middle of a deletion, or where the child
	 * (chain) might be deleted the instant we let go of its lock.
	 * We can potentially end up in a no-win situation!
	 *
	 * In particular, the indirect_maintenance() case can cause these
	 * situations.
	 *
	 * To deal with this we install a reptrack structure in the parent
	 * This reptrack structure 'owns' the parent ref and will automatically
	 * migrate to the parent's parent if the parent is deleted permanently.
	 */
	hammer2_spin_init(&reptrack.spin, "h2_rep");
	reptrack.chain = parent;
	hammer2_chain_ref(parent); /* for the reptrack */

	hammer2_spin_ex(&parent->core.spin);
	reptrack.next = parent->core.reptrack;
	parent->core.reptrack = &reptrack;
	hammer2_spin_unex(&parent->core.spin);

	hammer2_chain_unlock(chain);
	hammer2_chain_drop(chain);
	chain = NULL;

	/*
	 * At the top of this loop, chain is gone and parent is refd both
	 * by us explicitly AND via our reptrack.  We are attempting to
	 * lock parent.
	 */
	for (;;) {
		hammer2_chain_lock(parent, flags);

		if (reptrack.chain == parent)
			break;
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);

		hammer2_spin_ex(&reptrack.spin);
		parent = reptrack.chain;
		hammer2_chain_ref(parent);
		hammer2_spin_unex(&reptrack.spin);
	}

	/*
	 * Once parent is locked and matches our reptrack, our reptrack
	 * will be stable and we have our parent.  We can unlink our reptrack.
	 *
	 * WARNING!  Remember that the chain lock might be shared.
	 *	     Chains locked shared have stable parent linkages.
	 */
	hammer2_spin_ex(&parent->core.spin);
	repp = &parent->core.reptrack;
	while (*repp != &reptrack)
		repp = &(*repp)->next;
	*repp = reptrack.next;
	hammer2_spin_unex(&parent->core.spin);

	hammer2_chain_drop(parent); /* reptrack ref */
	*chainp = parent; /* return parent lock+ref */

	return (parent);
}

/*
 * Dispose of any linked reptrack structures in (chain) by shifting them to
 * (parent).  Both (chain) and (parent) must be exclusively locked.
 *
 * This is interlocked against any children of (chain) on the other side.
 * No children so remain as-of when this is called so we can test
 * core.reptrack without holding the spin-lock.
 *
 * Used whenever the caller intends to permanently delete chains related
 * to topological recursions (BREF_TYPE_INDIRECT, BREF_TYPE_FREEMAP_NODE),
 * where the chains underneath the node being deleted are given a new parent
 * above the node being deleted.
 */
static void
hammer2_chain_repchange(hammer2_chain_t *parent, hammer2_chain_t *chain)
{
	hammer2_reptrack_t *reptrack;

	KKASSERT(chain->core.live_count == 0 && RB_EMPTY(&chain->core.rbtree));
	while (chain->core.reptrack) {
		hammer2_spin_ex(&parent->core.spin);
		hammer2_spin_ex(&chain->core.spin);
		reptrack = chain->core.reptrack;
		if (reptrack == NULL) {
			hammer2_spin_unex(&chain->core.spin);
			hammer2_spin_unex(&parent->core.spin);
			break;
		}
		hammer2_spin_ex(&reptrack->spin);
		chain->core.reptrack = reptrack->next;
		reptrack->chain = parent;
		reptrack->next = parent->core.reptrack;
		parent->core.reptrack = reptrack;
		hammer2_chain_ref(parent); /* reptrack */

		hammer2_spin_unex(&chain->core.spin);
		hammer2_spin_unex(&parent->core.spin);
		hammer2_chain_drop(chain); /* reptrack */
	}
}

/*
 * Locate the first chain whos key range overlaps (key_beg, key_end) inclusive.
 * (*parentp) typically points to an inode but can also point to a related
 * indirect block and this function will recurse upwards and find the inode
 * or the nearest undeleted indirect block covering the key range.
 *
 * This function unconditionally sets *errorp, replacing any previous value.
 *
 * (*parentp) must be exclusive or shared locked (depending on flags) and
 * referenced and can be an inode or an existing indirect block within the
 * inode.
 *
 * If (*parent) is errored out, this function will not attempt to recurse
 * the radix tree and will return NULL along with an appropriate *errorp.
 * If NULL is returned and *errorp is 0, the requested lookup could not be
 * located.
 *
 * On return (*parentp) will be modified to point at the deepest parent chain
 * element encountered during the search, as a helper for an insertion or
 * deletion.
 *
 * The new (*parentp) will be locked shared or exclusive (depending on flags),
 * and referenced, and the old will be unlocked and dereferenced (no change
 * if they are both the same).  This is particularly important if the caller
 * wishes to insert a new chain, (*parentp) will be set properly even if NULL
 * is returned, as long as no error occurred.
 *
 * The matching chain will be returned locked according to flags.
 *
 * --
 * NULL is returned if no match was found, but (*parentp) will still
 * potentially be adjusted.
 *
 * On return (*key_nextp) will point to an iterative value for key_beg.
 * (If NULL is returned (*key_nextp) is set to (key_end + 1)).
 *
 * This function will also recurse up the chain if the key is not within the
 * current parent's range.  (*parentp) can never be set to NULL.  An iteration
 * can simply allow (*parentp) to float inside the loop.
 *
 * NOTE!  chain->data is not always resolved.  By default it will not be
 *	  resolved for BREF_TYPE_DATA, FREEMAP_NODE, or FREEMAP_LEAF.  Use
 *	  HAMMER2_LOOKUP_ALWAYS to force resolution (but be careful w/
 *	  BREF_TYPE_DATA as the device buffer can alias the logical file
 *	  buffer).
 */
hammer2_chain_t *
hammer2_chain_lookup(hammer2_chain_t **parentp, hammer2_key_t *key_nextp,
    hammer2_key_t key_beg, hammer2_key_t key_end, int *errorp, int flags)
{
	hammer2_chain_t *chain, *parent;
	hammer2_blockref_t bsave, *base, *bref;
	hammer2_key_t scan_beg, scan_end;
	int how_always = HAMMER2_RESOLVE_ALWAYS;
	int how_maybe = HAMMER2_RESOLVE_MAYBE;
	int how, generation, count = 0, maxloops = 300000;

	if (flags & HAMMER2_LOOKUP_ALWAYS) {
		how_maybe = how_always;
		how = HAMMER2_RESOLVE_ALWAYS;
	} else if (flags & HAMMER2_LOOKUP_NODATA) {
		how = HAMMER2_RESOLVE_NEVER;
	} else {
		how = HAMMER2_RESOLVE_MAYBE;
	}
	if (flags & HAMMER2_LOOKUP_SHARED) {
		how_maybe |= HAMMER2_RESOLVE_SHARED;
		how_always |= HAMMER2_RESOLVE_SHARED;
		how |= HAMMER2_RESOLVE_SHARED;
	}

	/*
	 * Recurse (*parentp) upward if necessary until the parent completely
	 * encloses the key range or we hit the inode.
	 *
	 * Handle races against the flusher deleting indirect nodes on its
	 * way back up by continuing to recurse upward past the deletion.
	 */
	parent = *parentp;
	hammer2_mtx_assert_locked(&parent->lock);
	*errorp = 0;

	while (parent->bref.type == HAMMER2_BREF_TYPE_INDIRECT ||
	    parent->bref.type == HAMMER2_BREF_TYPE_FREEMAP_NODE) {
		scan_beg = parent->bref.key;
		scan_end = scan_beg +
		    ((hammer2_key_t)1 << parent->bref.keybits) - 1;
		if ((parent->flags & HAMMER2_CHAIN_DELETED) == 0)
			if (key_beg >= scan_beg && key_end <= scan_end)
				break;
		parent = hammer2_chain_repparent(parentp, how_maybe);
	}
again:
	if (--maxloops == 0)
		hpanic("maxloops");

	/*
	 * MATCHIND case that does not require parent->data (do prior to
	 * parent->error check).
	 */
	switch (parent->bref.type) {
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
	case HAMMER2_BREF_TYPE_INDIRECT:
		if (flags & HAMMER2_LOOKUP_MATCHIND) {
			scan_beg = parent->bref.key;
			scan_end = scan_beg +
			    ((hammer2_key_t)1 << parent->bref.keybits) - 1;
			if (key_beg == scan_beg && key_end == scan_end) {
				chain = parent;
				hammer2_chain_ref(chain);
				hammer2_chain_lock(chain, how_maybe);
				*key_nextp = scan_end + 1;
				goto done;
			}
		}
		break;
	default:
		break;
	}

	/*
	 * No lookup is possible if the parent is errored.  We delayed
	 * this check as long as we could to ensure that the parent backup,
	 * embedded data code could still execute.
	 */
	if (parent->error) {
		*errorp = parent->error;
		return (NULL);
	}

	/*
	 * Locate the blockref array.  Currently we do a fully associative
	 * search through the array.
	 */
	switch (parent->bref.type) {
	case HAMMER2_BREF_TYPE_INODE:
		/*
		 * Special shortcut for embedded data returns the inode
		 * itself.  Callers must detect this condition and access
		 * the embedded data (the strategy code does this for us).
		 *
		 * This is only applicable to regular files and softlinks.
		 *
		 * We need a second lock on parent.  Since we already have
		 * a lock we must pass LOCKAGAIN to prevent unexpected
		 * blocking (we don't want to block on a second shared
		 * ref if an exclusive lock is pending).
		 */
		if (parent->data->ipdata.meta.op_flags &
		    HAMMER2_OPFLAG_DIRECTDATA) {
			if (flags & HAMMER2_LOOKUP_NODIRECT) {
				chain = NULL;
				*key_nextp = key_end + 1;
				goto done;
			}
			hammer2_chain_ref(parent);
			hammer2_chain_lock(parent,
			    how_always | HAMMER2_RESOLVE_LOCKAGAIN);
			*key_nextp = key_end + 1;
			return (parent);
		}
		base = &parent->data->ipdata.u.blockset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
	case HAMMER2_BREF_TYPE_INDIRECT:
		/*
		 * Optimize indirect blocks in the INITIAL state to avoid I/O.
		 *
		 * Debugging: Enter permanent wait state instead of
		 * panicing on unexpectedly NULL data for the moment.
		 */
		if (parent->flags & HAMMER2_CHAIN_INITIAL) {
			base = NULL;
		} else {
			KKASSERT(parent->data);
			base = &parent->data->npdata[0];
		}
		count = parent->bytes / sizeof(hammer2_blockref_t);
		break;
	case HAMMER2_BREF_TYPE_VOLUME:
		base = &parent->data->voldata.sroot_blockset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	case HAMMER2_BREF_TYPE_FREEMAP:
		base = &parent->data->blkset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	default:
		hpanic("bad blockref type %d", parent->bref.type);
		break;
	}

	/*
	 * Merged scan to find next candidate.
	 *
	 * hammer2_base_*() functions require the parent->core.live_* fields
	 * to be synchronized.
	 *
	 * We need to hold the spinlock to access the block array and RB tree
	 * and to interlock chain creation.
	 */
	if ((parent->flags & HAMMER2_CHAIN_COUNTEDBREFS) == 0)
		hammer2_chain_countbrefs(parent, base, count);

	/* Combined search. */
	hammer2_spin_ex(&parent->core.spin);
	chain = hammer2_combined_find(parent, base, count, key_nextp, key_beg,
	    key_end, &bref);
	generation = parent->core.generation;

	/* Exhausted parent chain, iterate. */
	if (bref == NULL) {
		KKASSERT(chain == NULL);
		hammer2_spin_unex(&parent->core.spin);
		if (key_beg == key_end)	/* Short cut single-key case. */
			return (NULL);

		/* Stop if we reached the end of the iteration. */
		if (parent->bref.type != HAMMER2_BREF_TYPE_INDIRECT &&
		    parent->bref.type != HAMMER2_BREF_TYPE_FREEMAP_NODE)
			return (NULL);

		/*
		 * Calculate next key, stop if we reached the end of the
		 * iteration, otherwise go up one level and loop.
		 */
		key_beg = parent->bref.key +
		    ((hammer2_key_t)1 << parent->bref.keybits);
		if (key_beg == 0 || key_beg > key_end)
			return (NULL);
		parent = hammer2_chain_repparent(parentp, how_maybe);
		goto again;
	}

	/* Selected from blockref or in-memory chain. */
	bsave = *bref;
	if (chain == NULL) {
		hammer2_spin_unex(&parent->core.spin);
		if (bsave.type == HAMMER2_BREF_TYPE_INDIRECT ||
		    bsave.type == HAMMER2_BREF_TYPE_FREEMAP_NODE)
			chain = hammer2_chain_get(parent, generation, &bsave,
			    how_maybe);
		else
			chain = hammer2_chain_get(parent, generation, &bsave,
			    how);
		if (chain == NULL)
			goto again;
	} else {
		hammer2_chain_ref(chain);
		hammer2_spin_unex(&parent->core.spin);
		/*
		 * chain is referenced but not locked.  We must lock the
		 * chain to obtain definitive state.
		 */
		if (bsave.type == HAMMER2_BREF_TYPE_INDIRECT ||
		    bsave.type == HAMMER2_BREF_TYPE_FREEMAP_NODE)
			hammer2_chain_lock(chain, how_maybe);
		else
			hammer2_chain_lock(chain, how);
		KKASSERT(chain->parent == parent);
	}
	if (bcmp(&bsave, &chain->bref, sizeof(bsave)) ||
	    chain->parent != parent) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		chain = NULL;
		goto again;
	}

	/*
	 * Skip deleted chains (XXX cache 'i' end-of-block-array?)
	 *
	 * NOTE: chain's key range is not relevant as there might be
	 *	 one-offs within the range that are not deleted.
	 *
	 * NOTE: Lookups can race delete-duplicate because
	 *	 delete-duplicate does not lock the parent's core
	 *	 (they just use the spinlock on the core).
	 */
	if (chain->flags & HAMMER2_CHAIN_DELETED) {
		hprintf("skip deleted %s chain %016llx/%d\n",
		    hammer2_breftype_to_str(chain->bref.type),
		    (long long)chain->bref.key, chain->bref.keybits);
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		chain = NULL;
		key_beg = *key_nextp;
		if (key_beg == 0 || key_beg > key_end)
			return (NULL);
		goto again;
	}

	/*
	 * If the chain element is an indirect block it becomes the new
	 * parent and we loop on it.  We must maintain our top-down locks
	 * to prevent the flusher from interfering (i.e. doing a
	 * delete-duplicate and leaving us recursing down a deleted chain).
	 *
	 * The parent always has to be locked with at least RESOLVE_MAYBE
	 * so we can access its data.  It might need a fixup if the caller
	 * passed incompatible flags.  Be careful not to cause a deadlock
	 * as a data-load requires an exclusive lock.
	 *
	 * If HAMMER2_LOOKUP_MATCHIND is set and the indirect block's key
	 * range is within the requested key range we return the indirect
	 * block and do NOT loop.  This is usually only used to acquire
	 * freemap nodes.
	 */
	if (chain->bref.type == HAMMER2_BREF_TYPE_INDIRECT ||
	    chain->bref.type == HAMMER2_BREF_TYPE_FREEMAP_NODE) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
		*parentp = parent = chain;
		chain = NULL;
		goto again;
	}
done:
	/*
	 * All done, return the locked chain.
	 *
	 * NOTE! A chain->error must be tested by the caller upon return.
	 *	 *errorp is only set based on issues which occur while
	 *	 trying to reach the chain.
	 */
	return (chain);
}

/*
 * After having issued a lookup we can iterate all matching keys.
 *
 * If chain is non-NULL we continue the iteration from just after it's index.
 * If chain is NULL we assume the parent was exhausted and continue the
 * iteration at the next parent.
 *
 * If a fatal error occurs (typically an I/O error), a dummy chain is
 * returned with chain->error and error-identifying information set.  This
 * chain will assert if you try to do anything fancy with it.
 *
 * XXX Depending on where the error occurs we should allow continued iteration.
 *
 * parent must be locked on entry and remains locked throughout.  chain's
 * lock status must match flags.  Chain is always at least referenced.
 */
hammer2_chain_t *
hammer2_chain_next(hammer2_chain_t **parentp, hammer2_chain_t *chain,
    hammer2_key_t *key_nextp, hammer2_key_t key_end, int *errorp, int flags)
{
	hammer2_chain_t *parent;
	hammer2_key_t key_beg;
	int how_maybe;

	/* Calculate locking flags for upward recursion. */
	how_maybe = HAMMER2_RESOLVE_MAYBE;
	if (flags & HAMMER2_LOOKUP_SHARED)
		how_maybe |= HAMMER2_RESOLVE_SHARED;

	parent = *parentp;
	hammer2_mtx_assert_locked(&parent->lock);
	*errorp = 0;

	/* Calculate the next index and recalculate the parent if necessary. */
	if (chain) {
		key_beg = chain->bref.key +
		    ((hammer2_key_t)1 << chain->bref.keybits);
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		/*
		 * chain invalid past this point, but we can still do a
		 * pointer comparison w/parent.
		 *
		 * Any scan where the lookup returned degenerate data embedded
		 * in the inode has an invalid index and must terminate.
		 */
		if (chain == parent)
			return (NULL);
		if (key_beg == 0 || key_beg > key_end)
			return (NULL);
		chain = NULL;
	} else if (parent->bref.type != HAMMER2_BREF_TYPE_INDIRECT &&
	    parent->bref.type != HAMMER2_BREF_TYPE_FREEMAP_NODE) {
		/* We reached the end of the iteration. */
		return (NULL);
	} else {
		/*
		 * Continue iteration with next parent unless the current
		 * parent covers the range.
		 *
		 * (This also handles the case of a deleted, empty indirect
		 * node).
		 */
		key_beg = parent->bref.key +
		    ((hammer2_key_t)1 << parent->bref.keybits);
		if (key_beg == 0 || key_beg > key_end)
			return (NULL);
		parent = hammer2_chain_repparent(parentp, how_maybe);
	}

	/* And execute. */
	return (hammer2_chain_lookup(parentp, key_nextp, key_beg, key_end,
	    errorp, flags));
}

/*
 * Caller wishes to iterate chains under parent, loading new chains into
 * chainp.  Caller must initialize *chainp to NULL and *firstp to 1, and
 * then call hammer2_chain_scan() repeatedly until a non-zero return.
 * During the scan, *firstp will be set to 0 and (*chainp) will be replaced
 * with the returned chain for the scan.  The returned *chainp will be
 * locked and referenced.  Any prior contents will be unlocked and dropped.
 *
 * Caller should check the return value.  A normal scan EOF will return
 * exactly HAMMER2_ERROR_EOF.  Any other non-zero value indicates an
 * error trying to access parent data.  Any error in the returned chain
 * must be tested separately by the caller.
 *
 * (*chainp) is dropped on each scan, but will only be set if the returned
 * element itself can recurse.  Leaf elements are NOT resolved, loaded, or
 * returned via *chainp.  The caller will get their bref only.
 *
 * The raw scan function is similar to lookup/next but does not seek to a key.
 * Blockrefs are iterated via first_bref = (parent, NULL) and
 * next_chain = (parent, bref).
 *
 * The passed-in parent must be locked and its data resolved.  The function
 * nominally returns a locked and referenced *chainp != NULL for chains
 * the caller might need to recurse on (and will dipose of any *chainp passed
 * in).  The caller must check the chain->bref.type either way.
 */
int
hammer2_chain_scan(hammer2_chain_t *parent, hammer2_chain_t **chainp,
    hammer2_blockref_t *bref, int *firstp, int flags)
{
	hammer2_blockref_t *base, *bref_ptr;
	hammer2_key_t key, next_key;
	hammer2_chain_t *chain = NULL;
	int how, generation, count = 0, error = 0, maxloops = 300000;

	/* Scan flags borrowed from lookup. */
	if (flags & HAMMER2_LOOKUP_ALWAYS)
		how = HAMMER2_RESOLVE_ALWAYS;
	else if (flags & HAMMER2_LOOKUP_NODATA)
		how = HAMMER2_RESOLVE_NEVER;
	else
		how = HAMMER2_RESOLVE_MAYBE;

	if (flags & HAMMER2_LOOKUP_SHARED)
		how |= HAMMER2_RESOLVE_SHARED;

	/*
	 * Calculate key to locate first/next element, unlocking the previous
	 * element as we go.  Be careful, the key calculation can overflow.
	 * (also reset bref to NULL)
	 */
	if (*firstp) {
		key = 0;
		*firstp = 0;
	} else {
		key = bref->key + ((hammer2_key_t)1 << bref->keybits);
		if ((chain = *chainp) != NULL) {
			*chainp = NULL;
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
			chain = NULL;
		}
		if (key == 0) {
			error |= HAMMER2_ERROR_EOF;
			goto done;
		}
	}

again:
	if (parent->error) {
		error = parent->error;
		goto done;
	}
	if (--maxloops == 0)
		hpanic("maxloops");

	/*
	 * Locate the blockref array.  Currently we do a fully associative
	 * search through the array.
	 */
	switch (parent->bref.type) {
	case HAMMER2_BREF_TYPE_INODE:
		/*
		 * An inode with embedded data has no sub-chains.
		 *
		 * WARNING! Bulk scan code may pass a static chain marked
		 *	    as BREF_TYPE_INODE with a copy of the volume
		 *	    root blockset to snapshot the volume.
		 */
		if (parent->data->ipdata.meta.op_flags &
		    HAMMER2_OPFLAG_DIRECTDATA) {
			error |= HAMMER2_ERROR_EOF;
			goto done;
		}
		base = &parent->data->ipdata.u.blockset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
	case HAMMER2_BREF_TYPE_INDIRECT:
		/*
		 * Optimize indirect blocks in the INITIAL state to avoid I/O.
		 */
		if (parent->flags & HAMMER2_CHAIN_INITIAL) {
			base = NULL;
		} else {
			if (parent->data == NULL)
				hpanic("parent->data is NULL");
			base = &parent->data->npdata[0];
		}
		count = parent->bytes / sizeof(hammer2_blockref_t);
		break;
	case HAMMER2_BREF_TYPE_VOLUME:
		base = &parent->data->voldata.sroot_blockset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	case HAMMER2_BREF_TYPE_FREEMAP:
		base = &parent->data->blkset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	default:
		hpanic("bad blockref type %d", parent->bref.type);
		break;
	}

	/*
	 * Merged scan to find next candidate.
	 *
	 * hammer2_base_*() functions require the parent->core.live_* fields
	 * to be synchronized.
	 *
	 * We need to hold the spinlock to access the block array and RB tree
	 * and to interlock chain creation.
	 */
	if ((parent->flags & HAMMER2_CHAIN_COUNTEDBREFS) == 0)
		hammer2_chain_countbrefs(parent, base, count);

	next_key = 0;
	bref_ptr = NULL;
	hammer2_spin_ex(&parent->core.spin);
	chain = hammer2_combined_find(parent, base, count, &next_key, key,
	    HAMMER2_KEY_MAX, &bref_ptr);
	generation = parent->core.generation;

	/* Exhausted parent chain, we're done. */
	if (bref_ptr == NULL) {
		hammer2_spin_unex(&parent->core.spin);
		KKASSERT(chain == NULL);
		error |= HAMMER2_ERROR_EOF;
		goto done;
	}

	/* Copy into the supplied stack-based blockref. */
	*bref = *bref_ptr;

	/* Selected from blockref or in-memory chain. */
	if (chain == NULL) {
		switch (bref->type) {
		case HAMMER2_BREF_TYPE_INODE:
		case HAMMER2_BREF_TYPE_FREEMAP_NODE:
		case HAMMER2_BREF_TYPE_INDIRECT:
		case HAMMER2_BREF_TYPE_VOLUME:
		case HAMMER2_BREF_TYPE_FREEMAP:
			/* Recursion, always get the chain. */
			hammer2_spin_unex(&parent->core.spin);
			chain = hammer2_chain_get(parent, generation, bref,
			    how);
			if (chain == NULL)
				goto again;
			break;
		default:
			/*
			 * No recursion, do not waste time instantiating
			 * a chain, just iterate using the bref.
			 */
			hammer2_spin_unex(&parent->core.spin);
			break;
		}
	} else {
		/*
		 * Recursion or not we need the chain in order to supply
		 * the bref.
		 */
		hammer2_chain_ref(chain);
		hammer2_spin_unex(&parent->core.spin);
		hammer2_chain_lock(chain, how);
	}
	if (chain && (bcmp(bref, &chain->bref, sizeof(*bref)) ||
	    chain->parent != parent)) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		chain = NULL;
		goto again;
	}

	/*
	 * Skip deleted chains (XXX cache 'i' end-of-block-array?)
	 *
	 * NOTE: chain's key range is not relevant as there might be
	 *	 one-offs within the range that are not deleted.
	 *
	 * NOTE: XXX this could create problems with scans used in
	 *	 situations other than mount-time recovery.
	 *
	 * NOTE: Lookups can race delete-duplicate because
	 *	 delete-duplicate does not lock the parent's core
	 *	 (they just use the spinlock on the core).
	 */
	if (chain && (chain->flags & HAMMER2_CHAIN_DELETED)) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		chain = NULL;
		key = next_key;
		if (key == 0) {
			error |= HAMMER2_ERROR_EOF;
			goto done;
		}
		goto again;
	}

done:
	/* All done, return the bref or NULL, supply chain if necessary. */
	if (chain)
		*chainp = chain;
	return (error);
}

/*
 * Create and return a new hammer2 system memory structure of the specified
 * key, type and size and insert it under (*parentp).  This is a full
 * insertion, based on the supplied key/keybits, and may involve creating
 * indirect blocks and moving other chains around via delete/duplicate.
 *
 * This call can be made with parent == NULL as long as a non -1 methods
 * is supplied.  hmp must also be supplied in this situation (otherwise
 * hmp is extracted from the supplied parent).  The chain will be detached
 * from the topology.  A later call with both parent and chain can be made
 * to attach it.
 *
 * THE CALLER MUST HAVE ALREADY PROPERLY SEEKED (*parentp) TO THE INSERTION
 * POINT SANS ANY REQUIRED INDIRECT BLOCK CREATIONS DUE TO THE ARRAY BEING
 * FULL.  This typically means that the caller is creating the chain after
 * doing a hammer2_chain_lookup().
 *
 * (*parentp) must be exclusive locked and may be replaced on return
 * depending on how much work the function had to do.
 *
 * (*parentp) must not be errored or this function will assert.
 *
 * (*chainp) usually starts out NULL and returns the newly created chain,
 * but if the caller desires the caller may allocate a disconnected chain
 * and pass it in instead.
 *
 * This function should NOT be used to insert INDIRECT blocks.  It is
 * typically used to create/insert inodes and data blocks.
 *
 * Caller must pass-in an exclusively locked parent the new chain is to
 * be inserted under, and optionally pass-in a disconnected, exclusively
 * locked chain to insert (else we create a new chain).  The function will
 * adjust (*parentp) as necessary, create or connect the chain, and
 * return an exclusively locked chain in *chainp.
 *
 * When creating a PFSROOT inode under the super-root, pmp is typically NULL
 * and will be reassigned.
 *
 * NOTE: returns HAMMER_ERROR_* flags
 */
int
hammer2_chain_create(hammer2_chain_t **parentp, hammer2_chain_t **chainp,
    hammer2_dev_t *hmp, hammer2_pfs_t *pmp, int methods, hammer2_key_t key,
    int keybits, int type, size_t bytes, hammer2_tid_t mtid,
    hammer2_off_t dedup_off, int flags)
{
	hammer2_chain_t *chain, *parent, *nparent;
	hammer2_blockref_t *base, dummy;
	int allocated = 0, error = 0, maxloops = 300000;
	unsigned int count = 0;

	/* Topology may be crossing a PFS boundary. */
	parent = *parentp;
	if (parent) {
		KKASSERT(hammer2_mtx_owned(&parent->lock));
		KKASSERT(parent->error == 0);
		hmp = parent->hmp;
	}
	chain = *chainp;

	if (chain == NULL) {
		/*
		 * First allocate media space and construct the dummy bref,
		 * then allocate the in-memory chain structure.  Set the
		 * INITIAL flag for fresh chains which do not have embedded
		 * data.
		 */
		bzero(&dummy, sizeof(dummy));
		dummy.type = type;
		dummy.key = key;
		dummy.keybits = keybits;
		dummy.data_off = hammer2_getradix(bytes);

		/*
		 * Inherit methods from parent by default.  Primarily used
		 * for BREF_TYPE_DATA.  Non-data types *must* be set to
		 * a non-NONE check algorithm.
		 */
		if (methods == HAMMER2_METH_DEFAULT)
			dummy.methods = parent->bref.methods;
		else
			dummy.methods = (uint8_t)methods;

		if (type != HAMMER2_BREF_TYPE_DATA &&
		    HAMMER2_DEC_CHECK(dummy.methods) == HAMMER2_CHECK_NONE)
			dummy.methods |=
			    HAMMER2_ENC_CHECK(HAMMER2_CHECK_DEFAULT);
		chain = hammer2_chain_alloc(hmp, pmp, &dummy);

		/*
		 * Lock the chain manually, chain_lock will load the chain
		 * which we do NOT want to do.  (note: chain->refs is set
		 * to 1 by chain_alloc() for us, but lockcnt is not).
		 */
		chain->lockcnt = 1;
		hammer2_mtx_ex(&chain->lock);
		allocated = 1;

		/*
		 * Set INITIAL to optimize I/O.  The flag will generally be
		 * processed when we call hammer2_chain_modify().
		 */
		switch (type) {
		case HAMMER2_BREF_TYPE_VOLUME:
		case HAMMER2_BREF_TYPE_FREEMAP:
			hpanic("called with volume type");
			break;
		case HAMMER2_BREF_TYPE_INDIRECT:
			hpanic("cannot be used to create indirect block");
			break;
		case HAMMER2_BREF_TYPE_FREEMAP_NODE:
			hpanic("cannot be used to create freemap root or node");
			break;
		case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
			KKASSERT(bytes == sizeof(chain->data->bmdata));
			/* fall through */
		default:
			/* Leave chain->data NULL, set INITIAL. */
			KKASSERT(chain->data == NULL);
			atomic_set_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
			break;
		}
	} else {
		/*
		 * We are reattaching a previously deleted chain, possibly
		 * under a new parent and possibly with a new key/keybits.
		 * The chain does not have to be in a modified state.  The
		 * UPDATE flag will be set later on in this routine.
		 *
		 * Do NOT mess with the current state of the INITIAL flag.
		 */
		chain->bref.key = key;
		chain->bref.keybits = keybits;
		if (chain->flags & HAMMER2_CHAIN_DELETED)
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_DELETED);
		KKASSERT(chain->parent == NULL);
	}

	/*
	 * Set the appropriate bref flag if requested.
	 *
	 * NOTE! Callers can call this function to move chains without
	 *	 knowing about special flags, so don't clear bref flags
	 *	 here!
	 */
	if (flags & HAMMER2_INSERT_PFSROOT)
		chain->bref.flags |= HAMMER2_BREF_FLAG_PFSROOT;

	if (parent == NULL)
		goto skip;

	/*
	 * Calculate how many entries we have in the blockref array and
	 * determine if an indirect block is required when inserting into
	 * the parent.
	 */
again:
	if (--maxloops == 0)
		hpanic("maxloops");

	switch (parent->bref.type) {
	case HAMMER2_BREF_TYPE_INODE:
		if ((parent->data->ipdata.meta.op_flags &
		    HAMMER2_OPFLAG_DIRECTDATA) != 0)
			hprintf("parent set for direct-data pkey %016llx "
			    "ckey %016llx\n",
			    (long long)parent->bref.key,
			    (long long)chain->bref.key);
		KKASSERT((parent->data->ipdata.meta.op_flags &
		    HAMMER2_OPFLAG_DIRECTDATA) == 0);
		KKASSERT(parent->data != NULL);
		base = &parent->data->ipdata.u.blockset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	case HAMMER2_BREF_TYPE_INDIRECT:
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
		if (parent->flags & HAMMER2_CHAIN_INITIAL)
			base = NULL;
		else
			base = &parent->data->npdata[0];
		count = parent->bytes / sizeof(hammer2_blockref_t);
		break;
	case HAMMER2_BREF_TYPE_VOLUME:
		KKASSERT(parent->data != NULL);
		base = &parent->data->voldata.sroot_blockset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	case HAMMER2_BREF_TYPE_FREEMAP:
		KKASSERT(parent->data != NULL);
		base = &parent->data->blkset.blockref[0];
		count = HAMMER2_SET_COUNT;
		break;
	default:
		hpanic("bad blockref type %d", parent->bref.type);
		break;
	}

	/* Make sure we've counted the brefs. */
	if ((parent->flags & HAMMER2_CHAIN_COUNTEDBREFS) == 0)
		hammer2_chain_countbrefs(parent, base, count);

	KASSERTMSG(parent->core.live_count >= 0 &&
	    parent->core.live_count <= count,
	    "bad live_count %d/%d (%02x, %d)",
	    parent->core.live_count, count, parent->bref.type, parent->bytes);

	/*
	 * If no free blockref could be found we must create an indirect
	 * block and move a number of blockrefs into it.  With the parent
	 * locked we can safely lock each child in order to delete+duplicate
	 * it without causing a deadlock.
	 *
	 * This may return the new indirect block or the old parent depending
	 * on where the key falls.  NULL is returned on error.
	 */
	if (parent->core.live_count == count) {
		KKASSERT((flags & HAMMER2_INSERT_SAMEPARENT) == 0);
		nparent = hammer2_chain_create_indirect(parent, key, keybits,
		    mtid, type, &error);
		if (nparent == NULL) {
			if (allocated)
				hammer2_chain_drop(chain);
			chain = NULL;
			goto done;
		}
		if (parent != nparent) {
			hammer2_chain_unlock(parent);
			hammer2_chain_drop(parent);
			parent = *parentp = nparent;
		}
		goto again;
	}

	/* Fall through if parent, or skip to here if no parent. */
skip:
	if (chain->flags & HAMMER2_CHAIN_DELETED)
		hprintf("inserting deleted %s chain %016llx/%d\n",
		    hammer2_breftype_to_str(chain->bref.type),
		    (long long)chain->bref.key, chain->bref.keybits);

	/* Link the chain into its parent. */
	if (chain->parent != NULL)
		hpanic("chain already connected");
	KKASSERT(chain->parent == NULL);
	if (parent) {
		KKASSERT(parent->core.live_count < count);
		hammer2_chain_insert(parent, chain,
		    HAMMER2_CHAIN_INSERT_SPIN | HAMMER2_CHAIN_INSERT_LIVE, 0);
	}

	if (allocated) {
		/*
		 * Mark the newly created chain modified.  This will cause
		 * UPDATE to be set and process the INITIAL flag.
		 *
		 * Device buffers are not instantiated for DATA elements
		 * as these are handled by logical buffers.
		 *
		 * Indirect and freemap node indirect blocks are handled
		 * by hammer2_chain_create_indirect() and not by this
		 * function.
		 *
		 * Data for all other bref types is expected to be
		 * instantiated (INODE, LEAF).
		 */
		switch (chain->bref.type) {
		case HAMMER2_BREF_TYPE_DATA:
		case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
		case HAMMER2_BREF_TYPE_DIRENT:
		case HAMMER2_BREF_TYPE_INODE:
			error = hammer2_chain_modify(chain, mtid, dedup_off,
			    HAMMER2_MODIFY_OPTDATA);
			break;
		default:
			/*
			 * Remaining types are not supported by this function.
			 * In particular, INDIRECT and LEAF_NODE types are
			 * handled by create_indirect().
			 */
			hpanic("bad blockref type %d", chain->bref.type);
			break;
		}
	} else {
		/*
		 * When reconnecting a chain we must set UPDATE and
		 * setflush so the flush recognizes that it must update
		 * the bref in the parent.
		 */
		if ((chain->flags & HAMMER2_CHAIN_UPDATE) == 0)
			atomic_set_int(&chain->flags, HAMMER2_CHAIN_UPDATE);
	}

	/*
	 * We must setflush(parent) to ensure that it recurses through to
	 * chain.  setflush(chain) might not work because ONFLUSH is possibly
	 * already set in the chain (so it won't recurse up to set it in the
	 * parent).
	 */
	if (parent)
		hammer2_chain_setflush(parent);
done:
	*chainp = chain;

	return (error);
}

/*
 * Move the chain from its old parent to a new parent.  The chain must have
 * already been deleted or already disconnected (or never associated) with
 * a parent.  The chain is reassociated with the new parent and the deleted
 * flag will be cleared (no longer deleted).  The chain's modification state
 * is not altered.
 *
 * THE CALLER MUST HAVE ALREADY PROPERLY SEEKED (parent) TO THE INSERTION
 * POINT SANS ANY REQUIRED INDIRECT BLOCK CREATIONS DUE TO THE ARRAY BEING
 * FULL.  This typically means that the caller is creating the chain after
 * doing a hammer2_chain_lookup().
 *
 * Neither (parent) or (chain) can be errored.
 *
 * If (parent) is non-NULL then the chain is inserted under the parent.
 *
 * If (parent) is NULL then the newly duplicated chain is not inserted
 * anywhere, similar to if it had just been chain_alloc()'d (suitable for
 * passing into hammer2_chain_create() after this function returns).
 *
 * WARNING! This function calls create which means it can insert indirect
 *	    blocks.  This can cause other unrelated chains in the parent to
 *	    be moved to a newly inserted indirect block in addition to the
 *	    specific chain.
 */
static void
hammer2_chain_rename(hammer2_chain_t **parentp, hammer2_chain_t *chain,
    hammer2_tid_t mtid, int flags)
{
	hammer2_blockref_t *bref;
	hammer2_chain_t *parent;

	/*
	 * WARNING!  We should never resolve DATA to device buffers
	 *	     (XXX allow it if the caller did?), and since
	 *	     we currently do not have the logical buffer cache
	 *	     buffer in-hand to fix its cached physical offset
	 *	     we also force the modify code to not COW it. XXX
	 *
	 * NOTE!     We allow error'd chains to be renamed.  The bref itself
	 *	     is good and can be renamed.  The content, however, may
	 *	     be inaccessible.
	 */
	KKASSERT(chain->parent == NULL);
	bref = &chain->bref;

	/*
	 * If parent is not NULL the duplicated chain will be entered under
	 * the parent and the UPDATE bit set to tell flush to update
	 * the blockref.
	 *
	 * We must setflush(parent) to ensure that it recurses through to
	 * chain.  setflush(chain) might not work because ONFLUSH is possibly
	 * already set in the chain (so it won't recurse up to set it in the
	 * parent).
	 *
	 * Having both chains locked is extremely important for atomicy.
	 */
	if (parentp && (parent = *parentp) != NULL) {
		KKASSERT(hammer2_mtx_owned(&parent->lock));
		KKASSERT(parent->refs > 0);
		KKASSERT(parent->error == 0);

		hammer2_chain_create(parentp, &chain, NULL, chain->pmp,
		    HAMMER2_METH_DEFAULT, bref->key, bref->keybits, bref->type,
		    chain->bytes, mtid, 0, flags);
		KKASSERT(chain->flags & HAMMER2_CHAIN_UPDATE);
		hammer2_chain_setflush(*parentp);
	}
}

/*
 * This works in tandem with delete_obref() to install a blockref in
 * (typically) an indirect block that is associated with the chain being
 * moved to *parentp.
 *
 * The reason we need this function is that the caller needs to maintain
 * the blockref as it was, and not generate a new blockref for what might
 * be a modified chain.  Otherwise stuff will leak into the flush that
 * the flush code's FLUSH_INODE_STOP flag is unable to catch.
 *
 * It is EXTREMELY important that we properly set CHAIN_BLKMAPUPD and
 * CHAIN_UPDATE.  We must set BLKMAPUPD if the bref does not match, and
 * we must clear CHAIN_UPDATE (that was likely set by the chain_rename) if
 * it does.  Otherwise we can end up in a situation where H2 is unable to
 * clean up the in-memory chain topology.
 *
 * The reason for this is that flushes do not generally flush through
 * BREF_TYPE_INODE chains and depend on a hammer2_inode_t queued to syncq
 * or sideq to properly flush and dispose of the related inode chain's flags.
 * Situations where the inode is not actually modified by the frontend,
 * but where we have to move the related chains around as we insert or cleanup
 * indirect blocks, can leave us with a 'dirty' (non-disposable) in-memory
 * inode chain that does not have a hammer2_inode_t associated with it.
 */
static void
hammer2_chain_rename_obref(hammer2_chain_t **parentp, hammer2_chain_t *chain,
    hammer2_tid_t mtid, int flags, hammer2_blockref_t *obref)
{
	hammer2_blockref_t *tbase;
	int tcount;

	hammer2_chain_rename(parentp, chain, mtid, flags);

	if (obref->type != HAMMER2_BREF_TYPE_EMPTY) {
		KKASSERT((chain->flags & HAMMER2_CHAIN_BLKMAPPED) == 0);
		hammer2_chain_modify(*parentp, mtid, 0, 0);
		tbase = hammer2_chain_base_and_count(*parentp, &tcount);
		hammer2_base_insert(*parentp, tbase, tcount, chain, obref);
		if (bcmp(obref, &chain->bref, sizeof(chain->bref)))
			atomic_set_int(&chain->flags,
			    HAMMER2_CHAIN_BLKMAPUPD | HAMMER2_CHAIN_UPDATE);
		else
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_UPDATE);
	}
}

/*
 * Helper function for deleting chains.
 *
 * The chain is removed from the live view (the RBTREE) as well as the parent's
 * blockmap.  Both chain and its parent must be locked.
 *
 * parent may not be errored.  chain can be errored.
 */
static int
_hammer2_chain_delete_helper(hammer2_chain_t *parent, hammer2_chain_t *chain,
    hammer2_tid_t mtid, int flags, hammer2_blockref_t *obref)
{
	hammer2_blockref_t *base;
	int count = 0, error = 0;

	KKASSERT((chain->flags & HAMMER2_CHAIN_DELETED) == 0);
	KKASSERT(chain->parent == parent);

	if (chain->flags & HAMMER2_CHAIN_BLKMAPPED) {
		/*
		 * Chain is blockmapped, so there must be a parent.
		 * Atomically remove the chain from the parent and remove
		 * the blockmap entry.  The parent must be set modified
		 * to remove the blockmap entry.
		 */
		KKASSERT(parent != NULL);
		KKASSERT(parent->error == 0);
		KKASSERT((parent->flags & HAMMER2_CHAIN_INITIAL) == 0);
		error = hammer2_chain_modify(parent, mtid, 0, 0);
		if (error)
			goto done;

		/* Calculate blockmap pointer. */
		KKASSERT(chain->flags & HAMMER2_CHAIN_ONRBTREE);
		hammer2_spin_ex(&chain->core.spin);
		hammer2_spin_ex(&parent->core.spin);

		atomic_set_int(&chain->flags, HAMMER2_CHAIN_DELETED);
		atomic_add_int(&parent->core.live_count, -1);
		++parent->core.generation;
		RB_REMOVE(hammer2_chain_tree, &parent->core.rbtree, chain);
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_ONRBTREE);
		--parent->core.chain_count;
		chain->parent = NULL;

		switch (parent->bref.type) {
		case HAMMER2_BREF_TYPE_INODE:
			/*
			 * Access the inode's block array.  However, there
			 * is no block array if the inode is flagged
			 * DIRECTDATA.
			 */
			if (parent->data &&
			    (parent->data->ipdata.meta.op_flags &
			    HAMMER2_OPFLAG_DIRECTDATA) == 0)
				base = &parent->data->ipdata.u.blockset.blockref[0];
			else
				base = NULL;
			count = HAMMER2_SET_COUNT;
			break;
		case HAMMER2_BREF_TYPE_INDIRECT:
		case HAMMER2_BREF_TYPE_FREEMAP_NODE:
			if (parent->data)
				base = &parent->data->npdata[0];
			else
				base = NULL;
			count = parent->bytes / sizeof(hammer2_blockref_t);
			break;
		case HAMMER2_BREF_TYPE_VOLUME:
			base = &parent->data->voldata.sroot_blockset.blockref[0];
			count = HAMMER2_SET_COUNT;
			break;
		case HAMMER2_BREF_TYPE_FREEMAP:
			base = &parent->data->blkset.blockref[0];
			count = HAMMER2_SET_COUNT;
			break;
		default:
			hpanic("bad blockref type %d", parent->bref.type);
			break;
		}

		/* Delete blockmapped chain from its parent. */
		if (base)
			hammer2_base_delete(parent, base, count, chain, obref);

		hammer2_spin_unex(&parent->core.spin);
		hammer2_spin_unex(&chain->core.spin);
	} else if (chain->flags & HAMMER2_CHAIN_ONRBTREE) {
		/*
		 * Chain is not blockmapped but a parent is present.
		 * Atomically remove the chain from the parent.  There is
		 * no blockmap entry to remove.
		 */
		hammer2_spin_ex(&chain->core.spin);
		hammer2_spin_ex(&parent->core.spin);
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_DELETED);
		atomic_add_int(&parent->core.live_count, -1);
		++parent->core.generation;
		RB_REMOVE(hammer2_chain_tree, &parent->core.rbtree, chain);
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_ONRBTREE);
		--parent->core.chain_count;
		chain->parent = NULL;
		hammer2_spin_unex(&parent->core.spin);
		hammer2_spin_unex(&chain->core.spin);
	} else {
		/*
		 * Chain is not blockmapped and has no parent.  This
		 * is a degenerate case.
		 */
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_DELETED);
	}
done:
	return (error);
}

/*
 * Create an indirect block that covers one or more of the elements in the
 * current parent.  Either returns the existing parent with no locking or
 * ref changes or returns the new indirect block locked and referenced
 * and leaving the original parent lock/ref intact as well.
 *
 * If an error occurs, NULL is returned and *errorp is set to the H2 error.
 *
 * The returned chain depends on where the specified key falls.
 *
 * The key/keybits for the indirect mode only needs to follow three rules:
 *
 * (1) That all elements underneath it fit within its key space and
 *
 * (2) That all elements outside it are outside its key space.
 *
 * (3) When creating the new indirect block any elements in the current
 *     parent that fit within the new indirect block's keyspace must be
 *     moved into the new indirect block.
 *
 * (4) The keyspace chosen for the inserted indirect block CAN cover a wider
 *     keyspace the the current parent, but lookup/iteration rules will
 *     ensure (and must ensure) that rule (2) for all parents leading up
 *     to the nearest inode or the root volume header is adhered to.  This
 *     is accomplished by always recursing through matching keyspaces in
 *     the hammer2_chain_lookup() and hammer2_chain_next() API.
 *
 * The current implementation calculates the current worst-case keyspace by
 * iterating the current parent and then divides it into two halves, choosing
 * whichever half has the most elements (not necessarily the half containing
 * the requested key).
 *
 * We can also opt to use the half with the least number of elements.  This
 * causes lower-numbered keys (aka logical file offsets) to recurse through
 * fewer indirect blocks and higher-numbered keys to recurse through more.
 * This also has the risk of not moving enough elements to the new indirect
 * block and being forced to create several indirect blocks before the element
 * can be inserted.
 *
 * Must be called with an exclusively locked parent.
 *
 * NOTE: *errorp set to HAMMER_ERROR_* flags
 */
static int hammer2_chain_indkey_freemap(hammer2_chain_t *, hammer2_key_t *, int,
    hammer2_blockref_t *, int);
static int hammer2_chain_indkey_file(hammer2_chain_t *, hammer2_key_t *, int,
    hammer2_blockref_t *, int, int);
static int hammer2_chain_indkey_dir(hammer2_chain_t *, hammer2_key_t *, int,
    hammer2_blockref_t *, int, int);

static hammer2_chain_t *
hammer2_chain_create_indirect(hammer2_chain_t *parent, hammer2_key_t create_key,
    int create_bits, hammer2_tid_t mtid, int for_type, int *errorp)
{
	hammer2_dev_t *hmp;
	hammer2_blockref_t *base, *bref, bsave, dummy;
	hammer2_chain_t *chain, *ichain;
	hammer2_key_t key_beg, key_end, key_next, key = create_key;
	int ncount, loops, reason, generation, error;
	int maxloops = 300000, keybits = create_bits;
	unsigned int count, nbytes;

	/*
	 * Calculate the base blockref pointer or NULL if the chain
	 * is known to be empty.  We need to calculate the array count
	 * for RB lookups either way.
	 */
	hmp = parent->hmp;
	KKASSERT(hammer2_mtx_owned(&parent->lock));

	/*
	 * Pre-modify the parent now to avoid having to deal with error
	 * processing if we tried to later (in the middle of our loop).
	 *
	 * We are going to be moving bref's around, the indirect blocks
	 * cannot be in an initial state.  Do not pass MODIFY_OPTDATA.
	 */
	*errorp = hammer2_chain_modify(parent, mtid, 0, 0);
	if (*errorp) {
		hprintf("%s chain %016llx/%d modify error %08x\n",
		    hammer2_breftype_to_str(parent->bref.type),
		    (long long)parent->bref.key, parent->bref.keybits, *errorp);
		return (NULL);
	}
	KKASSERT((parent->flags & HAMMER2_CHAIN_INITIAL) == 0);

	base = hammer2_chain_base_and_count(parent, &count);

	/*
	 * How big should our new indirect block be?  It has to be at least
	 * as large as its parent for splits to work properly.
	 *
	 * The freemap uses a specific indirect block size.  The number of
	 * levels are built dynamically and ultimately depend on the size
	 * volume.  Because freemap blocks are taken from the reserved areas
	 * of the volume our goal is efficiency (fewer levels) and not so
	 * much to save disk space.
	 *
	 * The first indirect block level for a directory usually uses
	 * HAMMER2_IND_BYTES_MIN (4KB = 32 directory entries).  Due to
	 * the hash mechanism, this typically gives us a nominal
	 * 32 * 4 entries with one level of indirection.
	 *
	 * We use HAMMER2_IND_BYTES_NOM (16KB = 128 blockrefs) for FILE
	 * indirect blocks.  The initial 4 entries in the inode gives us
	 * 256KB.  Up to 4 indirect blocks gives us 32MB.  Three levels
	 * of indirection gives us 137GB, and so forth.  H2 can support
	 * huge file sizes but they are not typical, so we try to stick
	 * with compactness and do not use a larger indirect block size.
	 *
	 * We could use 64KB (PBUFSIZE), giving us 512 blockrefs, but
	 * due to the way indirect blocks are created this usually winds
	 * up being extremely inefficient for small files.  Even though
	 * 16KB requires more levels of indirection for very large files,
	 * the 16KB records can be ganged together into 64KB DIOs.
	 */
	if (for_type == HAMMER2_BREF_TYPE_FREEMAP_NODE ||
	    for_type == HAMMER2_BREF_TYPE_FREEMAP_LEAF) {
		nbytes = HAMMER2_FREEMAP_LEVELN_PSIZE;
	} else if (parent->bref.type == HAMMER2_BREF_TYPE_INODE) {
		if (parent->data->ipdata.meta.type ==
		    HAMMER2_OBJTYPE_DIRECTORY)
			nbytes = HAMMER2_IND_BYTES_MIN;	/* 4KB = 32 entries */
		else
			nbytes = HAMMER2_IND_BYTES_NOM;	/* 16KB = ~8MB file */
	} else {
		nbytes = HAMMER2_IND_BYTES_NOM;
	}
	if (nbytes < count * sizeof(hammer2_blockref_t)) {
		KKASSERT(for_type != HAMMER2_BREF_TYPE_FREEMAP_NODE &&
		    for_type != HAMMER2_BREF_TYPE_FREEMAP_LEAF);
		nbytes = count * sizeof(hammer2_blockref_t);
	}
	ncount = nbytes / sizeof(hammer2_blockref_t);

	/*
	 * When creating an indirect block for a freemap node or leaf
	 * the key/keybits must be fitted to static radix levels because
	 * particular radix levels use particular reserved blocks in the
	 * related zone.
	 *
	 * This routine calculates the key/radix of the indirect block
	 * we need to create, and whether it is on the high-side or the
	 * low-side.
	 */
	switch (for_type) {
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
	case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
		keybits = hammer2_chain_indkey_freemap(parent, &key, keybits,
		    base, count);
		break;
	case HAMMER2_BREF_TYPE_DATA:
		keybits = hammer2_chain_indkey_file(parent, &key, keybits, base,
		    count, ncount);
		break;
	case HAMMER2_BREF_TYPE_DIRENT:
	case HAMMER2_BREF_TYPE_INODE:
		keybits = hammer2_chain_indkey_dir(parent, &key, keybits, base,
		    count, ncount);
		break;
	default:
		hpanic("illegal indirect block for blockref type %d", for_type);
		break;
	}

	/*
	 * Normalize the key for the radix being represented, keeping the
	 * high bits and throwing away the low bits.
	 */
	key &= ~(((hammer2_key_t)1 << keybits) - 1);

	/* Ok, create our new indirect block. */
	bzero(&dummy, sizeof(dummy));
	if (for_type == HAMMER2_BREF_TYPE_FREEMAP_NODE ||
	    for_type == HAMMER2_BREF_TYPE_FREEMAP_LEAF)
		dummy.type = HAMMER2_BREF_TYPE_FREEMAP_NODE;
	else
		dummy.type = HAMMER2_BREF_TYPE_INDIRECT;
	dummy.key = key;
	dummy.keybits = keybits;
	dummy.data_off = hammer2_getradix(nbytes);
	dummy.methods =
	    HAMMER2_ENC_CHECK(HAMMER2_DEC_CHECK(parent->bref.methods)) |
	    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE);

	ichain = hammer2_chain_alloc(hmp, parent->pmp, &dummy);
	atomic_set_int(&ichain->flags, HAMMER2_CHAIN_INITIAL);
	hammer2_chain_lock(ichain, HAMMER2_RESOLVE_MAYBE);
	/* ichain has one ref at this point */

	/*
	 * We have to mark it modified to allocate its block, but use
	 * OPTDATA to allow it to remain in the INITIAL state.  Otherwise
	 * it won't be acted upon by the flush code.
	 *
	 * XXX remove OPTDATA, we need a fully initialized indirect block to
	 * be able to move the original blockref.
	 */
	*errorp = hammer2_chain_modify(ichain, mtid, 0, 0);
	if (*errorp) {
		hprintf("%s chain %016llx/%d modify error %08x\n",
		    hammer2_breftype_to_str(ichain->bref.type),
		    (long long)ichain->bref.key, ichain->bref.keybits, *errorp);
		hammer2_chain_unlock(ichain);
		hammer2_chain_drop(ichain);
		return (NULL);
	}
	KKASSERT((ichain->flags & HAMMER2_CHAIN_INITIAL) == 0);

	/*
	 * Iterate the original parent and move the matching brefs into
	 * the new indirect block.
	 *
	 * XXX handle flushes.
	 */
	key_beg = 0;
	key_end = HAMMER2_KEY_MAX;
	key_next = 0; /* avoid gcc warnings */
	hammer2_spin_ex(&parent->core.spin);
	loops = 0;
	reason = 0;

	for (;;) {
		/*
		 * Parent may have been modified, relocating its block array.
		 * Reload the base pointer.
		 */
		base = hammer2_chain_base_and_count(parent, &count);

		if (++loops > 100000)
			hpanic("excessive loops reason %d count %d "
			    "key_next %016llx",
			    reason, count, (long long)key_next);

		/*
		 * NOTE: spinlock stays intact, returned chain (if not NULL)
		 *	 is not referenced or locked which means that we
		 *	 cannot safely check its flagged / deletion status
		 *	 until we lock it.
		 */
		chain = hammer2_combined_find(parent, base, count, &key_next,
		    key_beg, key_end, &bref);
		generation = parent->core.generation;
		if (bref == NULL)
			break;
		key_next = bref->key + ((hammer2_key_t)1 << bref->keybits);

		/*
		 * Skip keys that are not within the key/radix of the new
		 * indirect block.  They stay in the parent.
		 */
		if (rounddown2(key ^ bref->key, (hammer2_key_t)1 << keybits) != 0)
			goto next_key_spinlocked;

		/*
		 * Load the new indirect block by acquiring the related
		 * chains (potentially from media as it might not be
		 * in-memory).  Then move it to the new parent (ichain).
		 *
		 * chain is referenced but not locked.  We must lock the
		 * chain to obtain definitive state.
		 */
		bsave = *bref;
		if (chain) {
			/* Use chain already present in the rbtree. */
			hammer2_chain_ref(chain);
			hammer2_spin_unex(&parent->core.spin);
			hammer2_chain_lock(chain, HAMMER2_RESOLVE_NEVER);
		} else {
			/*
			 * Get chain for blockref element.  _get returns NULL
			 * on insertion race.
			 */
			hammer2_spin_unex(&parent->core.spin);
			chain = hammer2_chain_get(parent, generation, &bsave,
			    HAMMER2_RESOLVE_NEVER);
			if (chain == NULL) {
				reason = 1;
				hammer2_spin_ex(&parent->core.spin);
				continue;
			}
		}

		/*
		 * This is always live so if the chain has been deleted
		 * we raced someone and we have to retry.
		 *
		 * NOTE: Lookups can race delete-duplicate because
		 *	 delete-duplicate does not lock the parent's core
		 *	 (they just use the spinlock on the core).
		 *
		 *	 (note reversed logic for this one)
		 */
		if (bcmp(&bsave, &chain->bref, sizeof(bsave)) ||
		    chain->parent != parent ||
		    (chain->flags & HAMMER2_CHAIN_DELETED)) {
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
			debug_hprintf("LOST PARENT RETRY\n");
			hammer2_spin_ex(&parent->core.spin);
			continue;
		}

		/*
		 * Shift the chain to the indirect block.
		 *
		 * WARNING! The (parent, chain) deletion may modify the parent
		 *	    and invalidate the base pointer.
		 *
		 * WARNING! Parent must already be marked modified, so we
		 *	    can assume that chain_delete always suceeds.
		 *
		 * WARNING! hammer2_chain_repchange() does not have to be
		 *	    called (and doesn't work anyway because we are
		 *	    only doing a partial shift).  A recursion that is
		 *	    in-progress can continue at the current parent
		 *	    and will be able to properly find its next key.
		 */
		error = hammer2_chain_delete_obref(parent, chain, mtid, 0,
		    &bsave);
		if (error)
			hpanic("error %08x", error);
		hammer2_chain_rename_obref(&ichain, chain, mtid, 0, &bsave);
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
		KKASSERT(parent->refs > 0);
		chain = NULL;
		base = NULL; /* safety */
		hammer2_spin_ex(&parent->core.spin);
next_key_spinlocked:
		if (--maxloops == 0)
			hpanic("maxloops");
		reason = 4;
		if (key_next == 0 || key_next > key_end)
			break;
		key_beg = key_next;
		/* loop */
	}
	hammer2_spin_unex(&parent->core.spin);

	/*
	 * Insert the new indirect block into the parent now that we've
	 * cleared out some entries in the parent.  We calculated a good
	 * insertion index in the loop above (ichain->index).
	 *
	 * We don't have to set UPDATE here because we mark ichain
	 * modified down below (so the normal modified -> flush -> set-moved
	 * sequence applies).
	 *
	 * The insertion shouldn't race as this is a completely new block
	 * and the parent is locked.
	 */
	base = NULL; /* safety, parent modify may change address */
	KKASSERT((ichain->flags & HAMMER2_CHAIN_ONRBTREE) == 0);
	KKASSERT(parent->core.live_count < count);
	hammer2_chain_insert(parent, ichain,
	    HAMMER2_CHAIN_INSERT_SPIN | HAMMER2_CHAIN_INSERT_LIVE, 0);

	/* Make sure flushes propogate after our manual insertion. */
	hammer2_chain_setflush(ichain);
	hammer2_chain_setflush(parent);

	/* Figure out what to return. */
	if (rounddown2(create_key ^ key, (hammer2_key_t)1 << keybits) != 0) {
		/*
		 * Key being created is outside the key range,
		 * return the original parent.
		 */
		hammer2_chain_unlock(ichain);
		hammer2_chain_drop(ichain);
	} else {
		/*
		 * Otherwise its in the range, return the new parent.
		 * (leave both the new and old parent locked).
		 */
		parent = ichain;
	}

	return (parent);
}

/*
 * Do maintenance on an indirect chain.  Both parent and chain are locked.
 *
 * Returns non-zero if (chain) is deleted, either due to being empty or
 * because its children were safely moved into the parent.
 */
int
hammer2_chain_indirect_maintenance(hammer2_chain_t *parent,
    hammer2_chain_t *chain)
{
	hammer2_blockref_t *chain_base, *base, *bref, bsave;
	hammer2_key_t key_next, key_beg, key_end;
	hammer2_chain_t *sub;
	int generation, error;
	unsigned int chain_count, count;

	/* Make sure we have an accurate live_count. */
	if ((chain->flags &
	    (HAMMER2_CHAIN_INITIAL | HAMMER2_CHAIN_COUNTEDBREFS)) == 0) {
		base = &chain->data->npdata[0];
		count = chain->bytes / sizeof(hammer2_blockref_t);
		hammer2_chain_countbrefs(chain, base, count);
	}

	/*
	 * If the indirect block is empty we can delete it.
	 * (ignore deletion error)
	 */
	if (chain->core.live_count == 0 && RB_EMPTY(&chain->core.rbtree)) {
		hammer2_chain_delete(parent, chain, chain->bref.modify_tid,
		    HAMMER2_DELETE_PERMANENT);
		hammer2_chain_repchange(parent, chain);
		return (1);
	}

	base = hammer2_chain_base_and_count(parent, &count);

	if ((parent->flags &
	    (HAMMER2_CHAIN_INITIAL | HAMMER2_CHAIN_COUNTEDBREFS)) == 0)
		hammer2_chain_countbrefs(parent, base, count);

	/*
	 * Determine if we can collapse chain into parent, calculate
	 * hysteresis for chain emptiness.
	 */
	if (parent->core.live_count + chain->core.live_count - 1 > count)
		return (0);
	chain_count = chain->bytes / sizeof(hammer2_blockref_t);
	if (chain->core.live_count > chain_count * 3 / 4)
		return (0);

	/*
	 * Ok, theoretically we can collapse chain's contents into
	 * parent.  chain is locked, but any in-memory children of chain
	 * are not.  For this to work, we must be able to dispose of any
	 * in-memory children of chain.
	 *
	 * For now require that there are no in-memory children of chain.
	 *
	 * WARNING! Both chain and parent must remain locked across this
	 *	    entire operation.
	 */

	/*
	 * Parent must be marked modified.  Don't try to collapse it if we
	 * can't mark it modified.  Once modified, destroy chain to make room
	 * and to get rid of what will be a conflicting key (this is included
	 * in the calculation above).  Finally, move the children of chain
	 * into chain's parent.
	 *
	 * This order creates an accounting problem for bref.embed.stats
	 * because we destroy chain before we remove its children.  Any
	 * elements whos blockref is already synchronized will be counted
	 * twice.  To deal with the problem we clean out chain's stats prior
	 * to deleting it.
	 */
	error = hammer2_chain_modify(parent, 0, 0, 0);
	if (error) {
		hprintf("%s chain %016llx/%d modify error %08x\n",
		    hammer2_breftype_to_str(parent->bref.type),
		    (long long)parent->bref.key, parent->bref.keybits, error);
		return (0);
	}
	error = hammer2_chain_modify(chain, chain->bref.modify_tid, 0, 0);
	if (error) {
		hprintf("%s chain %016llx/%d modify error %08x\n",
		    hammer2_breftype_to_str(chain->bref.type),
		    (long long)chain->bref.key, chain->bref.keybits, error);
		return (0);
	}

	chain->bref.embed.stats.inode_count = 0;
	chain->bref.embed.stats.data_count = 0;
	error = hammer2_chain_delete(parent, chain, chain->bref.modify_tid,
	    HAMMER2_DELETE_PERMANENT);
	KKASSERT(error == 0);

	/*
	 * The combined_find call requires core.spin to be held.  One would
	 * think there wouldn't be any conflicts since we hold chain
	 * exclusively locked, but the caching mechanism for 0-ref children
	 * does not require a chain lock.
	 */
	hammer2_spin_ex(&chain->core.spin);

	key_next = 0;
	key_beg = 0;
	key_end = HAMMER2_KEY_MAX;
	for (;;) {
		chain_base = &chain->data->npdata[0];
		chain_count = chain->bytes / sizeof(hammer2_blockref_t);
		sub = hammer2_combined_find(chain, chain_base, chain_count,
		    &key_next, key_beg, key_end, &bref);
		generation = chain->core.generation;
		if (bref == NULL)
			break;
		key_next = bref->key + ((hammer2_key_t)1 << bref->keybits);

		bsave = *bref;
		if (sub) {
			hammer2_chain_ref(sub);
			hammer2_spin_unex(&chain->core.spin);
			hammer2_chain_lock(sub, HAMMER2_RESOLVE_NEVER);
		} else {
			hammer2_spin_unex(&chain->core.spin);
			sub = hammer2_chain_get(chain, generation, &bsave,
			    HAMMER2_RESOLVE_NEVER);
			if (sub == NULL) {
				hammer2_spin_ex(&chain->core.spin);
				continue;
			}
		}
		if (bcmp(&bsave, &sub->bref, sizeof(bsave)) ||
		    sub->parent != chain ||
		    (sub->flags & HAMMER2_CHAIN_DELETED)) {
			hammer2_chain_unlock(sub);
			hammer2_chain_drop(sub);
			hammer2_spin_ex(&chain->core.spin);
			sub = NULL; /* safety */
			continue;
		}
		error = hammer2_chain_delete_obref(chain, sub,
		    sub->bref.modify_tid, 0, &bsave);
		KKASSERT(error == 0);
		hammer2_chain_rename_obref(&parent, sub,
		    sub->bref.modify_tid, HAMMER2_INSERT_SAMEPARENT, &bsave);
		hammer2_chain_unlock(sub);
		hammer2_chain_drop(sub);
		hammer2_spin_ex(&chain->core.spin);

		if (key_next == 0)
			break;
		key_beg = key_next;
	}
	hammer2_spin_unex(&chain->core.spin);

	hammer2_chain_repchange(parent, chain);

	return (1);
}

/*
 * Freemap indirect blocks
 *
 * Calculate the keybits and highside/lowside of the freemap node the
 * caller is creating.
 *
 * This routine will specify the next higher-level freemap key/radix
 * representing the lowest-ordered set.  By doing so, eventually all
 * low-ordered sets will be moved one level down.
 *
 * We have to be careful here because the freemap reserves a limited
 * number of blocks for a limited number of levels.  So we can't just
 * push indiscriminately.
 */
int
hammer2_chain_indkey_freemap(hammer2_chain_t *parent, hammer2_key_t *keyp,
    int keybits, hammer2_blockref_t *base, int count)
{
	hammer2_chain_t *chain;
	hammer2_blockref_t *bref;
	hammer2_key_t key, key_beg, key_end, key_next;
	int maxloops = 300000;

	key = *keyp;
	keybits = 64;

	/*
	 * Calculate the range of keys in the array being careful to skip
	 * slots which are overridden with a deletion.
	 */
	key_beg = 0;
	key_end = HAMMER2_KEY_MAX;
	hammer2_spin_ex(&parent->core.spin);

	for (;;) {
		if (--maxloops == 0)
			hpanic("maxloops");
		chain = hammer2_combined_find(parent, base, count, &key_next,
		    key_beg, key_end, &bref);

		/* Exhausted search. */
		if (bref == NULL)
			break;

		/* Skip deleted chains. */
		if (chain && (chain->flags & HAMMER2_CHAIN_DELETED)) {
			if (key_next == 0 || key_next > key_end)
				break;
			key_beg = key_next;
			continue;
		}

		/*
		 * Use the full live (not deleted) element for the scan
		 * iteration.  HAMMER2 does not allow partial replacements.
		 *
		 * XXX should be built into hammer2_combined_find().
		 */
		key_next = bref->key + ((hammer2_key_t)1 << bref->keybits);

		if (keybits > bref->keybits) {
			key = bref->key;
			keybits = bref->keybits;
		} else if (keybits == bref->keybits && bref->key < key) {
			key = bref->key;
		}
		if (key_next == 0)
			break;
		key_beg = key_next;
	}
	hammer2_spin_unex(&parent->core.spin);

	/*
	 * Return the keybits for a higher-level FREEMAP_NODE covering
	 * this node.
	 */
	switch (keybits) {
	case HAMMER2_FREEMAP_LEVEL0_RADIX:
		keybits = HAMMER2_FREEMAP_LEVEL1_RADIX;
		break;
	case HAMMER2_FREEMAP_LEVEL1_RADIX:
		keybits = HAMMER2_FREEMAP_LEVEL2_RADIX;
		break;
	case HAMMER2_FREEMAP_LEVEL2_RADIX:
		keybits = HAMMER2_FREEMAP_LEVEL3_RADIX;
		break;
	case HAMMER2_FREEMAP_LEVEL3_RADIX:
		keybits = HAMMER2_FREEMAP_LEVEL4_RADIX;
		break;
	case HAMMER2_FREEMAP_LEVEL4_RADIX:
		keybits = HAMMER2_FREEMAP_LEVEL5_RADIX;
		break;
	case HAMMER2_FREEMAP_LEVEL5_RADIX:
		hpanic("level too high");
		break;
	default:
		hpanic("bad radix %d", keybits);
		break;
	}
	*keyp = key;

	return (keybits);
}

/*
 * File indirect blocks
 *
 * Calculate the key/keybits for the indirect block to create by scanning
 * existing keys.  The key being created is also passed in *keyp and can be
 * inside or outside the indirect block.  Regardless, the indirect block
 * must hold at least two keys in order to guarantee sufficient space.
 *
 * We use a modified version of the freemap's fixed radix tree, but taylored
 * for file data.  Basically we configure an indirect block encompassing the
 * smallest key.
 */
static int
hammer2_chain_indkey_file(hammer2_chain_t *parent, hammer2_key_t *keyp,
    int keybits, hammer2_blockref_t *base, int count, int ncount)
{
	hammer2_chain_t *chain;
	hammer2_blockref_t *bref;
	hammer2_key_t key, key_beg, key_end, key_next;
	int nradix = 0, maxloops = 300000;

	key = *keyp;
	keybits = 64;

	/*
	 * Calculate the range of keys in the array being careful to skip
	 * slots which are overridden with a deletion.
	 *
	 * Locate the smallest key.
	 */
	key_beg = 0;
	key_end = HAMMER2_KEY_MAX;
	hammer2_spin_ex(&parent->core.spin);

	for (;;) {
		if (--maxloops == 0)
			hpanic("maxloops");
		chain = hammer2_combined_find(parent, base, count, &key_next,
		    key_beg, key_end, &bref);

		/* Exhausted search. */
		if (bref == NULL)
			break;

		/* Skip deleted chains. */
		if (chain && (chain->flags & HAMMER2_CHAIN_DELETED)) {
			if (key_next == 0 || key_next > key_end)
				break;
			key_beg = key_next;
			continue;
		}

		/*
		 * Use the full live (not deleted) element for the scan
		 * iteration.  HAMMER2 does not allow partial replacements.
		 *
		 * XXX should be built into hammer2_combined_find().
		 */
		key_next = bref->key + ((hammer2_key_t)1 << bref->keybits);

		if (keybits > bref->keybits) {
			key = bref->key;
			keybits = bref->keybits;
		} else if (keybits == bref->keybits && bref->key < key) {
			key = bref->key;
		}
		if (key_next == 0)
			break;
		key_beg = key_next;
	}
	hammer2_spin_unex(&parent->core.spin);

	/*
	 * Calculate the static keybits for a higher-level indirect block
	 * that contains the key.
	 */
	*keyp = key;

	switch (ncount) {
	case HAMMER2_IND_COUNT_MIN:
		nradix = HAMMER2_IND_RADIX_MIN - HAMMER2_BLOCKREF_RADIX;
		break;
	case HAMMER2_IND_COUNT_NOM:
		nradix = HAMMER2_IND_RADIX_NOM - HAMMER2_BLOCKREF_RADIX;
		break;
	case HAMMER2_IND_COUNT_MAX:
		nradix = HAMMER2_IND_RADIX_MAX - HAMMER2_BLOCKREF_RADIX;
		break;
	default:
		hpanic("bad ncount %d", ncount);
		break;
	}

	/*
	 * The largest radix that can be returned for an indirect block is
	 * 63 bits.  (The largest practical indirect block radix is actually
	 * 62 bits because the top-level inode or volume root contains four
	 * entries, but allow 63 to be returned).
	 */
	if (nradix >= 64)
		nradix = 63;

	return (keybits + nradix);
}

/*
 * Directory indirect blocks.
 *
 * Covers both the inode index (directory of inodes), and directory contents
 * (filenames hardlinked to inodes).
 *
 * Because directory keys are hashed we generally try to cut the space in
 * half.  We accomodate the inode index (which tends to have linearly
 * increasing inode numbers) by ensuring that the keyspace is at least large
 * enough to fill up the indirect block being created.
 */
static int
hammer2_chain_indkey_dir(hammer2_chain_t *parent, hammer2_key_t *keyp,
    int keybits, hammer2_blockref_t *base, int count, int ncount)
{
	hammer2_blockref_t *bref;
	hammer2_chain_t	*chain;
	hammer2_key_t key_beg, key_end, key_next, key;
	int nkeybits, locount, hicount, maxloops = 300000;

	/*
	 * NOTE: We can't take a shortcut here anymore for inodes because
	 *	 the root directory can contain a mix of inodes and directory
	 *	 entries (we used to just return 63 if parent->bref.type was
	 *	 HAMMER2_BREF_TYPE_INODE.
	 */
	key = *keyp;
	locount = 0;
	hicount = 0;

	/*
	 * Calculate the range of keys in the array being careful to skip
	 * slots which are overridden with a deletion.
	 */
	key_beg = 0;
	key_end = HAMMER2_KEY_MAX;
	hammer2_spin_ex(&parent->core.spin);

	for (;;) {
		if (--maxloops == 0)
			hpanic("maxloops");
		chain = hammer2_combined_find(parent, base, count, &key_next,
		    key_beg, key_end, &bref);

		/* Exhausted search. */
		if (bref == NULL)
			break;

		/* Deleted object. */
		if (chain && (chain->flags & HAMMER2_CHAIN_DELETED)) {
			if (key_next == 0 || key_next > key_end)
				break;
			key_beg = key_next;
			continue;
		}

		/*
		 * Use the full live (not deleted) element for the scan
		 * iteration.  HAMMER2 does not allow partial replacements.
		 *
		 * XXX should be built into hammer2_combined_find().
		 */
		key_next = bref->key + ((hammer2_key_t)1 << bref->keybits);

		/*
		 * Expand our calculated key range (key, keybits) to fit
		 * the scanned key.  nkeybits represents the full range
		 * that we will later cut in half (two halves @ nkeybits - 1).
		 */
		nkeybits = keybits;
		if (nkeybits < bref->keybits) {
			if (bref->keybits > 64)
				hpanic("bad %s blockref %016llx/%d",
				    hammer2_breftype_to_str(bref->type),
				    (long long)bref->key, bref->keybits);
			nkeybits = bref->keybits;
		}
		while (nkeybits < 64 &&
		    rounddown2(key ^ bref->key, (hammer2_key_t)1 << nkeybits) != 0)
			++nkeybits;

		/*
		 * If the new key range is larger we have to determine
		 * which side of the new key range the existing keys fall
		 * under by checking the high bit, then collapsing the
		 * locount into the hicount or vise-versa.
		 */
		if (keybits != nkeybits) {
			if (((hammer2_key_t)1 << (nkeybits - 1)) & key) {
				hicount += locount;
				locount = 0;
			} else {
				locount += hicount;
				hicount = 0;
			}
			keybits = nkeybits;
		}

		/*
		 * The newly scanned key will be in the lower half or the
		 * upper half of the (new) key range.
		 */
		if (((hammer2_key_t)1 << (nkeybits - 1)) & bref->key)
			++hicount;
		else
			++locount;

		if (key_next == 0)
			break;
		key_beg = key_next;
	}
	hammer2_spin_unex(&parent->core.spin);
	bref = NULL; /* now invalid (safety) */

	/*
	 * Adjust keybits to represent half of the full range calculated
	 * above (radix 63 max) for our new indirect block.
	 */
	--keybits;

	/*
	 * Expand keybits to hold at least ncount elements.  ncount will be
	 * a power of 2.  This is to try to completely fill leaf nodes (at
	 * least for keys which are not hashes).
	 *
	 * We aren't counting 'in' or 'out', we are counting 'high side'
	 * and 'low side' based on the bit at (1LL << keybits).  We want
	 * everything to be inside in these cases so shift it all to
	 * the low or high side depending on the new high bit.
	 */
	while (((hammer2_key_t)1 << keybits) < (hammer2_key_t)ncount) {
		++keybits;
		if (key & ((hammer2_key_t)1 << keybits)) {
			hicount += locount;
			locount = 0;
		} else {
			locount += hicount;
			hicount = 0;
		}
	}

	if (hicount > locount)
		key |= (hammer2_key_t)1 << keybits;
	else
		key &= ~(hammer2_key_t)1 << keybits;

	*keyp = key;

	return (keybits);
}

/*
 * Sets CHAIN_DELETED and remove the chain's blockref from the parent if
 * it exists.
 *
 * Both parent and chain must be locked exclusively.
 *
 * This function will modify the parent if the blockref requires removal
 * from the parent's block table.
 *
 * This function is NOT recursive.  Any entity already pushed into the
 * chain (such as an inode) may still need visibility into its contents,
 * as well as the ability to read and modify the contents.  For example,
 * for an unlinked file which is still open.
 *
 * Also note that the flusher is responsible for cleaning up empty
 * indirect blocks.
 */
int
hammer2_chain_delete(hammer2_chain_t *parent, hammer2_chain_t *chain,
    hammer2_tid_t mtid, int flags)
{
	int error = 0;

	KKASSERT(hammer2_mtx_owned(&chain->lock));

	/*
	 * Nothing to do if already marked.
	 *
	 * We need the spinlock on the core whos RBTREE contains chain
	 * to protect against races.
	 */
	if ((chain->flags & HAMMER2_CHAIN_DELETED) == 0) {
		KKASSERT((chain->flags & HAMMER2_CHAIN_DELETED) == 0 &&
		    chain->parent == parent);
		error = _hammer2_chain_delete_helper(parent, chain, mtid, flags,
		    NULL);
	}

	/*
	 * Permanent deletions mark the chain as destroyed.
	 *
	 * NOTE: We do not setflush the chain unless the deletion is
	 *	 permanent, since the deletion of a chain does not actually
	 *	 require it to be flushed.
	 */
	if (error == 0) {
		if (flags & HAMMER2_DELETE_PERMANENT) {
			atomic_set_int(&chain->flags, HAMMER2_CHAIN_DESTROY);
			hammer2_chain_setflush(chain);
		}
	}

	return (error);
}

static int
hammer2_chain_delete_obref(hammer2_chain_t *parent, hammer2_chain_t *chain,
    hammer2_tid_t mtid, int flags, hammer2_blockref_t *obref)
{
	int error = 0;

	KKASSERT(hammer2_mtx_owned(&chain->lock));

	/*
	 * Nothing to do if already marked.
	 *
	 * We need the spinlock on the core whos RBTREE contains chain
	 * to protect against races.
	 */
	obref->type = HAMMER2_BREF_TYPE_EMPTY;
	if ((chain->flags & HAMMER2_CHAIN_DELETED) == 0) {
		KKASSERT((chain->flags & HAMMER2_CHAIN_DELETED) == 0 &&
		    chain->parent == parent);
		error = _hammer2_chain_delete_helper(parent, chain, mtid, flags,
		    obref);
	}

	/*
	 * Permanent deletions mark the chain as destroyed.
	 *
	 * NOTE: We do not setflush the chain unless the deletion is
	 *	 permanent, since the deletion of a chain does not actually
	 *	 require it to be flushed.
	 */
	if (error == 0) {
		if (flags & HAMMER2_DELETE_PERMANENT) {
			atomic_set_int(&chain->flags, HAMMER2_CHAIN_DESTROY);
			hammer2_chain_setflush(chain);
		}
	}

	return (error);
}

/*
 * Returns the index of the nearest element in the blockref array >= elm.
 * Returns (count) if no element could be found.
 *
 * Sets *key_nextp to the next key for loop purposes but does not modify
 * it if the next key would be higher than the current value of *key_nextp.
 * Note that *key_nexp can overflow to 0, which should be tested by the
 * caller.
 *
 * WARNING!  Must be called with parent's spinlock held.  Spinlock remains
 *	     held through the operation.
 */
static int
hammer2_base_find(hammer2_chain_t *parent, hammer2_blockref_t *base, int count,
    hammer2_key_t *key_nextp, hammer2_key_t key_beg)
{
	hammer2_blockref_t *scan;
	hammer2_key_t scan_end;
	int i, limit;

	/*
	 * Require the live chain's already have their core's counted
	 * so we can optimize operations.
	 */
	KKASSERT(parent->flags & HAMMER2_CHAIN_COUNTEDBREFS);

	/* Degenerate case. */
	if (count == 0 || base == NULL)
		return (count);

	/*
	 * Sequential optimization using parent->cache_index.  This is
	 * the most likely scenario.
	 *
	 * We can avoid trailing empty entries on live chains, otherwise
	 * we might have to check the whole block array.
	 */
	i = parent->cache_index;	/* SMP RACE OK */
	cpu_ccfence();
	limit = parent->core.live_zero;
	if (i >= limit)
		i = limit - 1;
	if (i < 0)
		i = 0;
	KKASSERT(i < count);

	/* Search backwards. */
	scan = &base[i];
	while (i > 0 && (scan->type == HAMMER2_BREF_TYPE_EMPTY ||
	    scan->key > key_beg)) {
		--scan;
		--i;
	}
	parent->cache_index = i;

	/*
	 * Search forwards, stop when we find a scan element which
	 * encloses the key or until we know that there are no further
	 * elements.
	 */
	while (i < count) {
		if (scan->type != HAMMER2_BREF_TYPE_EMPTY) {
			scan_end = scan->key +
			    ((hammer2_key_t)1 << scan->keybits) - 1;
			if (scan->key > key_beg || scan_end >= key_beg)
				break;
		}
		if (i >= limit)
			return (count);
		++scan;
		++i;
	}
	if (i != count) {
		parent->cache_index = i;
		if (i >= limit) {
			i = count;
		} else {
			scan_end = scan->key +
			    ((hammer2_key_t)1 << scan->keybits);
			if (scan_end && (*key_nextp > scan_end ||
			    *key_nextp == 0))
				*key_nextp = scan_end;
		}
	}
	return (i);
}

/*
 * Do a combined search and return the next match either from the blockref
 * array or from the in-memory chain.  Sets *brefp to the returned bref in
 * both cases, or sets it to NULL if the search exhausted.  Only returns
 * a non-NULL chain if the search matched from the in-memory chain.
 *
 * When no in-memory chain has been found and a non-NULL bref is returned
 * in *brefp.
 *
 * The returned chain is not locked or referenced.  Use the returned bref
 * to determine if the search exhausted or not.  Iterate if the base find
 * is chosen but matches a deleted chain.
 *
 * WARNING!  Must be called with parent's spinlock held.  Spinlock remains
 *	     held through the operation.
 */
static hammer2_chain_t *
hammer2_combined_find(hammer2_chain_t *parent, hammer2_blockref_t *base,
    int count, hammer2_key_t *key_nextp, hammer2_key_t key_beg,
    hammer2_key_t key_end, hammer2_blockref_t **brefp)
{
	hammer2_chain_t *chain;
	hammer2_blockref_t *bref;
	int i;

	/* Lookup in block array and in rbtree. */
	*key_nextp = key_end + 1;
	i = hammer2_base_find(parent, base, count, key_nextp, key_beg);
	chain = hammer2_chain_find(parent, key_nextp, key_beg, key_end);

	/* Neither matched. */
	if (i == count && chain == NULL) {
		*brefp = NULL;
		return (NULL);
	}

	/* Only chain matched. */
	if (i == count) {
		bref = &chain->bref;
		goto found;
	}

	/* Only blockref matched. */
	if (chain == NULL) {
		bref = &base[i];
		goto found;
	}

	/*
	 * Both in-memory and blockref matched, select the nearer element.
	 *
	 * If both are flush with the left-hand side or both are the
	 * same distance away, select the chain.  In this situation the
	 * chain must have been loaded from the matching blockmap.
	 */
	if ((chain->bref.key <= key_beg && base[i].key <= key_beg) ||
	    chain->bref.key == base[i].key) {
		KKASSERT(chain->bref.key == base[i].key);
		bref = &chain->bref;
		goto found;
	}

	/* Select the nearer key. */
	if (chain->bref.key < base[i].key) {
		bref = &chain->bref;
	} else {
		bref = &base[i];
		chain = NULL;
	}

	/* If the bref is out of bounds we've exhausted our search. */
found:
	if (bref->key > key_end) {
		*brefp = NULL;
		chain = NULL;
	} else {
		*brefp = bref;
	}
	return (chain);
}

/*
 * Locate the specified block array element and delete it.  The element
 * must exist.  The spin lock on the related chain must be held.
 *
 * NOTE: live_count was adjusted when the chain was deleted, so it does not
 *	 need to be adjusted when we commit the media change.
 */
void
hammer2_base_delete(hammer2_chain_t *parent, hammer2_blockref_t *base,
    int count, hammer2_chain_t *chain, hammer2_blockref_t *obref)
{
	hammer2_blockref_t *scan, *elm = &chain->bref;
	hammer2_key_t key_next;
	int i;

	/*
	 * Delete element.  Expect the element to exist.
	 *
	 * XXX see caller, flush code not yet sophisticated enough to prevent
	 *     re-flushed in some cases.
	 */
	key_next = 0; /* max range */
	i = hammer2_base_find(parent, base, count, &key_next, elm->key);
	scan = &base[i];

	if (i == count || scan->type == HAMMER2_BREF_TYPE_EMPTY ||
	    scan->key != elm->key ||
	    ((chain->flags & HAMMER2_CHAIN_BLKMAPUPD) == 0 &&
	    scan->keybits != elm->keybits))
		hpanic("delete %s elm %016llx/%d from %s base %016llx/%d "
		    "not found at %d/%d",
		    hammer2_breftype_to_str(elm->type),
		    (long long)elm->key, elm->keybits,
		    hammer2_breftype_to_str(base->type),
		    (long long)base->key, base->keybits, i, count);

	/*
	 * Update stats and zero the entry.
	 * NOTE: Handle radix == 0 (0 bytes) case.
	 */
	if ((int)(scan->data_off & HAMMER2_OFF_MASK_RADIX))
		parent->bref.embed.stats.data_count -= (hammer2_off_t)1 <<
		    (int)(scan->data_off & HAMMER2_OFF_MASK_RADIX);

	switch (scan->type) {
	case HAMMER2_BREF_TYPE_INODE:
		--parent->bref.embed.stats.inode_count;
		/* fall through */
	case HAMMER2_BREF_TYPE_DATA:
		if (parent->bref.leaf_count == HAMMER2_BLOCKREF_LEAF_MAX) {
			atomic_set_int(&chain->flags,
			    HAMMER2_CHAIN_HINT_LEAF_COUNT);
		} else {
			if (parent->bref.leaf_count)
				--parent->bref.leaf_count;
		}
		/* fall through */
	case HAMMER2_BREF_TYPE_INDIRECT:
		if (scan->type != HAMMER2_BREF_TYPE_DATA) {
			parent->bref.embed.stats.data_count -=
			    scan->embed.stats.data_count;
			parent->bref.embed.stats.inode_count -=
			    scan->embed.stats.inode_count;
		}
		if (scan->type == HAMMER2_BREF_TYPE_INODE)
			break;
		if (parent->bref.leaf_count == HAMMER2_BLOCKREF_LEAF_MAX) {
			atomic_set_int(&chain->flags,
			    HAMMER2_CHAIN_HINT_LEAF_COUNT);
		} else {
			if (parent->bref.leaf_count <= scan->leaf_count)
				parent->bref.leaf_count = 0;
			else
				parent->bref.leaf_count -= scan->leaf_count;
		}
		break;
	case HAMMER2_BREF_TYPE_DIRENT:
		if (parent->bref.leaf_count == HAMMER2_BLOCKREF_LEAF_MAX) {
			atomic_set_int(&chain->flags,
			    HAMMER2_CHAIN_HINT_LEAF_COUNT);
		} else {
			if (parent->bref.leaf_count)
				--parent->bref.leaf_count;
		}
	default:
		break;
	}

	if (obref)
		*obref = *scan;
	bzero(scan, sizeof(*scan));

	/* We can only optimize parent->core.live_zero for live chains. */
	if (parent->core.live_zero == i + 1) {
		while (--i >= 0 && base[i].type == HAMMER2_BREF_TYPE_EMPTY)
			;
		parent->core.live_zero = i + 1;
	}

	/* Clear appropriate blockmap flags in chain. */
	atomic_clear_int(&chain->flags,
	    HAMMER2_CHAIN_BLKMAPPED | HAMMER2_CHAIN_BLKMAPUPD);
}

/*
 * Insert the specified element.  The block array must not already have the
 * element and must have space available for the insertion.
 * The spin lock on the related chain must be held.
 *
 * NOTE: live_count was adjusted when the chain was deleted, so it does not
 *	 need to be adjusted when we commit the media change.
 */
void
hammer2_base_insert(hammer2_chain_t *parent, hammer2_blockref_t *base,
    int count, hammer2_chain_t *chain, hammer2_blockref_t *elm)
{
	hammer2_key_t key_next, xkey;
	int i, j, k, l, u = 1;

	/*
	 * Insert new element.  Expect the element to not already exist
	 * unless we are replacing it.
	 *
	 * XXX see caller, flush code not yet sophisticated enough to prevent
	 *     re-flushed in some cases.
	 */
	key_next = 0; /* max range */
	i = hammer2_base_find(parent, base, count, &key_next, elm->key);

	/*
	 * Shortcut fill optimization, typical ordered insertion(s) may not
	 * require a search.
	 */
	KKASSERT(i >= 0 && i <= count);

	/* Set appropriate blockmap flags in chain (if not NULL). */
	if (chain)
		atomic_set_int(&chain->flags, HAMMER2_CHAIN_BLKMAPPED);

	/* Update stats and zero the entry. */
	if ((int)(elm->data_off & HAMMER2_OFF_MASK_RADIX))
		parent->bref.embed.stats.data_count += (hammer2_off_t)1 <<
		    (int)(elm->data_off & HAMMER2_OFF_MASK_RADIX);

	switch (elm->type) {
	case HAMMER2_BREF_TYPE_INODE:
		++parent->bref.embed.stats.inode_count;
		/* fall through */
	case HAMMER2_BREF_TYPE_DATA:
		if (parent->bref.leaf_count != HAMMER2_BLOCKREF_LEAF_MAX)
			++parent->bref.leaf_count;
		/* fall through */
	case HAMMER2_BREF_TYPE_INDIRECT:
		if (elm->type != HAMMER2_BREF_TYPE_DATA) {
			parent->bref.embed.stats.data_count +=
			    elm->embed.stats.data_count;
			parent->bref.embed.stats.inode_count +=
			    elm->embed.stats.inode_count;
		}
		if (elm->type == HAMMER2_BREF_TYPE_INODE)
			break;
		if (parent->bref.leaf_count + elm->leaf_count <
		    HAMMER2_BLOCKREF_LEAF_MAX)
			parent->bref.leaf_count += elm->leaf_count;
		else
			parent->bref.leaf_count = HAMMER2_BLOCKREF_LEAF_MAX;
		break;
	case HAMMER2_BREF_TYPE_DIRENT:
		if (parent->bref.leaf_count != HAMMER2_BLOCKREF_LEAF_MAX)
			++parent->bref.leaf_count;
		break;
	default:
		break;
	}

	/* We can only optimize parent->core.live_zero for live chains. */
	if (i == count && parent->core.live_zero < count) {
		i = parent->core.live_zero++;
		base[i] = *elm;
		return;
	}

	xkey = elm->key + ((hammer2_key_t)1 << elm->keybits) - 1;
	if (i != count && (base[i].key < elm->key || xkey >= base[i].key))
		hpanic("insert %s elm %016llx/%d to %s base %016llx/%d "
		    "overlapping at %d/%d",
		    hammer2_breftype_to_str(elm->type),
		    (long long)elm->key, elm->keybits,
		    hammer2_breftype_to_str(base->type),
		    (long long)base->key, base->keybits, i, count);

	/* Try to find an empty slot before or after. */
	j = i;
	k = i;
	while (j > 0 || k < count) {
		/* NetBSD bcopy(9) doesn't support overlapped region. */
		--j;
		if (j >= 0 && base[j].type == HAMMER2_BREF_TYPE_EMPTY) {
			if (j == i - 1) {
				base[j] = *elm;
			} else {
				memmove(&base[j], &base[j+1],
				    (i - j - 1) * sizeof(*base));
				base[i - 1] = *elm;
			}
			goto validate;
		}
		++k;
		if (k < count && base[k].type == HAMMER2_BREF_TYPE_EMPTY) {
			memmove(&base[i+1], &base[i],
			    (k - i) * sizeof(hammer2_blockref_t));
			base[i] = *elm;
			/*
			 * We can only update parent->core.live_zero for live
			 * chains.
			 */
			if (parent->core.live_zero <= k)
				parent->core.live_zero = k + 1;
			u = 2;
			goto validate;
		}
	}
	hpanic("no room");

	/* Debugging */
validate:
	key_next = 0;
	for (l = 0; l < count; ++l) {
		if (base[l].type != HAMMER2_BREF_TYPE_EMPTY) {
			key_next = base[l].key +
			    ((hammer2_key_t)1 << base[l].keybits) - 1;
			break;
		}
	}
	while (++l < count) {
		if (base[l].type != HAMMER2_BREF_TYPE_EMPTY) {
			if (base[l].key <= key_next)
				hpanic("insert %d %d,%d,%d fail %d",
				    u, i, j, k, l);
			key_next = base[l].key +
			    ((hammer2_key_t)1 << base[l].keybits) - 1;
		}
	}
}

/*
 * Set the check data for a chain.  This can be a heavy-weight operation
 * and typically only runs on-flush.  For file data check data is calculated
 * when the logical buffers are flushed.
 */
void
hammer2_chain_setcheck(hammer2_chain_t *chain, void *bdata)
{
	atomic_clear_int(&chain->flags, HAMMER2_CHAIN_NOTTESTED);

	switch (HAMMER2_DEC_CHECK(chain->bref.methods)) {
	case HAMMER2_CHECK_NONE:
		break;
	case HAMMER2_CHECK_DISABLED:
		break;
	case HAMMER2_CHECK_ISCSI32:
		chain->bref.check.iscsi32.value =
		    hammer2_icrc32(bdata, chain->bytes);
		break;
	case HAMMER2_CHECK_XXHASH64:
		chain->bref.check.xxhash64.value =
		    XXH64(bdata, chain->bytes, XXH_HAMMER2_SEED);
		break;
	case HAMMER2_CHECK_SHA192:
		{
		SHA2_CTX hash_ctx;
		union {
			uint8_t digest[SHA256_DIGEST_LENGTH];
			uint64_t digest64[SHA256_DIGEST_LENGTH/8];
		} u;
		SHA256Init(&hash_ctx);
		SHA256Update(&hash_ctx, bdata, chain->bytes);
		SHA256Final(u.digest, &hash_ctx);
		u.digest64[2] ^= u.digest64[3];
		bcopy(u.digest, chain->bref.check.sha192.data,
		    sizeof(chain->bref.check.sha192.data));
		}
		break;
	case HAMMER2_CHECK_FREEMAP:
		chain->bref.check.freemap.icrc32 =
		    hammer2_icrc32(bdata, chain->bytes);
		break;
	default:
		hpanic("bad check type %02x", chain->bref.methods);
		break;
	}
}

/*
 * Returns non-zero on success, 0 on failure.
 */
static int
hammer2_chain_testcheck(const hammer2_chain_t *chain, void *bdata)
{
	static int count = 0;
	int r = 0;

	if (chain->flags & HAMMER2_CHAIN_NOTTESTED)
		return (1);

	switch (HAMMER2_DEC_CHECK(chain->bref.methods)) {
	case HAMMER2_CHECK_NONE:
		r = 1;
		break;
	case HAMMER2_CHECK_DISABLED:
		r = 1;
		break;
	case HAMMER2_CHECK_ISCSI32:
		r = chain->bref.check.iscsi32.value ==
		    hammer2_icrc32(bdata, chain->bytes);
		break;
	case HAMMER2_CHECK_XXHASH64:
		r = chain->bref.check.xxhash64.value ==
		    XXH64(bdata, chain->bytes, XXH_HAMMER2_SEED);
		break;
	case HAMMER2_CHECK_SHA192:
		{
		SHA2_CTX hash_ctx;
		union {
			uint8_t digest[SHA256_DIGEST_LENGTH];
			uint64_t digest64[SHA256_DIGEST_LENGTH/8];
		} u;
		SHA256Init(&hash_ctx);
		SHA256Update(&hash_ctx, bdata, chain->bytes);
		SHA256Final(u.digest, &hash_ctx);
		u.digest64[2] ^= u.digest64[3];
		r = bcmp(u.digest, chain->bref.check.sha192.data,
		    sizeof(chain->bref.check.sha192.data)) == 0;
		}
		break;
	case HAMMER2_CHECK_FREEMAP:
		r = chain->bref.check.freemap.icrc32 ==
		    hammer2_icrc32(bdata, chain->bytes);
		break;
	default:
		hpanic("bad check type %02x", chain->bref.methods);
		break;
	}

	if (r == 0 && count < 1000) {
		hprintf("failed: chain %s %016llx %016llx/%d meth %02x "
		    "mir %016llx mod %016llx flags %08x\n",
		    hammer2_breftype_to_str(chain->bref.type),
		    (long long)chain->bref.data_off, (long long)chain->bref.key,
		    chain->bref.keybits, chain->bref.methods,
		    (long long)chain->bref.mirror_tid,
		    (long long)chain->bref.modify_tid, chain->flags);
		count++;
		if (count >= 1000)
			hprintf("gave up\n");
	}

	return (r);
}

/*
 * Acquire the chain and parent representing the specified inode for the
 * device at the specified cluster index.
 *
 * The flags passed in are LOOKUP flags, not RESOLVE flags.
 *
 * If we are unable to locate the inode, HAMMER2_ERROR_EIO or HAMMER2_ERROR_CHECK
 * is returned.  In case of error, *chainp and/or *parentp may still be returned
 * non-NULL.
 *
 * The caller may pass-in a locked *parentp and/or *chainp, or neither.
 * They will be unlocked and released by this function.  The *parentp and
 * *chainp representing the located inode are returned locked.
 *
 * The returned error includes any error on the returned chain in addition to
 * errors incurred while trying to lookup the inode.  However, a chain->error
 * might not be recognized if HAMMER2_LOOKUP_NODATA is passed.  This flag may
 * not be passed to this function.
 */
int
hammer2_chain_inode_find(hammer2_pfs_t *pmp, hammer2_key_t inum, int clindex,
    int flags, hammer2_chain_t **parentp, hammer2_chain_t **chainp)
{
	hammer2_inode_t *ip;
	hammer2_chain_t *parent, *rchain;
	hammer2_key_t key_dummy;
	int resolve_flags, error;

	KKASSERT((flags & HAMMER2_LOOKUP_NODATA) == 0);

	resolve_flags = (flags & HAMMER2_LOOKUP_SHARED) ?
	    HAMMER2_RESOLVE_SHARED : 0;

	/* Caller expects us to replace these. */
	if (*chainp) {
		hammer2_chain_unlock(*chainp);
		hammer2_chain_drop(*chainp);
		*chainp = NULL;
	}
	if (*parentp) {
		hammer2_chain_unlock(*parentp);
		hammer2_chain_drop(*parentp);
		*parentp = NULL;
	}

	/*
	 * Be very careful, this is a backend function and we CANNOT
	 * lock any frontend inode structure we find.  But we have to
	 * look the inode up this way first in case it exists but is
	 * detached from the radix tree.
	 */
	ip = hammer2_inode_lookup(pmp, inum);
	if (ip) {
		*chainp = hammer2_inode_chain_and_parent(ip, clindex, parentp,
		    resolve_flags);
		hammer2_inode_drop(ip);
		if (*chainp)
			return ((*chainp)->error);
		if (*parentp) {
			hammer2_chain_unlock(*parentp);
			hammer2_chain_drop(*parentp);
			*parentp = NULL;
		}
	}

	/*
	 * Inodes hang off of the iroot (bit 63 is clear, differentiating
	 * inodes from root directory entries in the key lookup).
	 */
	parent = hammer2_inode_chain(pmp->iroot, clindex, resolve_flags);
	rchain = NULL;
	if (parent) {
		/*
		 * NOTE: rchain can be returned as NULL even if error == 0
		 *	 (i.e. not found)
		 */
		rchain = hammer2_chain_lookup(&parent, &key_dummy, inum, inum,
		    &error, flags);
		/*
		 * Propagate a chain-specific error to caller.
		 *
		 * If the chain is not errored, we must still validate that the inode
		 * number is correct, because all hell will break loose if it isn't
		 * correct.  It should always be correct so print to the console and
		 * simulate a CHECK error if it is not.
		 */
		if (error == 0 && rchain) {
			error = rchain->error;
			if (error == 0 && rchain->data)
				if (inum != rchain->data->ipdata.meta.inum) {
					hprintf("lookup inum %016llx, got valid "
					    "inode but with inum %016llx\n",
					    (long long)inum,
					    (long long)rchain->data->ipdata.meta.inum);
					error = HAMMER2_ERROR_CHECK;
					rchain->error = error;
				}
		}
	} else {
		error = HAMMER2_ERROR_EIO;
	}
	*parentp = parent;
	*chainp = rchain;

	return (error);
}

/*
 * Used by the bulkscan code to snapshot the synchronized storage for
 * a volume, allowing it to be scanned concurrently against normal
 * operation.
 */
hammer2_chain_t *
hammer2_chain_bulksnap(hammer2_dev_t *hmp)
{
	hammer2_chain_t *copy;

	copy = hammer2_chain_alloc(hmp, hmp->spmp, &hmp->vchain.bref);
	copy->data = hmalloc(sizeof(copy->data->voldata), M_HAMMER2,
	    M_WAITOK | M_ZERO);
	hammer2_voldata_lock(hmp);
	copy->data->voldata = hmp->volsync;
	hammer2_voldata_unlock(hmp);

	return (copy);
}

void
hammer2_chain_bulkdrop(hammer2_chain_t *copy)
{
	KKASSERT(copy->bref.type == HAMMER2_BREF_TYPE_VOLUME);
	KKASSERT(copy->data);

	hfree(copy->data, M_HAMMER2, sizeof(copy->data->voldata));
	copy->data = NULL;
	hammer2_chain_drop(copy);
}

/*
 * Returns non-zero if the chain (INODE or DIRENT) matches the filename.
 */
int
hammer2_chain_dirent_test(const hammer2_chain_t *chain, const char *name,
    size_t name_len)
{
	const hammer2_inode_data_t *ripdata;

	if (chain->bref.type == HAMMER2_BREF_TYPE_INODE) {
		ripdata = &chain->data->ipdata;
		if (ripdata->meta.name_len == name_len &&
		    bcmp(ripdata->filename, name, name_len) == 0)
			return (1);
	}
	if (chain->bref.type == HAMMER2_BREF_TYPE_DIRENT &&
	    chain->bref.embed.dirent.namlen == name_len) {
		if (name_len > sizeof(chain->bref.check.buf) &&
		    bcmp(chain->data->buf, name, name_len) == 0)
			return (1);
		if (name_len <= sizeof(chain->bref.check.buf) &&
		    bcmp(chain->bref.check.buf, name, name_len) == 0)
			return (1);
	}

	return (0);
}

void
hammer2_dump_chain(hammer2_chain_t *chain, int tab, int bi, int depth, char pfx)
{
	hammer2_chain_t *scan;
	int i;

	KKASSERT(depth == -1 || depth >= 0);
	if (depth != -1 && depth-- == 0)
		return;

	printf("%*.*s%c-chain %s.%-3d %016llx %016llx/%d mir %016llx mod "
	    "%016llx\n",
	    tab, tab, "", pfx,
	    hammer2_breftype_to_str(chain->bref.type), bi,
	    (long long)chain->bref.data_off,
	    (long long)chain->bref.key, chain->bref.keybits,
	    (long long)chain->bref.mirror_tid,
	    (long long)chain->bref.modify_tid);

	printf("%*.*s      (%s) flags %08x refs %d error %08x",
	    tab, tab, "",
	    (chain->bref.type == HAMMER2_BREF_TYPE_INODE && chain->data) ?
	    (char *)chain->data->ipdata.filename : "?",
	    chain->flags, chain->refs, chain->error);

	if (!RB_EMPTY(&chain->core.rbtree)) {
		printf(" {\n");
		i = 0;
		RB_FOREACH(scan, hammer2_chain_tree, &chain->core.rbtree) {
			hammer2_dump_chain(scan, tab + 4, i, depth, 'a');
			i++;
		}
		if (chain->bref.type == HAMMER2_BREF_TYPE_INODE && chain->data)
			printf("%*.*s}(%s)\n", tab, tab, "",
			    chain->data->ipdata.filename);
		else
			printf("%*.*s}\n", tab, tab, "");
	} else {
		printf("\n");
	}
}

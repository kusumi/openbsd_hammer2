/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2013-2023 The DragonFly Project.  All rights reserved.
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

#define HAMMER2_DOP_READ	1
#define HAMMER2_DOP_NEW		2
#define HAMMER2_DOP_NEWNZ	3
#define HAMMER2_DOP_READQ	4

/*
 * Implements an abstraction layer for buffered device I/O.
 * Can be used as an OS-abstraction but the main purpose is to allow larger
 * buffers to be used against hammer2_chain's using smaller allocations,
 * without causing deadlocks.
 */
static hammer2_io_t *hammer2_io_hash_lookup(hammer2_dev_t *, hammer2_off_t,
    uint64_t *);
static hammer2_io_t *hammer2_io_hash_enter(hammer2_dev_t *, hammer2_io_t *,
    uint64_t *);
static void hammer2_io_hash_cleanup(hammer2_dev_t *, int);

static __inline void
hammer2_assert_io_refs(hammer2_io_t *dio)
{
	KKASSERT(dio);
	hammer2_mtx_assert_ex(&dio->lock);
	KKASSERT((dio->refs & HAMMER2_DIO_MASK) != 0);
}

void
hammer2_io_hash_init(hammer2_dev_t *hmp)
{
	hammer2_io_hash_t *hash;
	int i;

	for (i = 0; i < HAMMER2_IOHASH_SIZE; ++i) {
		hash = &hmp->iohash[i];
		hammer2_spin_init(&hash->spin, "h2io_hasp");
	}
}

void
hammer2_io_hash_destroy(hammer2_dev_t *hmp)
{
	hammer2_io_hash_t *hash;
	int i;

	for (i = 0; i < HAMMER2_IOHASH_SIZE; ++i) {
		hash = &hmp->iohash[i];
		hammer2_spin_destroy(&hash->spin);
	}
}

/*
 * Returns the locked DIO corresponding to the data|radix offset.
 */
static hammer2_io_t *
hammer2_io_alloc(hammer2_dev_t *hmp, hammer2_off_t data_off, uint8_t btype,
    int createit)
{
	hammer2_volume_t *vol;
	hammer2_io_t *dio, *xio;
	hammer2_off_t lbase, pbase, pmask;
	int lsize, psize;

	hammer2_mtx_assert_ex(&hmp->iohash_lock);

	psize = HAMMER2_PBUFSIZE;
	pmask = ~(hammer2_off_t)(psize - 1);
	if ((int)(data_off & HAMMER2_OFF_MASK_RADIX))
		lsize = 1 << (int)(data_off & HAMMER2_OFF_MASK_RADIX);
	else
		lsize = 0;
	lbase = data_off & ~HAMMER2_OFF_MASK_RADIX;
	pbase = lbase & pmask;

	if (pbase == 0 || ((lbase + lsize - 1) & pmask) != pbase)
		hpanic("illegal base: %016llx %016llx+%08x / %016llx",
		    (long long)pbase, (long long)lbase, lsize,
		    (long long)pmask);

	/* Access or allocate dio, bump dio->refs to prevent destruction. */
	dio = hammer2_io_hash_lookup(hmp, pbase, NULL);
	if (dio) {
		/* NOP */
	} else if (createit) {
		vol = hammer2_get_volume(hmp, pbase);
		dio = hmalloc(sizeof(*dio), M_HAMMER2, M_WAITOK | M_ZERO);
		dio->hmp = hmp;
		dio->devvp = vol->dev->devvp;
		dio->dbase = vol->offset;
		KKASSERT((dio->dbase & HAMMER2_FREEMAP_LEVEL1_MASK) == 0);
		dio->pbase = pbase;
		dio->psize = psize;
		dio->btype = btype;
		dio->refs = 1;
		dio->act = 5;
		hammer2_mtx_init(&dio->lock, "h2io_inplk");
		hammer2_mtx_ex(&dio->lock);
		xio = hammer2_io_hash_enter(hmp, dio, NULL);
		if (xio == NULL) {
			atomic_add_int(&hammer2_count_dio_allocated, 1);
		} else {
			hammer2_mtx_unlock(&dio->lock);
			hammer2_mtx_destroy(&dio->lock);
			hfree(dio, M_HAMMER2, sizeof(*dio));
			dio = xio;
			hammer2_mtx_ex(&dio->lock);
		}
	} else {
		return (NULL);
	}

	dio->ticks = getticks();
	if (dio->act < 10)
		++dio->act;

	hammer2_assert_io_refs(dio);

	return (dio);
}

static int
hammer2_bread(hammer2_dev_t *hmp, hammer2_io_t *dio, daddr_t lblkno)
{
	int error;

	error = bread(dio->devvp, lblkno, dio->psize, &dio->bp);
	if (error)
		brelse(dio->bp);
	else
		hammer2_inc_iostat(&hmp->iostat_read, dio->btype, dio->psize);

	return (error);
}

/*
 * Acquire the requested dio.
 * If DIO_GOOD is set the buffer already exists and is good to go.
 */
hammer2_io_t *
hammer2_io_getblk(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase, int lsize,
    int op)
{
	hammer2_io_t *dio;
	daddr_t lblkno;
	int error;

	KKASSERT((1 << (int)(lbase & HAMMER2_OFF_MASK_RADIX)) == lsize);

	hammer2_mtx_ex(&hmp->iohash_lock);
	if (op == HAMMER2_DOP_READQ) {
		dio = hammer2_io_alloc(hmp, lbase, btype, 0);
		if (dio == NULL)
			return (NULL);
		op = HAMMER2_DOP_READ;
	} else {
		dio = hammer2_io_alloc(hmp, lbase, btype, 1);
	}
	KKASSERT(dio);
	hammer2_assert_io_refs(dio); /* dio locked + refs > 0 */
	hammer2_mtx_unlock(&hmp->iohash_lock);

	/* Buffer is already GOOD, handle the op and return. */
	if (dio->refs & HAMMER2_DIO_GOOD) {
		switch (op) {
		case HAMMER2_DOP_NEW:
			bzero(hammer2_io_data(dio, lbase), lsize);
			/* fall through */
		case HAMMER2_DOP_NEWNZ:
			dio->refs |= HAMMER2_DIO_DIRTY;
			break;
		default:
			break;
		}
		hammer2_mtx_unlock(&dio->lock);
		return (dio);
	}

	/* GOOD is not set. */
	KKASSERT(dio->bp == NULL);

	error = 0;
	lblkno = (dio->pbase - dio->dbase) / DEV_BSIZE;

	if (dio->pbase == (lbase & ~HAMMER2_OFF_MASK_RADIX) &&
	    dio->psize == lsize) {
		switch (op) {
		case HAMMER2_DOP_NEW:
		case HAMMER2_DOP_NEWNZ:
			dio->bp = getblk(dio->devvp, lblkno, dio->psize, 0, 0);
			if (op == HAMMER2_DOP_NEW)
				bzero(dio->bp->b_data, dio->psize);
			dio->refs |= HAMMER2_DIO_DIRTY;
			break;
		default:
			error = hammer2_bread(hmp, dio, lblkno);
			break;
		}
	} else {
		error = hammer2_bread(hmp, dio, lblkno);
		if (dio->bp) {
			KKASSERT(error == 0);
			switch (op) {
			case HAMMER2_DOP_NEW:
				bzero(hammer2_io_data(dio, lbase), lsize);
				/* fall through */
			case HAMMER2_DOP_NEWNZ:
				dio->refs |= HAMMER2_DIO_DIRTY;
				break;
			default:
				break;
			}
		}
	}
	//KKASSERT(error == 0 || dio->bp == NULL);

	/* XXX
	if (dio->bp)
		BUF_KERNPROC(dio->bp);
	*/

	dio->error = error;
	if (error == 0)
		dio->refs |= HAMMER2_DIO_GOOD;

	hammer2_mtx_unlock(&dio->lock);

	/* XXX error handling */

	return (dio);
}

/*
 * Release our ref on *diop.
 * On the 1->0 transition we clear DIO_GOOD and dispose of dio->bp.
 */
void
hammer2_io_putblk(hammer2_io_t **diop)
{
	hammer2_dev_t *hmp;
	hammer2_io_t *dio;
	struct buf *bp;
	uint64_t orefs;
	int dio_limit;

	dio = *diop;
	*diop = NULL;

	hammer2_mtx_ex(&dio->lock);
	if ((dio->refs & HAMMER2_DIO_MASK) == 0) {
		hammer2_mtx_unlock(&dio->lock);
		return; /* lost race */
	}
	hammer2_assert_io_refs(dio);

	/*
	 * Drop refs.
	 * On the 1->0 transition clear DIO_GOOD.
	 * On any other transition we can return early.
	 */
	orefs = dio->refs;
	if ((dio->refs & HAMMER2_DIO_MASK) == 1) {
		dio->refs--;
		dio->refs &= ~(HAMMER2_DIO_GOOD | HAMMER2_DIO_DIRTY);
	} else {
		dio->refs--;
		hammer2_mtx_unlock(&dio->lock);
		return;
	}

	/* Lastdrop (1->0 transition) case. */
	hmp = dio->hmp;
	bp = dio->bp;
	dio->bp = NULL;

	/* Write out and dispose of buffer. */
	if ((orefs & HAMMER2_DIO_GOOD) && bp) {
		/* Non-errored disposal of buffer. */
		if (orefs & HAMMER2_DIO_DIRTY) {
			/*
			 * Allows dirty buffers to accumulate and
			 * possibly be canceled (e.g. by a 'rm'),
			 * by default we will burst-write later.
			 *
			 * We generally do NOT want to issue an actual
			 * b[a]write() or cluster_write() here.  Due to
			 * the way chains are locked, buffers may be cycled
			 * in and out quite often and disposal here can cause
			 * multiple writes or write-read stalls.
			 *
			 * If FLUSH is set we do want to issue the actual
			 * write.  This typically occurs in the write-behind
			 * case when writing to large files.
			 */
			/* No cluster_write() in OpenBSD. */
			if (dio->refs & HAMMER2_DIO_FLUSH)
				bawrite(bp);
			else
				bdwrite(bp);
			hammer2_inc_iostat(&hmp->iostat_write, dio->btype,
			    dio->psize);
		} else {
			bqrelse(bp);
		}
	} else if (bp) {
		/* Errored disposal of buffer. */
		brelse(bp);
	}

	/* Update iofree_count before disposing of the dio. */
	atomic_add_int(&hmp->iofree_count, 1);

	KKASSERT(!(dio->refs & HAMMER2_DIO_GOOD));
	hammer2_mtx_unlock(&dio->lock);
	/* Another process may come in and get/put this dio. */

	/*
	 * We cache free buffers so re-use cases can use a shared lock,
	 * but if too many build up we have to clean them out.
	 */
	hammer2_mtx_ex(&hmp->iohash_lock);
	dio_limit = hammer2_dio_limit;
	if (dio_limit < 256)
		dio_limit = 256;
	if (dio_limit > 1024*1024)
		dio_limit = 1024*1024;
	if (hmp->iofree_count > dio_limit)
		hammer2_io_hash_cleanup(hmp, dio_limit);
	hammer2_mtx_unlock(&hmp->iohash_lock);
}

char *
hammer2_io_data(hammer2_io_t *dio, hammer2_off_t lbase)
{
	struct buf *bp;
	off_t b_offset;
	int off;

	bp = dio->bp;
	KASSERTMSG(bp != NULL, "NULL dio buf");

	lbase -= dio->dbase;
	b_offset = (off_t)bp->b_lblkno * DEV_BSIZE;
	off = (lbase & ~HAMMER2_OFF_MASK_RADIX) - b_offset;
	KASSERTMSG(off >= 0 && off < bp->b_bufsize, "bad offset");

	return (bp->b_data + off);
}

int
hammer2_io_new(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase, int lsize,
    hammer2_io_t **diop)
{
	*diop = hammer2_io_getblk(hmp, btype, lbase, lsize, HAMMER2_DOP_NEW);
	return ((*diop)->error);
}

int
hammer2_io_newnz(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase, int lsize,
    hammer2_io_t **diop)
{
	*diop = hammer2_io_getblk(hmp, btype, lbase, lsize, HAMMER2_DOP_NEWNZ);
	return ((*diop)->error);
}

int
hammer2_io_bread(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase, int lsize,
    hammer2_io_t **diop)
{
	*diop = hammer2_io_getblk(hmp, btype, lbase, lsize, HAMMER2_DOP_READ);
	return ((*diop)->error);
}

hammer2_io_t *
hammer2_io_getquick(hammer2_dev_t *hmp, off_t lbase, int lsize)
{
	return (hammer2_io_getblk(hmp, 0, lbase, lsize, HAMMER2_DOP_READQ));
}

void
hammer2_io_bawrite(hammer2_io_t **diop)
{
	atomic_set_32(&(*diop)->refs, HAMMER2_DIO_DIRTY | HAMMER2_DIO_FLUSH);
	hammer2_io_putblk(diop);
}

void
hammer2_io_bdwrite(hammer2_io_t **diop)
{
	atomic_set_32(&(*diop)->refs, HAMMER2_DIO_DIRTY);
	hammer2_io_putblk(diop);
}

int
hammer2_io_bwrite(hammer2_io_t **diop)
{
	atomic_set_32(&(*diop)->refs, HAMMER2_DIO_DIRTY | HAMMER2_DIO_FLUSH);
	hammer2_io_putblk(diop);

	return (0); /* XXX */
}

void
hammer2_io_setdirty(hammer2_io_t *dio)
{
	atomic_set_32(&dio->refs, HAMMER2_DIO_DIRTY);
}

void
hammer2_io_brelse(hammer2_io_t **diop)
{
	hammer2_io_putblk(diop);
}

void
hammer2_io_bqrelse(hammer2_io_t **diop)
{
	hammer2_io_putblk(diop);
}

static __inline hammer2_io_hash_t *
hammer2_io_hashv(hammer2_dev_t *hmp, hammer2_off_t pbase)
{
	int hv;

	hv = (int)pbase + (int)(pbase >> 16);
	return (&hmp->iohash[hv & HAMMER2_IOHASH_MASK]);
}

/*
 * Lookup and reference the requested dio.
 */
static hammer2_io_t *
hammer2_io_hash_lookup(hammer2_dev_t *hmp, hammer2_off_t pbase, uint64_t *refsp)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *dio;
	uint64_t refs;

	hammer2_mtx_assert_ex(&hmp->iohash_lock);

	if (refsp)
		*refsp = 0;

	hash = hammer2_io_hashv(hmp, pbase);
	//hammer2_spin_sh(&hash->spin);
	for (dio = hash->base; dio; dio = dio->next) {
		if (dio->pbase == pbase) {
			hammer2_mtx_ex(&dio->lock);
			refs = dio->refs++;
			if ((refs & HAMMER2_DIO_MASK) == 0)
				atomic_add_int(&dio->hmp->iofree_count, -1);
			if (refsp)
				*refsp = refs;
			break;
		}
	}
	//hammer2_spin_unsh(&hash->spin);

	if (dio)
		hammer2_assert_io_refs(dio);
	return (dio);
}

/*
 * Enter a dio into the hash.  If the pbase already exists in the hash,
 * the xio in the hash is referenced and returned.  If dio is sucessfully
 * entered into the hash, NULL is returned.
 */
static hammer2_io_t *
hammer2_io_hash_enter(hammer2_dev_t *hmp, hammer2_io_t *dio, uint64_t *refsp)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *xio, **xiop;
	uint64_t refs;

	hammer2_mtx_assert_ex(&hmp->iohash_lock);
	hammer2_assert_io_refs(dio);

	if (refsp)
		*refsp = 0;

	hash = hammer2_io_hashv(hmp, dio->pbase);
	//hammer2_spin_ex(&hash->spin);
	for (xiop = &hash->base; (xio = *xiop) != NULL; xiop = &xio->next) {
		if (xio->pbase == dio->pbase) {
			refs = xio->refs++;
			if ((refs & HAMMER2_DIO_MASK) == 0)
				atomic_add_int(&xio->hmp->iofree_count, -1);
			if (refsp)
				*refsp = refs;
			goto done;
		}
	}
	dio->next = NULL;
	*xiop = dio;
done:
	//hammer2_spin_unex(&hash->spin);

	return (xio);
}

/*
 * Clean out a limited number of freeable DIOs.
 */
static void
hammer2_io_hash_cleanup(hammer2_dev_t *hmp, int dio_limit)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *dio, **diop, *cleanbase, **cleanapp;
	int count, maxscan, act, i;

	hammer2_mtx_assert_ex(&hmp->iohash_lock);

	count = hmp->iofree_count - dio_limit + 32;
	if (count <= 0)
		return;

	cleanbase = NULL;
	cleanapp = &cleanbase;
	i = hmp->io_iterator++;
	maxscan = HAMMER2_IOHASH_SIZE;

	while (count > 0 && maxscan--) {
		hash = &hmp->iohash[i & HAMMER2_IOHASH_MASK];
		//hammer2_spin_ex(&hash->spin);
		diop = &hash->base;
		while ((dio = *diop) != NULL) {
			if ((dio->refs & HAMMER2_DIO_MASK) != 0) {
				diop = &dio->next;
				continue;
			}
			if (dio->act > 0) {
				act = dio->act - (getticks() - dio->ticks) / hz - 1;
				dio->act = (act < 0) ? 0 : act;
			}
			if (dio->act) {
				diop = &dio->next;
				continue;
			}
			KKASSERT(dio->bp == NULL);
			*diop = dio->next;
			dio->next = NULL;
			*cleanapp = dio;
			cleanapp = &dio->next;
			--count;
			/* diop remains unchanged */
			atomic_add_int(&hammer2_count_dio_allocated, -1);
			atomic_add_int(&hmp->iofree_count, -1);
		}
		//hammer2_spin_unex(&hash->spin);
		i = hmp->io_iterator++;
	}

	/* Get rid of dios on clean list without holding any locks. */
	while ((dio = cleanbase) != NULL) {
		cleanbase = dio->next;
		dio->next = NULL;
		KKASSERT(dio->bp == NULL &&
		    (dio->refs & HAMMER2_DIO_MASK) == 0);
		if (dio->refs & HAMMER2_DIO_DIRTY)
			hprintf("dirty buffer %016llx/%d\n",
			    (long long)dio->pbase, dio->psize);
		hammer2_mtx_destroy(&dio->lock);
		hfree(dio, M_HAMMER2, sizeof(*dio));
	}
}

/*
 * Destroy all DIOs associated with the media.
 */
void
hammer2_io_hash_cleanup_all(hammer2_dev_t *hmp)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *dio;
	int i;

	hammer2_mtx_assert_ex(&hmp->iohash_lock);

	for (i = 0; i < HAMMER2_IOHASH_SIZE; ++i) {
		hash = &hmp->iohash[i];
		while ((dio = hash->base) != NULL) {
			hash->base = dio->next;
			dio->next = NULL;
			KKASSERT(dio->bp == NULL &&
			    (dio->refs & HAMMER2_DIO_MASK) == 0);
			if (dio->refs & HAMMER2_DIO_DIRTY)
				hprintf("dirty buffer %016llx/%d\n",
				    (long long)dio->pbase, dio->psize);
			hammer2_mtx_destroy(&dio->lock);
			hfree(dio, M_HAMMER2, sizeof(*dio));
			atomic_add_int(&hammer2_count_dio_allocated, -1);
			atomic_add_int(&hmp->iofree_count, -1);
		}
	}
}

#define HAMMER2_DEDUP_FRAG	(HAMMER2_PBUFSIZE / 64)
#define HAMMER2_DEDUP_FRAGRADIX	(HAMMER2_PBUFRADIX - 6)

uint64_t
hammer2_dedup_mask(hammer2_io_t *dio, hammer2_off_t data_off, u_int bytes)
{
	int bbeg, bits;
	uint64_t mask;

	bbeg = (int)((data_off & ~HAMMER2_OFF_MASK_RADIX) - dio->pbase) >>
	    HAMMER2_DEDUP_FRAGRADIX;
	bits = (int)((bytes + (HAMMER2_DEDUP_FRAG - 1)) >>
	    HAMMER2_DEDUP_FRAGRADIX);

	if (bbeg + bits == 64)
		mask = (uint64_t)-1;
	else
		mask = ((uint64_t)1 << (bbeg + bits)) - 1;
	mask &= ~(((uint64_t)1 << bbeg) - 1);

	return (mask);
}

/*
 * Set dedup validation bits in a DIO.  We do not need the buffer cache
 * buffer for this.  This must be done concurrent with setting bits in
 * the freemap so as to interlock with bulkfree's clearing of those bits.
 */
void
hammer2_io_dedup_set(hammer2_dev_t *hmp, hammer2_blockref_t *bref)
{
	hammer2_io_t *dio;
	uint64_t mask;
	int lsize;

	hammer2_mtx_ex(&hmp->iohash_lock);
	dio = hammer2_io_alloc(hmp, bref->data_off, bref->type, 1);
	KKASSERT(dio);
	hammer2_assert_io_refs(dio); /* dio locked + refs > 0 */
	hammer2_mtx_unlock(&hmp->iohash_lock);

	if ((int)(bref->data_off & HAMMER2_OFF_MASK_RADIX))
		lsize = 1 << (int)(bref->data_off & HAMMER2_OFF_MASK_RADIX);
	else
		lsize = 0;

	mask = hammer2_dedup_mask(dio, bref->data_off, lsize);
	dio->dedup_valid &= ~mask;
	dio->dedup_alloc |= mask;

	hammer2_mtx_unlock(&dio->lock);
	hammer2_io_putblk(&dio);
}

/*
 * Clear dedup validation bits in a DIO.  This is typically done when
 * a modified chain is destroyed or by the bulkfree code.  No buffer
 * is needed for this operation.  If the DIO no longer exists it is
 * equivalent to the bits not being set.
 */
void
hammer2_io_dedup_delete(hammer2_dev_t *hmp, uint8_t btype,
    hammer2_off_t data_off, unsigned int bytes)
{
	hammer2_io_t *dio;
	uint64_t mask;

	if ((data_off & ~HAMMER2_OFF_MASK_RADIX) == 0)
		return;
	if (btype != HAMMER2_BREF_TYPE_DATA)
		return;

	hammer2_mtx_ex(&hmp->iohash_lock);
	dio = hammer2_io_alloc(hmp, data_off, btype, 0);
	if (dio) {
		hammer2_assert_io_refs(dio); /* dio locked + refs > 0 */
		hammer2_mtx_unlock(&hmp->iohash_lock);

		if (data_off < (hammer2_off_t)dio->pbase ||
		    (data_off & ~HAMMER2_OFF_MASK_RADIX) +
		    (hammer2_off_t)bytes >
		    (hammer2_off_t)dio->pbase + dio->psize)
			hpanic("bad data_off %016llx/%d %016llx",
			    (long long)data_off, bytes, (long long)dio->pbase);

		mask = hammer2_dedup_mask(dio, data_off, bytes);
		dio->dedup_alloc &= ~mask;
		dio->dedup_valid &= ~mask;

		hammer2_mtx_unlock(&dio->lock);
		hammer2_io_putblk(&dio);
	} else {
		hammer2_mtx_unlock(&hmp->iohash_lock);
	}
}

/*
 * Assert that dedup allocation bits in a DIO are not set.  This operation
 * does not require a buffer.  The DIO does not need to exist.
 */
void
hammer2_io_dedup_assert(hammer2_dev_t *hmp, hammer2_off_t data_off,
    unsigned int bytes)
{
	hammer2_io_t *dio;

	hammer2_mtx_ex(&hmp->iohash_lock);
	dio = hammer2_io_alloc(hmp, data_off, HAMMER2_BREF_TYPE_DATA, 0);
	if (dio) {
		hammer2_assert_io_refs(dio); /* dio locked + refs > 0 */
		hammer2_mtx_unlock(&hmp->iohash_lock);

		KASSERTMSG((dio->dedup_alloc &
		    hammer2_dedup_mask(dio, data_off, bytes)) == 0,
		    "%016llx/%d %016llx/%016llx",
		    (long long)data_off, bytes,
		    (long long)hammer2_dedup_mask(dio, data_off, bytes),
		    (long long)dio->dedup_alloc);

		hammer2_mtx_unlock(&dio->lock);
		hammer2_io_putblk(&dio);
	} else {
		hammer2_mtx_unlock(&hmp->iohash_lock);
	}
}

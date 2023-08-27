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
#include "hammer2_lz4.h"
#include "hammer2_xxhash.h"

#include <lib/libz/zlib.h>

static int hammer2_strategy_read(struct vop_strategy_args *);
static void hammer2_strategy_read_completion(hammer2_chain_t *,
    const char *, struct buf *);

int
hammer2_strategy(void *v)
{
	struct vop_strategy_args /* {
		struct vnode *a_vp;
		struct buf *a_bp;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct buf *bp = ap->a_bp;
	int s;

	if (vp->v_type == VBLK || vp->v_type == VCHR)
		hpanic("spec %d", vp->v_type);

	/*
	 * OpenBSD filesystems set bp->b_dev to devvp->v_rdev before
	 * VOP_STRATEGY(devvp), but that's not the case here with HAMMER2.
	 */
	if (bp->b_flags & B_READ) {
		hammer2_strategy_read(ap);
	} else {
		bp->b_error = EOPNOTSUPP;
		bp->b_flags |= B_ERROR;
		s = splbio();
		biodone(bp);
		splx(s);
		return (bp->b_error);
	}

	return (0);
}

/*
 * Callback used in read path in case that a block is compressed with LZ4.
 */
static void
hammer2_decompress_LZ4_callback(const char *data, unsigned int bytes,
    struct buf *bp)
{
	char *compressed_buffer;
	int compressed_size;
	int result;

	KKASSERT(bp->b_bufsize <= HAMMER2_PBUFSIZE);
	compressed_size = *(const int *)data;
	KKASSERT((uint32_t)compressed_size <= bytes - sizeof(int));

	compressed_buffer = malloc(HAMMER2_PBUFSIZE, M_HAMMER2_RBUF,
	    M_WAITOK | M_ZERO);
	result = LZ4_decompress_safe(__DECONST(char *, &data[sizeof(int)]),
	    compressed_buffer, compressed_size, bp->b_bufsize);
	if (result < 0) {
		hprintf("error during decompression: buf %016jx/%016jx/%d\n",
		    (intmax_t)bp->b_lblkno, (intmax_t)bp->b_blkno, bytes);
		/* Make sure it isn't random garbage. */
		bzero(compressed_buffer, bp->b_bufsize);
	}

	KKASSERT(result <= bp->b_bufsize);
	bcopy(compressed_buffer, bp->b_data, bp->b_bufsize);
	if (result < bp->b_bufsize)
		bzero(bp->b_data + result, bp->b_bufsize - result);
	free(compressed_buffer, M_HAMMER2_RBUF, 0);
	bp->b_resid = 0;
}

/*
 * Callback used in read path in case that a block is compressed with ZLIB.
 */
static void
hammer2_decompress_ZLIB_callback(const char *data, unsigned int bytes,
    struct buf *bp)
{
	char *compressed_buffer;
	z_stream strm_decompress;
	int result;

	KKASSERT(bp->b_bufsize <= HAMMER2_PBUFSIZE);
	strm_decompress.avail_in = 0;
	strm_decompress.next_in = Z_NULL;

	result = inflateInit(&strm_decompress);
	if (result != Z_OK)
		hprintf("fatal error in inflateInit\n");

	compressed_buffer = malloc(HAMMER2_PBUFSIZE, M_HAMMER2_RBUF,
	    M_WAITOK | M_ZERO);
	strm_decompress.next_in = __DECONST(char *, data);

	/* XXX Supply proper size, subset of device bp. */
	strm_decompress.avail_in = bytes;
	strm_decompress.next_out = compressed_buffer;
	strm_decompress.avail_out = bp->b_bufsize;

	result = inflate(&strm_decompress, Z_FINISH);
	if (result != Z_STREAM_END) {
		hprintf("fatal error during decompression\n");
		bzero(compressed_buffer, bp->b_bufsize);
	}
	bcopy(compressed_buffer, bp->b_data, bp->b_bufsize);
	result = bp->b_bufsize - strm_decompress.avail_out;
	if (result < bp->b_bufsize)
		bzero(bp->b_data + result, strm_decompress.avail_out);
	free(compressed_buffer, M_HAMMER2_RBUF, 0);
	inflateEnd(&strm_decompress);

	bp->b_resid = 0;
}

/*
 * Logical buffer I/O.
 */
static int
hammer2_strategy_read(struct vop_strategy_args *ap)
{
	hammer2_xop_strategy_t *xop;
	hammer2_inode_t *ip = VTOI(ap->a_vp);
	struct buf *bp = ap->a_bp;
	hammer2_key_t lbase;

	lbase = (hammer2_key_t)bp->b_lblkno * hammer2_get_logical();
	KKASSERT(((int)lbase & HAMMER2_PBUFMASK) == 0);

	xop = hammer2_xop_alloc(ip, HAMMER2_XOP_STRATEGY);
	xop->bp = bp;
	xop->lbase = lbase;
	hammer2_xop_start(&xop->head, &hammer2_strategy_read_desc);

	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (0);
}

/*
 * Backend for hammer2_strategy_read().
 * Do a synchronous lookup of the chain and its data.
 */
void
hammer2_xop_strategy_read(hammer2_xop_t *arg, int clindex)
{
	hammer2_xop_strategy_t *xop = &arg->xop_strategy;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t lbase, key_dummy;
	struct buf *bp;
	const char *data;
	int s, error;

	lbase = xop->lbase;

	parent = hammer2_inode_chain(xop->head.ip1, clindex,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	if (parent) {
		chain = hammer2_chain_lookup(&parent, &key_dummy, lbase, lbase,
		    &error, HAMMER2_LOOKUP_ALWAYS | HAMMER2_LOOKUP_SHARED);
		if (chain)
			error = chain->error;
	} else {
		error = HAMMER2_ERROR_EIO;
		chain = NULL;
	}
	error = hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}

	bp = xop->bp;
	error = hammer2_xop_collect(&xop->head, HAMMER2_XOP_COLLECT_NOWAIT);
	switch (error) {
	case 0:
		data = hammer2_xop_gdata(&xop->head)->buf;
		hammer2_strategy_read_completion(xop->head.cluster.focus, data,
		    xop->bp);
		hammer2_xop_pdata(&xop->head);
		s = splbio();
		biodone(bp);
		splx(s);
		break;
	case HAMMER2_ERROR_ENOENT:
		bp->b_resid = 0;
		bp->b_error = 0;
		bzero(bp->b_data, bp->b_bcount);
		s = splbio();
		biodone(bp);
		splx(s);
		break;
	default:
		hprintf("error %08x at blkno %016jx/%016jx\n",
		    error, (intmax_t)bp->b_lblkno, (intmax_t)bp->b_blkno);
		bp->b_error = EIO;
		bp->b_flags |= B_ERROR;
		s = splbio();
		biodone(bp);
		splx(s);
		break;
	}
}

static void
hammer2_strategy_read_completion(hammer2_chain_t *focus, const char *data,
    struct buf *bp)
{
	if (focus->bref.type == HAMMER2_BREF_TYPE_INODE) {
		/* Copy from in-memory inode structure. */
		bcopy(((const hammer2_inode_data_t *)data)->u.data, bp->b_data,
		    HAMMER2_EMBEDDED_BYTES);
		bzero(bp->b_data + HAMMER2_EMBEDDED_BYTES,
		    bp->b_bcount - HAMMER2_EMBEDDED_BYTES);
		bp->b_resid = 0;
		bp->b_error = 0;
	} else if (focus->bref.type == HAMMER2_BREF_TYPE_DATA) {
		/*
		 * Data is on-media, record for live dedup.  Release the
		 * chain (try to free it) when done.  The data is still
		 * cached by both the buffer cache in front and the
		 * block device behind us.  This leaves more room in the
		 * LRU chain cache for meta-data chains which we really
		 * want to retain.
		 *
		 * NOTE: Deduplication cannot be safely recorded for
		 *	 records without a check code.
		 */
		hammer2_dedup_record(focus, NULL, data);
		atomic_set_int(&focus->flags, HAMMER2_CHAIN_RELEASE);

		/* Decompression and copy. */
		switch (HAMMER2_DEC_COMP(focus->bref.methods)) {
		case HAMMER2_COMP_LZ4:
			hammer2_decompress_LZ4_callback(data, focus->bytes, bp);
			/* b_resid set by call */
			break;
		case HAMMER2_COMP_ZLIB:
			hammer2_decompress_ZLIB_callback(data, focus->bytes, bp);
			/* b_resid set by call */
			break;
		case HAMMER2_COMP_NONE:
			KKASSERT(focus->bytes <= (unsigned int)bp->b_bcount);
			bcopy(data, bp->b_data, focus->bytes);
			if (focus->bytes < (unsigned int)bp->b_bcount)
				bzero(bp->b_data + focus->bytes,
				    bp->b_bcount - focus->bytes);
			bp->b_resid = 0;
			bp->b_error = 0;
			break;
		default:
			hpanic("bad comp type %02x", focus->bref.methods);
		}
	} else {
		hpanic("bad blockref type %d", focus->bref.type);
	}
}

/*
 * Wait for pending I/O to complete.
 */
void
hammer2_bioq_sync(hammer2_pfs_t *pmp)
{
}

/*
 * LIVE DEDUP HEURISTICS
 *
 * Record media and crc information for possible dedup operation.  Note
 * that the dedup mask bits must also be set in the related DIO for a dedup
 * to be fully validated (which is handled in the freemap allocation code).
 *
 * WARNING! This code is SMP safe but the heuristic allows SMP collisions.
 *	    All fields must be loaded into locals and validated.
 *
 * WARNING! Should only be used for file data and directory entries,
 *	    hammer2_chain_modify() only checks for the dedup case on data
 *	    chains.  Also, dedup data can only be recorded for committed
 *	    chains (so NOT strategy writes which can undergo further
 *	    modification after the fact!).
 */
void
hammer2_dedup_record(hammer2_chain_t *chain, hammer2_io_t *dio,
    const char *data)
{
	hammer2_dev_t *hmp = chain->hmp;
	hammer2_dedup_t *dedup;
	uint64_t crc, mask;
	int i, dticks, best = 0;

	/*
	 * We can only record a dedup if we have media data to test against.
	 * If dedup is not enabled, return early, which allows a chain to
	 * remain marked MODIFIED (which might have benefits in special
	 * situations, though typically it does not).
	 */
	if (1 /* || hammer2_dedup_enable == 0 */)
		return;
	KKASSERT(0);

	if (dio == NULL) {
		dio = chain->dio;
		if (dio == NULL)
			return;
	}

	switch (HAMMER2_DEC_CHECK(chain->bref.methods)) {
	case HAMMER2_CHECK_ISCSI32:
		/*
		 * XXX use the built-in crc (the dedup lookup sequencing
		 * needs to be fixed so the check code is already present
		 * when dedup_lookup is called)
		 */
		crc = XXH64(data, chain->bytes, XXH_HAMMER2_SEED);
		break;
	case HAMMER2_CHECK_XXHASH64:
		crc = chain->bref.check.xxhash64.value;
		break;
	case HAMMER2_CHECK_SHA192:
		/*
		 * XXX use the built-in crc (the dedup lookup sequencing
		 * needs to be fixed so the check code is already present
		 * when dedup_lookup is called)
		 */
		crc = XXH64(data, chain->bytes, XXH_HAMMER2_SEED);
		break;
	default:
		/*
		 * Cannot dedup without a check code.
		 *
		 * NOTE: In particular, CHECK_NONE allows a sector to be
		 *	 overwritten without copy-on-write, recording
		 *	 a dedup block for a CHECK_NONE object would be
		 *	 a disaster!
		 */
		return;
	}

	atomic_set_int(&chain->flags, HAMMER2_CHAIN_DEDUPABLE);

	dedup = &hmp->heur_dedup[crc & (HAMMER2_DEDUP_HEUR_MASK & ~3)];
	for (i = 0; i < 4; ++i) {
		if (dedup[i].data_crc == crc) {
			best = i;
			break;
		}
		dticks = (int)(dedup[i].ticks - dedup[best].ticks);
		if (dticks < 0 || dticks > hz * 60 * 30)
			best = i;
	}

	dedup += best;
	//debug_hprintf("REC %04x %016jx %016jx\n",
	//    (int)(dedup - hmp->heur_dedup), crc, chain->bref.data_off);
	dedup->ticks = getticks();
	dedup->data_off = chain->bref.data_off;
	dedup->data_crc = crc;

	/*
	 * Set the valid bits for the dedup only after we know the data
	 * buffer has been updated.  The alloc bits were set (and the valid
	 * bits cleared) when the media was allocated.
	 *
	 * This is done in two stages becuase the bulkfree code can race
	 * the gap between allocation and data population.  Both masks must
	 * be set before a bcmp/dedup operation is able to use the block.
	 */
	mask = hammer2_dedup_mask(dio, chain->bref.data_off, chain->bytes);
	dio->dedup_valid |= mask;
}

/*
 * Poof.  Races are ok, if someone gets in and reuses a dedup offset
 * before or while we are clearing it they will also recover the freemap
 * entry (set it to fully allocated), so a bulkfree race can only set it
 * to a possibly-free state.
 *
 * XXX ok, well, not really sure races are ok but going to run with it
 *     for the moment.
 */
void
hammer2_dedup_clear(hammer2_dev_t *hmp)
{
	int i;

	for (i = 0; i < HAMMER2_DEDUP_HEUR_SIZE; ++i) {
		hmp->heur_dedup[i].data_off = 0;
		hmp->heur_dedup[i].ticks = getticks() - 1;
	}
}

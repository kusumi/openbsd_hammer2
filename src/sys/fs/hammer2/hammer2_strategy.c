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

/* Also see sys/sys/vnode.h. */
#define IO_ASYNC	0x10000000

/* Taken from sys/sys/buf.h in NetBSD. */
#define BUF_ISREAD(bp)	(((bp)->b_flags & B_READ) == B_READ)
#define BUF_ISWRITE(bp)	(((bp)->b_flags & B_READ) == B_WRITE)

static int hammer2_strategy_read(struct vop_strategy_args *);
static int hammer2_strategy_write(struct vop_strategy_args *);
static void hammer2_strategy_read_completion(hammer2_chain_t *, const char *,
    struct buf *);
static void hammer2_dedup_record(hammer2_chain_t *, hammer2_io_t *,
    const char *);
static hammer2_off_t hammer2_dedup_lookup(hammer2_dev_t *, char **, int);

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
	if (BUF_ISREAD(bp)) {
		hammer2_strategy_read(ap);
	} else if (BUF_ISWRITE(bp)) {
		hammer2_strategy_write(ap);
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

	compressed_buffer = hmalloc(HAMMER2_PBUFSIZE, M_HAMMER2_RBUF,
	    M_WAITOK | M_ZERO);
	result = LZ4_decompress_safe(__DECONST(char *, &data[sizeof(int)]),
	    compressed_buffer, compressed_size, bp->b_bufsize);
	if (result < 0) {
		hprintf("error during decompression: buf %016llx/%016llx/%d\n",
		    (long long)bp->b_lblkno, (long long)bp->b_blkno, bytes);
		/* Make sure it isn't random garbage. */
		bzero(compressed_buffer, bp->b_bufsize);
	}

	KKASSERT(result <= bp->b_bufsize);
	bcopy(compressed_buffer, bp->b_data, bp->b_bufsize);
	if (result < bp->b_bufsize)
		bzero(bp->b_data + result, bp->b_bufsize - result);
	hfree(compressed_buffer, M_HAMMER2_RBUF, HAMMER2_PBUFSIZE);
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
	bzero(&strm_decompress, sizeof(strm_decompress));
	strm_decompress.avail_in = 0;
	strm_decompress.next_in = Z_NULL;

	result = inflateInit(&strm_decompress);
	if (result != Z_OK)
		hprintf("fatal error in inflateInit\n");

	compressed_buffer = hmalloc(HAMMER2_PBUFSIZE, M_HAMMER2_RBUF,
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
	hfree(compressed_buffer, M_HAMMER2_RBUF, HAMMER2_PBUFSIZE);
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
hammer2_xop_strategy_read(hammer2_xop_t *arg, void *scratch, int clindex)
{
	hammer2_xop_strategy_t *xop = &arg->xop_strategy;
	hammer2_chain_t *chain, *parent;
	hammer2_key_t lbase = xop->lbase, key_dummy;
	struct buf *bp;
	const char *data;
	int s, error;

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
	hammer2_xop_feed(&xop->head, chain, clindex, error);
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	chain = NULL; /* safety */
	parent = NULL; /* safety */

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
		hprintf("error %08x at blkno %016llx/%016llx\n",
		    error, (long long)bp->b_lblkno, (long long)bp->b_blkno);
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
		 * block device behind us.
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
			break;
		}
	} else {
		hpanic("bad blockref type %d", focus->bref.type);
	}
}

static void hammer2_write_file_core(char *, hammer2_inode_t *,
    hammer2_chain_t **, hammer2_key_t, int, int, hammer2_tid_t, int *);
static void hammer2_compress_and_write(char *, hammer2_inode_t *,
    hammer2_chain_t **, hammer2_key_t, int, int, hammer2_tid_t, int *, int,
    int);
static void hammer2_zero_check_and_write(char *, hammer2_inode_t *,
    hammer2_chain_t **, hammer2_key_t, int, int, hammer2_tid_t, int *, int);
static int test_block_zeros(const char *, size_t);
static void zero_write(char *, hammer2_inode_t *, hammer2_chain_t **,
    hammer2_key_t, hammer2_tid_t, int *);
static void hammer2_write_bp(hammer2_chain_t *, char *, int, int, hammer2_tid_t,
    int *, int);

static int
hammer2_strategy_write(struct vop_strategy_args *ap)
{
	hammer2_xop_strategy_t *xop;
	hammer2_inode_t *ip = VTOI(ap->a_vp);
	hammer2_pfs_t *pmp = ip->pmp;
	struct buf *bp = ap->a_bp;
	hammer2_key_t lbase;

	lbase = (hammer2_key_t)bp->b_lblkno * hammer2_get_logical();
	KKASSERT(((int)lbase & HAMMER2_PBUFMASK) == 0);

	atomic_set_int(&ip->flags, HAMMER2_INODE_DIRTYDATA);
	hammer2_trans_assert_strategy(pmp);
	hammer2_trans_init(pmp, HAMMER2_TRANS_BUFCACHE);

	xop = hammer2_xop_alloc(ip,
	    HAMMER2_XOP_MODIFYING | HAMMER2_XOP_STRATEGY);
	xop->bp = bp;
	xop->lbase = lbase;
	hammer2_xop_start(&xop->head, &hammer2_strategy_write_desc);
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (0);
}

void
hammer2_xop_strategy_write(hammer2_xop_t *arg, void *scratch, int clindex)
{
	hammer2_xop_strategy_t *xop = &arg->xop_strategy;
	hammer2_chain_t *parent;
	hammer2_inode_t *ip = xop->head.ip1; /* retained by ref */
	hammer2_key_t lbase = xop->lbase;
	struct buf *bp = xop->bp;
	char *bio_data = scratch;
	int s, error, lblksize, pblksize;

	lblksize = hammer2_calc_logical(ip, lbase, &lbase, NULL);
	pblksize = hammer2_calc_physical(ip, lbase);
	KKASSERT(lblksize <= MAXPHYS);
	bcopy(bp->b_data, bio_data, lblksize);
	bp = NULL; /* safety, illegal to access after unlock */

	parent = hammer2_inode_chain(ip, clindex, HAMMER2_RESOLVE_ALWAYS);
	hammer2_write_file_core(bio_data, ip, &parent, lbase, IO_ASYNC,
	    pblksize, xop->head.mtid, &error);
	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
		parent = NULL; /* safety */
	}
	hammer2_xop_feed(&xop->head, NULL, clindex, error);

	error = hammer2_xop_collect(&xop->head, HAMMER2_XOP_COLLECT_NOWAIT);
	bp = xop->bp; /* now owned by us */
	if (error == HAMMER2_ERROR_ENOENT || error == 0) {
		bp->b_resid = 0;
		bp->b_error = 0;
		s = splbio();
		biodone(bp);
		splx(s);
	} else {
		hprintf("error %08x at blkno %016llx/%016llx\n",
		    error, (long long)bp->b_lblkno, (long long)bp->b_blkno);
		bp->b_error = EIO;
		bp->b_flags |= B_ERROR;
		s = splbio();
		biodone(bp);
		splx(s);
	}
	hammer2_trans_assert_strategy(ip->pmp);
	hammer2_trans_done(ip->pmp, HAMMER2_TRANS_BUFCACHE);
}

/*
 * Wait for pending I/O to complete.
 */
void
hammer2_bioq_sync(hammer2_pfs_t *pmp)
{
}

/*
 * Assign physical storage at (cparent, lbase), returning a suitable chain
 * and setting *errorp appropriately.
 *
 * If no error occurs, the returned chain will be in a modified state.
 *
 * If an error occurs, the returned chain may or may not be NULL.  If
 * not-null any chain->error (if not 0) will also be rolled up into *errorp.
 * So the caller only needs to test *errorp.
 *
 * cparent can wind up being anything.
 *
 * If datap is not NULL, *datap points to the real data we intend to write.
 * If we can dedup the storage location we set *datap to NULL to indicate
 * to the caller that a dedup occurred.
 *
 * NOTE: Special case for data embedded in inode.
 */
static hammer2_chain_t *
hammer2_assign_physical(hammer2_inode_t *ip, hammer2_chain_t **parentp,
    hammer2_key_t lbase, int pblksize, hammer2_tid_t mtid, char **datap,
    int *errorp)
{
	hammer2_chain_t *chain;
	hammer2_key_t key_dummy;
	hammer2_off_t dedup_off;
	int pradix;

	KKASSERT(pblksize >= HAMMER2_ALLOC_MIN);
	pradix = hammer2_getradix(pblksize);

	/*
	 * Locate the chain associated with lbase, return a locked chain.
	 * However, do not instantiate any data reference (which utilizes a
	 * device buffer) because we will be using direct IO via the
	 * logical buffer cache buffer.
	 */
	chain = hammer2_chain_lookup(parentp, &key_dummy, lbase, lbase, errorp,
	    HAMMER2_LOOKUP_NODATA);
	/*
	 * The lookup code should not return a DELETED chain to us, unless
	 * its a short-file embedded in the inode.  Then it is possible for
	 * the lookup to return a deleted inode.
	 */
	if (chain && (chain->flags & HAMMER2_CHAIN_DELETED) &&
	    chain->bref.type != HAMMER2_BREF_TYPE_INODE)
		hpanic("assign physical deleted %s chain %016llx/%d inum "
		    "%016llx lbase %016llx",
		    hammer2_breftype_to_str(chain->bref.type),
		    (long long)chain->bref.key, chain->bref.keybits,
		    (long long)ip->meta.inum, (long long)lbase);

	if (chain == NULL) {
		/*
		 * We found a hole, create a new chain entry.
		 *
		 * NOTE: DATA chains are created without device backing
		 *	 store (nor do we want any).
		 */
		dedup_off = hammer2_dedup_lookup((*parentp)->hmp, datap,
		    pblksize);
		*errorp |= hammer2_chain_create(parentp, &chain, NULL, ip->pmp,
		    HAMMER2_ENC_CHECK(ip->meta.check_algo) |
		    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE), lbase,
		    HAMMER2_PBUFRADIX, HAMMER2_BREF_TYPE_DATA, pblksize, mtid,
		    dedup_off, 0);
		if (chain == NULL)
			goto failed;
	} else if (chain->error == 0) {
		switch (chain->bref.type) {
		case HAMMER2_BREF_TYPE_INODE:
			/*
			 * The data is embedded in the inode, which requires
			 * a bit more finess.
			 */
			*errorp |= hammer2_chain_modify_ip(ip, chain, mtid, 0);
			break;
		case HAMMER2_BREF_TYPE_DATA:
			dedup_off = hammer2_dedup_lookup(chain->hmp, datap,
			    pblksize);
			if (chain->bytes != (unsigned int)pblksize) {
				*errorp |= hammer2_chain_resize(chain, mtid,
				    dedup_off, pradix, HAMMER2_MODIFY_OPTDATA);
				if (*errorp)
					break;
			}
			/*
			 * DATA buffers must be marked modified whether the
			 * data is in a logical buffer or not.  We also have
			 * to make this call to fixup the chain data pointers
			 * after resizing in case this is an encrypted or
			 * compressed buffer.
			 */
			*errorp |= hammer2_chain_modify(chain, mtid, dedup_off,
			    HAMMER2_MODIFY_OPTDATA);
			break;
		default:
			hpanic("bad blockref type %d", chain->bref.type);
			break;
		}
	} else {
		*errorp = chain->error;
	}
	atomic_set_int(&ip->flags, HAMMER2_INODE_DIRTYDATA);
failed:
	return (chain);
}

/*
 * The core write function which determines which path to take
 * depending on compression settings.  We also have to locate the
 * related chains so we can calculate and set the check data for
 * the blockref.
 */
static void
hammer2_write_file_core(char *data, hammer2_inode_t *ip,
    hammer2_chain_t **parentp, hammer2_key_t lbase, int ioflag, int pblksize,
    hammer2_tid_t mtid, int *errorp)
{
	hammer2_chain_t *chain;
	hammer2_inode_data_t *wipdata;
	char *bdata;

	*errorp = 0;

	switch (HAMMER2_DEC_ALGO(ip->meta.comp_algo)) {
	case HAMMER2_COMP_NONE:
		/*
		 * We have to assign physical storage to the buffer
		 * we intend to dirty or write now to avoid deadlocks
		 * in the strategy code later.
		 *
		 * This can return NOOFFSET for inode-embedded data.
		 * The strategy code will take care of it in that case.
		 */
		bdata = data;
		chain = hammer2_assign_physical(ip, parentp, lbase, pblksize,
		    mtid, &bdata, errorp);
		if (*errorp) {
			/* Skip modifications. */
		} else if (chain->bref.type == HAMMER2_BREF_TYPE_INODE) {
			wipdata = &chain->data->ipdata;
			KKASSERT(wipdata->meta.op_flags &
			    HAMMER2_OPFLAG_DIRECTDATA);
			bcopy(data, wipdata->u.data, HAMMER2_EMBEDDED_BYTES);
		} else if (bdata == NULL) {
			/* Copy of data already present on-media. */
			chain->bref.methods =
			    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE) +
			    HAMMER2_ENC_CHECK(ip->meta.check_algo);
			hammer2_chain_setcheck(chain, data);
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
		} else {
			hammer2_write_bp(chain, data, ioflag, pblksize, mtid,
			    errorp, ip->meta.check_algo);
		}
		if (chain) {
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
		}
		break;
	case HAMMER2_COMP_AUTOZERO:
		/* Check for zero-fill only. */
		hammer2_zero_check_and_write(data, ip, parentp, lbase, ioflag,
		    pblksize, mtid, errorp, ip->meta.check_algo);
		break;
	case HAMMER2_COMP_LZ4:
	case HAMMER2_COMP_ZLIB:
	default:
		/* Check for zero-fill and attempt compression. */
		hammer2_compress_and_write(data, ip, parentp, lbase, ioflag,
		    pblksize, mtid, errorp, ip->meta.comp_algo,
		    ip->meta.check_algo);
		break;
	}
}

/*
 * Generic function that will perform the compression in compression
 * write path. The compression algorithm is determined by the settings
 * obtained from inode.
 */
static void
hammer2_compress_and_write(char *data, hammer2_inode_t *ip,
    hammer2_chain_t **parentp, hammer2_key_t lbase, int ioflag, int pblksize,
    hammer2_tid_t mtid, int *errorp, int comp_algo, int check_algo)
{
	hammer2_chain_t *chain;
	hammer2_inode_data_t *wipdata;
	hammer2_io_t *dio;
	z_stream strm_compress;
	char *comp_buffer, *bdata;
	int comp_size, comp_block_size, comp_level, ret;

	KKASSERT(pblksize / 2 <= 32768);
	KKASSERT(pblksize / 2 <= HAMMER2_PBUFSIZE / 2);

	/*
	 * An all-zeros write creates a hole unless the check code
	 * is disabled.  When the check code is disabled all writes
	 * are done in-place, including any all-zeros writes.
	 *
	 * NOTE: A snapshot will still force a copy-on-write
	 *	 (see the HAMMER2_CHECK_NONE in hammer2_chain.c).
	 */
	if (check_algo != HAMMER2_CHECK_NONE &&
	    test_block_zeros(data, pblksize)) {
		zero_write(data, ip, parentp, lbase, mtid, errorp);
		return;
	}

	/*
	 * Compression requested.  Try to compress the block.  We store
	 * the data normally if we cannot sufficiently compress it.
	 *
	 * We have a heuristic to detect files which are mostly
	 * uncompressable and avoid the compression attempt in that
	 * case.  If the compression heuristic is turned off, we always
	 * try to compress.
	 */
	comp_size = 0;
	comp_buffer = NULL;

	if (ip->comp_heuristic < 8 || (ip->comp_heuristic & 7) == 0 ||
	    hammer2_always_compress) {
		switch (HAMMER2_DEC_ALGO(comp_algo)) {
		case HAMMER2_COMP_LZ4:
			/*
			 * We need to prefix with the size, LZ4
			 * doesn't do it for us.  Add the related
			 * overhead.
			 *
			 * NOTE: The LZ4 code seems to assume at least an
			 *	 8-byte buffer size granularity and may
			 *	 overrun the buffer if given a 4-byte
			 *	 granularity.
			 */
			comp_buffer = hmalloc(HAMMER2_PBUFSIZE / 2, M_HAMMER2_WBUF,
			    M_WAITOK | M_ZERO);
			comp_size = LZ4_compress_limitedOutput(data,
			    &comp_buffer[sizeof(int)], pblksize,
			    pblksize / 2 - sizeof(int64_t));
			*(int *)comp_buffer = comp_size;
			if (comp_size)
				comp_size += sizeof(int);
			break;
		case HAMMER2_COMP_ZLIB:
			comp_level = HAMMER2_DEC_LEVEL(comp_algo);
			if (comp_level == 0)
				comp_level = 6; /* default zlib compression */
			else if (comp_level < 6)
				comp_level = 6;
			else if (comp_level > 9)
				comp_level = 9;
			bzero(&strm_compress, sizeof(strm_compress));
			ret = deflateInit(&strm_compress, comp_level);
			if (ret != Z_OK)
				hprintf("fatal error on deflateInit\n");

			comp_buffer = hmalloc(HAMMER2_PBUFSIZE / 2, M_HAMMER2_WBUF,
			    M_WAITOK | M_ZERO);
			strm_compress.next_in = data;
			strm_compress.avail_in = pblksize;
			strm_compress.next_out = comp_buffer;
			strm_compress.avail_out = pblksize / 2;
			ret = deflate(&strm_compress, Z_FINISH);
			if (ret == Z_STREAM_END)
				comp_size = pblksize / 2 -
				    strm_compress.avail_out;
			else
				comp_size = 0;
			ret = deflateEnd(&strm_compress);
			break;
		default:
			hprintf("unknown compression method %d\n", comp_algo);
			break;
		}
	}

	if (comp_size == 0) {
		/* Compression failed or turned off. */
		comp_block_size = pblksize; /* safety */
		if (++ip->comp_heuristic > 128)
			ip->comp_heuristic = 8;
	} else {
		/* Compression succeeded. */
		ip->comp_heuristic = 0;
		if (comp_size <= 1024) {
			comp_block_size = 1024;
		} else if (comp_size <= 2048) {
			comp_block_size = 2048;
		} else if (comp_size <= 4096) {
			comp_block_size = 4096;
		} else if (comp_size <= 8192) {
			comp_block_size = 8192;
		} else if (comp_size <= 16384) {
			comp_block_size = 16384;
		} else if (comp_size <= 32768) {
			comp_block_size = 32768;
		} else {
			hpanic("weird comp_size value");
			/* NOT REACHED */
		}
		/*
		 * Must zero the remainder or dedup (which operates on a
		 * physical block basis) will not find matches.
		 */
		if (comp_size < comp_block_size)
			bzero(comp_buffer + comp_size,
			    comp_block_size - comp_size);
	}

	/*
	 * Assign physical storage, bdata will be set to NULL if a live-dedup
	 * was successful.
	 */
	bdata = comp_size ? comp_buffer : data;
	chain = hammer2_assign_physical(ip, parentp, lbase, comp_block_size,
	    mtid, &bdata, errorp);
	if (*errorp)
		goto done;
	if (chain->bref.type == HAMMER2_BREF_TYPE_INODE) {
		*errorp = hammer2_chain_modify_ip(ip, chain, mtid, 0);
		if (*errorp == 0) {
			wipdata = &chain->data->ipdata;
			KKASSERT(wipdata->meta.op_flags &
			    HAMMER2_OPFLAG_DIRECTDATA);
			bcopy(data, wipdata->u.data, HAMMER2_EMBEDDED_BYTES);
		}
	} else if (bdata == NULL) {
		/*
		 * Live deduplication, a copy of the data is already present
		 * on the media.
		 */
		if (comp_size)
			chain->bref.methods =
			    HAMMER2_ENC_COMP(comp_algo) +
			    HAMMER2_ENC_CHECK(check_algo);
		else
			chain->bref.methods =
			    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE) +
			    HAMMER2_ENC_CHECK(check_algo);
		bdata = comp_size ? comp_buffer : data;
		hammer2_chain_setcheck(chain, bdata);
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
	} else {
		KKASSERT(chain->flags & HAMMER2_CHAIN_MODIFIED);
		switch (chain->bref.type) {
		case HAMMER2_BREF_TYPE_INODE:
			hpanic("unexpected inode");
			break;
		case HAMMER2_BREF_TYPE_DATA:
			/* Optimize out the read-before-write if possible. */
			*errorp = hammer2_io_newnz(chain->hmp, chain->bref.type,
			    chain->bref.data_off, chain->bytes, &dio);
			if (*errorp) {
				hammer2_io_brelse(&dio);
				hprintf("getblk error %d\n", *errorp);
				break;
			}
			bdata = hammer2_io_data(dio, chain->bref.data_off);
			/*
			 * When loading the block make sure we don't
			 * leave garbage after the compressed data.
			 */
			if (comp_size) {
				chain->bref.methods =
				    HAMMER2_ENC_COMP(comp_algo) +
				    HAMMER2_ENC_CHECK(check_algo);
				bcopy(comp_buffer, bdata, comp_block_size);
			} else {
				chain->bref.methods =
				    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE) +
				    HAMMER2_ENC_CHECK(check_algo);
				bcopy(data, bdata, pblksize);
			}
			/*
			 * The flush code doesn't calculate check codes for
			 * file data (doing so can result in excessive I/O),
			 * so we do it here.
			 */
			hammer2_chain_setcheck(chain, bdata);
			/*
			 * Device buffer is now valid, chain is no longer in
			 * the initial state.
			 *
			 * (No blockref table worries with file data)
			 */
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
			hammer2_dedup_record(chain, dio, bdata);
			/* Now write the related dio. */
			if (ioflag & IO_SYNC)
				hammer2_io_bwrite(&dio);
			else if (ioflag & IO_ASYNC)
				hammer2_io_bawrite(&dio);
			else
				hammer2_io_bdwrite(&dio);
			break;
		default:
			hpanic("bad blockref type %d", chain->bref.type);
			break;
		}
	}
done:
	if (chain) {
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
	if (comp_buffer)
		hfree(comp_buffer, M_HAMMER2_WBUF, HAMMER2_PBUFSIZE / 2);
}

/*
 * Function that performs zero-checking and writing without compression,
 * it corresponds to default zero-checking path.
 */
static void
hammer2_zero_check_and_write(char *data, hammer2_inode_t *ip,
    hammer2_chain_t **parentp, hammer2_key_t lbase, int ioflag, int pblksize,
    hammer2_tid_t mtid, int *errorp, int check_algo)
{
	hammer2_chain_t *chain;
	char *bdata;

	if (check_algo != HAMMER2_CHECK_NONE &&
	    test_block_zeros(data, pblksize)) {
		/*
		 * An all-zeros write creates a hole unless the check code
		 * is disabled.  When the check code is disabled all writes
		 * are done in-place, including any all-zeros writes.
		 *
		 * NOTE: A snapshot will still force a copy-on-write
		 *	 (see the HAMMER2_CHECK_NONE in hammer2_chain.c).
		 */
		zero_write(data, ip, parentp, lbase, mtid, errorp);
	} else {
		/* Normal write (bdata set to NULL if de-duplicated). */
		bdata = data;
		chain = hammer2_assign_physical(ip, parentp, lbase, pblksize,
		    mtid, &bdata, errorp);
		if (*errorp) {
			/* Do nothing. */
		} else if (bdata) {
			hammer2_write_bp(chain, data, ioflag, pblksize, mtid,
			    errorp, check_algo);
		} else {
			/* Dedup occurred. */
			chain->bref.methods =
			    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE) +
			    HAMMER2_ENC_CHECK(check_algo);
			hammer2_chain_setcheck(chain, data);
			atomic_clear_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
		}
		if (chain) {
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
		}
	}
}

/*
 * A function to test whether a block of data contains only zeros,
 * returns TRUE (non-zero) if the block is all zeros.
 */
static int
test_block_zeros(const char *buf, size_t bytes)
{
	size_t i;

	for (i = 0; i < bytes; i += sizeof(long)) {
		if (*(const long *)(buf + i) != 0)
			return (0);
	}
	return (1);
}

/*
 * Function to "write" a block that contains only zeros.
 */
static void
zero_write(char *data, hammer2_inode_t *ip, hammer2_chain_t **parentp,
    hammer2_key_t lbase, hammer2_tid_t mtid, int *errorp)
{
	hammer2_chain_t *chain;
	hammer2_inode_data_t *wipdata;
	hammer2_key_t key_dummy;

	chain = hammer2_chain_lookup(parentp, &key_dummy, lbase, lbase, errorp,
	    HAMMER2_LOOKUP_NODATA);
	if (chain) {
		if (chain->bref.type == HAMMER2_BREF_TYPE_INODE) {
			if (*errorp == 0)
				*errorp = hammer2_chain_modify_ip(ip, chain,
				    mtid, 0);
			if (*errorp == 0) {
				wipdata = &chain->data->ipdata;
				KKASSERT(wipdata->meta.op_flags &
				    HAMMER2_OPFLAG_DIRECTDATA);
				bzero(wipdata->u.data, HAMMER2_EMBEDDED_BYTES);
			}
		} else {
			/* chain->error ok for deletion */
			hammer2_chain_delete(*parentp, chain, mtid,
			    HAMMER2_DELETE_PERMANENT);
		}
		atomic_set_int(&ip->flags, HAMMER2_INODE_DIRTYDATA);
		hammer2_chain_unlock(chain);
		hammer2_chain_drop(chain);
	}
}

/*
 * Function to write the data as it is, without performing any sort of
 * compression. This function is used in path without compression and
 * default zero-checking path.
 */
static void
hammer2_write_bp(hammer2_chain_t *chain, char *data, int ioflag, int pblksize,
    hammer2_tid_t mtid, int *errorp, int check_algo)
{
	hammer2_inode_data_t *wipdata;
	hammer2_io_t *dio;
	char *bdata;
	int error = 0;

	KKASSERT(chain->flags & HAMMER2_CHAIN_MODIFIED);

	switch (chain->bref.type) {
	case HAMMER2_BREF_TYPE_INODE:
		wipdata = &chain->data->ipdata;
		KKASSERT(wipdata->meta.op_flags & HAMMER2_OPFLAG_DIRECTDATA);
		bcopy(data, wipdata->u.data, HAMMER2_EMBEDDED_BYTES);
		error = 0;
		break;
	case HAMMER2_BREF_TYPE_DATA:
		error = hammer2_io_newnz(chain->hmp, chain->bref.type,
		    chain->bref.data_off, chain->bytes, &dio);
		if (error) {
			hammer2_io_bqrelse(&dio);
			hprintf("getblk error %d\n", error);
			break;
		}
		bdata = hammer2_io_data(dio, chain->bref.data_off);
		chain->bref.methods =
		    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE) +
		    HAMMER2_ENC_CHECK(check_algo);
		bcopy(data, bdata, chain->bytes);
		/*
		 * The flush code doesn't calculate check codes for
		 * file data (doing so can result in excessive I/O),
		 * so we do it here.
		 */
		hammer2_chain_setcheck(chain, bdata);
		/*
		 * Device buffer is now valid, chain is no longer in
		 * the initial state.
		 *
		 * (No blockref table worries with file data)
		 */
		atomic_clear_int(&chain->flags, HAMMER2_CHAIN_INITIAL);
		hammer2_dedup_record(chain, dio, bdata);
		/* Now write the related dio. */
		if (ioflag & IO_SYNC)
			hammer2_io_bwrite(&dio);
		else if (ioflag & IO_ASYNC)
			hammer2_io_bawrite(&dio);
		else
			hammer2_io_bdwrite(&dio);
		break;
	default:
		hpanic("bad blockref type %d", chain->bref.type);
		break;
	}
	*errorp = error;
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
static void
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
	if (hammer2_dedup_enable == 0)
		return;
	if (dio == NULL) {
		dio = chain->dio;
		if (dio == NULL)
			return;
	}
	hammer2_mtx_assert_unlocked(&dio->lock);

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
	hammer2_mtx_ex(&dio->lock);
	dio->dedup_valid |= mask; /* DragonFly uses atomic_set_64 */
	hammer2_mtx_unlock(&dio->lock);
}

static hammer2_off_t
hammer2_dedup_lookup(hammer2_dev_t *hmp, char **datap, int pblksize)
{
	hammer2_dedup_t *dedup;
	hammer2_io_t *dio;
	hammer2_off_t off;
	char *data, *dtmp;
	uint64_t crc, mask;
	int i;

	if (hammer2_dedup_enable == 0)
		return (0);
	data = *datap;
	if (data == NULL)
		return (0);

	/*
	 * XXX use the built-in crc (the dedup lookup sequencing
	 * needs to be fixed so the check code is already present
	 * when dedup_lookup is called)
	 */
	crc = XXH64(data, pblksize, XXH_HAMMER2_SEED);
	dedup = &hmp->heur_dedup[crc & (HAMMER2_DEDUP_HEUR_MASK & ~3)];

	for (i = 0; i < 4; ++i) {
		off = dedup[i].data_off;
		cpu_ccfence();
		if (dedup[i].data_crc != crc)
			continue;
		if ((1 << (int)(off & HAMMER2_OFF_MASK_RADIX)) != pblksize)
			continue;
		dio = hammer2_io_getquick(hmp, off, pblksize);
		if (dio) {
			dtmp = hammer2_io_data(dio, off),
			mask = hammer2_dedup_mask(dio, off, pblksize);
			hammer2_mtx_assert_unlocked(&dio->lock);
			hammer2_mtx_ex(&dio->lock);
			if ((dio->dedup_alloc & mask) == mask &&
			    (dio->dedup_valid & mask) == mask &&
			    bcmp(data, dtmp, pblksize) == 0) {
				hammer2_mtx_unlock(&dio->lock);
				hammer2_io_putblk(&dio);
				*datap = NULL;
				dedup[i].ticks = getticks();
				return (off);
			}
			hammer2_mtx_unlock(&dio->lock);
			hammer2_io_putblk(&dio);
		}
	}
	return (0);
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

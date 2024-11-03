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

#ifndef _FS_HAMMER2_OS_H_
#define _FS_HAMMER2_OS_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/pool.h>
#include <sys/vnode.h>
#include <sys/atomic.h>

#include "hammer2_compat.h"

#ifdef HAMMER2_INVARIANTS
#define HFMT	"%s(%s|%d): "
#define HARGS	__func__, \
    curproc ? curproc->p_p->ps_comm : "-", \
    curproc ? curproc->p_tid : -1
#else
#define HFMT	"%s: "
#define HARGS	__func__
#endif

#define hprintf(X, ...)	printf(HFMT X, HARGS, ## __VA_ARGS__)
#define hpanic(X, ...)	panic(HFMT X, HARGS, ## __VA_ARGS__)

#ifdef HAMMER2_INVARIANTS
#define debug_hprintf	hprintf
#else
#define debug_hprintf(X, ...)	do {} while (0)
#endif

/* hammer2_lk is lockmgr(9) in DragonFly. */
/* mutex(9) is spinlock in OpenBSD. */
typedef struct rwlock hammer2_lk_t;

static __inline void
hammer2_lk_init(hammer2_lk_t *p, const char *s)
{
	rw_init(p, s);
}

static __inline void
hammer2_lk_ex(hammer2_lk_t *p)
{
	rw_enter_write(p);
}

static __inline void
hammer2_lk_unlock(hammer2_lk_t *p)
{
	rw_exit_write(p);
}

static __inline void
hammer2_lk_destroy(hammer2_lk_t *p __unused)
{
}

static __inline void
hammer2_lk_assert_ex(hammer2_lk_t *p)
{
	KASSERT(rw_status(p) == RW_WRITE);
}

static __inline void
hammer2_lk_assert_unlocked(hammer2_lk_t *p)
{
	KASSERT(rw_status(p) == 0);
}

typedef int hammer2_lkc_t;

static __inline void
hammer2_lkc_init(hammer2_lkc_t *c __unused, const char *s __unused)
{
}

static __inline void
hammer2_lkc_destroy(hammer2_lkc_t *c __unused)
{
}

static __inline void
hammer2_lkc_sleep(hammer2_lkc_t *c, hammer2_lk_t *p, const char *s)
{
	rwsleep(c, p, PCATCH, s, 0);
}

static __inline void
hammer2_lkc_wakeup(hammer2_lkc_t *c)
{
	wakeup(c);
}

/*
 * Mutex and spinlock shims.
 * Normal synchronous non-abortable locks can be substituted for spinlocks.
 * OpenBSD HAMMER2 currently uses rrwlock(9) for mtx and rwlock(9) for spinlock.
 */
struct rrwlock_wrapper {
	struct rrwlock lock;
	int refs;
};
typedef struct rrwlock_wrapper hammer2_mtx_t;

static __inline void
hammer2_mtx_init(hammer2_mtx_t *p, const char *s)
{
	bzero(p, sizeof(*p));
	rrw_init(&p->lock, s);
}

static __inline void
hammer2_mtx_init_recurse(hammer2_mtx_t *p, const char *s)
{
	bzero(p, sizeof(*p));
	rrw_init(&p->lock, s);
}

static __inline void
hammer2_mtx_ex(hammer2_mtx_t *p)
{
	rrw_enter(&p->lock, RW_WRITE);
	atomic_add_int(&p->refs, 1);
}

static __inline void
hammer2_mtx_sh(hammer2_mtx_t *p)
{
	rrw_enter(&p->lock, RW_READ);
	atomic_add_int(&p->refs, 1);
}

static __inline void
hammer2_mtx_unlock(hammer2_mtx_t *p)
{
	atomic_add_int(&p->refs, -1);
	rrw_exit(&p->lock);
}

static __inline int
hammer2_mtx_refs(hammer2_mtx_t *p)
{
	return (p->refs);
}

static __inline void
hammer2_mtx_destroy(hammer2_mtx_t *p __unused)
{
}

/* Non-zero if exclusively locked by the calling thread. */
static __inline int
hammer2_mtx_owned(hammer2_mtx_t *p)
{
	return (rrw_status(&p->lock) == RW_WRITE);
}

/* RW_READ doesn't necessarily mean read locked by calling thread. */
static __inline void
hammer2_mtx_assert_ex(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) == RW_WRITE);
}

static __inline void
hammer2_mtx_assert_sh(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) == RW_READ);
}

static __inline void
hammer2_mtx_assert_locked(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) == RW_READ || rrw_status(&p->lock) == RW_WRITE);
}

static __inline void
hammer2_mtx_assert_unlocked(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) == 0);
}

static __inline int
hammer2_mtx_ex_try(hammer2_mtx_t *p)
{
	if (!rrw_enter(&p->lock, RW_WRITE|RW_NOSLEEP)) {
		atomic_add_int(&p->refs, 1);
		return (0);
	} else {
		return (1);
	}
}

static __inline int
hammer2_mtx_sh_try(hammer2_mtx_t *p)
{
	if (!rrw_enter(&p->lock, RW_READ|RW_NOSLEEP)) {
		atomic_add_int(&p->refs, 1);
		return (0);
	} else {
		return (1);
	}
}

static __inline int
hammer2_mtx_upgrade_try(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) != 0);
	if (hammer2_mtx_owned(p))
		return (0);

	hammer2_mtx_unlock(p); /* XXX */

	return (hammer2_mtx_ex_try(p));
}

static __inline int
hammer2_mtx_temp_release(hammer2_mtx_t *p)
{
	int x;

	x = hammer2_mtx_owned(p);
	hammer2_mtx_unlock(p);

	return (x);
}

static __inline void
hammer2_mtx_temp_restore(hammer2_mtx_t *p, int x)
{
	if (x)
		hammer2_mtx_ex(p);
	else
		hammer2_mtx_sh(p);
}

typedef struct rwlock hammer2_spin_t;

static __inline void
hammer2_spin_init(hammer2_spin_t *p, const char *s)
{
	rw_init(p, s);
}

static __inline void
hammer2_spin_ex(hammer2_spin_t *p)
{
	rw_enter(p, RW_WRITE);
}

static __inline void
hammer2_spin_sh(hammer2_spin_t *p)
{
	rw_enter(p, RW_READ);
}

static __inline void
hammer2_spin_unex(hammer2_spin_t *p)
{
	rw_exit(p);
}

static __inline void
hammer2_spin_unsh(hammer2_spin_t *p)
{
	rw_exit(p);
}

static __inline void
hammer2_spin_destroy(hammer2_spin_t *p __unused)
{
}

static __inline void
hammer2_spin_assert_ex(hammer2_spin_t *p)
{
	rw_assert_wrlock(p);
}

static __inline void
hammer2_spin_assert_sh(hammer2_spin_t *p)
{
	rw_assert_rdlock(p);
}

static __inline void
hammer2_spin_assert_locked(hammer2_spin_t *p)
{
	rw_assert_anylock(p);
}

static __inline void
hammer2_spin_assert_unlocked(hammer2_spin_t *p)
{
	rw_assert_unlocked(p);
}

extern struct pool hammer2_pool_inode;
extern struct pool hammer2_pool_xops;

extern int malloc_leak_m_hammer2;
extern int malloc_leak_m_hammer2_rbuf;
extern int malloc_leak_m_hammer2_wbuf;
extern int malloc_leak_m_hammer2_lz4;
extern int malloc_leak_m_temp;

//#define HAMMER2_MALLOC
#ifdef HAMMER2_MALLOC
static __inline void
adjust_malloc_leak(int delta, int type)
{
	int *lp;

	switch (type) {
	case M_HAMMER2:
		lp = &malloc_leak_m_hammer2;
		break;
	case M_HAMMER2_RBUF:
		lp = &malloc_leak_m_hammer2_rbuf;
		break;
	case M_HAMMER2_WBUF:
		lp = &malloc_leak_m_hammer2_wbuf;
		break;
	case M_HAMMER2_LZ4:
		lp = &malloc_leak_m_hammer2_lz4;
		break;
	case M_TEMP:
		lp = &malloc_leak_m_temp;
		break;
	default:
		hpanic("bad malloc type %d", type);
		break;
	}
	atomic_add_int(lp, delta);
}

static __inline void *
hmalloc(size_t size, int type, int flags)
{
	void *addr;

	flags &= ~M_WAITOK;
	flags |= M_NOWAIT;

	addr = malloc(size, type, flags);
	KASSERTMSG(addr, "size %ld type %d flags %x malloc_leak %d,%d,%d,%d,%d",
	    (long)size, type, flags,
	    malloc_leak_m_hammer2,
	    malloc_leak_m_hammer2_rbuf,
	    malloc_leak_m_hammer2_wbuf,
	    malloc_leak_m_hammer2_lz4,
	    malloc_leak_m_temp);
	if (addr) {
		KKASSERT(size > 0);
		adjust_malloc_leak(size, type);
	}

	return (addr);
}

static __inline void
hfree(void *addr, int type, size_t freedsize)
{
	if (addr) {
		KKASSERT(freedsize > 0);
		adjust_malloc_leak(-(int)freedsize, type);
	}
	free(addr, type, freedsize);
}

static __inline char *
hstrdup(const char *str)
{
	size_t len;
	char *copy;

	len = strlen(str) + 1;
	copy = hmalloc(len, M_TEMP, M_NOWAIT);
	if (copy == NULL)
		return (NULL);
	bcopy(str, copy, len);

	return (copy);
}
#else
#define hmalloc(size, type, flags)	malloc(size, type, flags)
#define hfree(addr, type, freedsize)	free(addr, type, freedsize)

static __inline char *
hstrdup(const char *str)
{
	size_t len;
	char *copy;

	len = strlen(str) + 1;
	copy = hmalloc(len, M_TEMP, M_WAITOK);
	bcopy(str, copy, len);

	return (copy);
}
#endif

static __inline void
hstrfree(char *str)
{
	hfree(str, M_TEMP, strlen(str) + 1);
}

extern const struct vops hammer2_vops;
extern const struct vops hammer2_specvops;
#ifdef FIFO
extern const struct vops hammer2_fifovops;
#endif

#endif /* !_FS_HAMMER2_OS_H_ */

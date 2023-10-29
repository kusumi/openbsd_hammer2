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

/* printf(9) variants for HAMMER2 */
#ifdef INVARIANTS
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

#ifdef INVARIANTS
#define debug_hprintf	hprintf
#else
#define debug_hprintf(X, ...)	do { } while (0)
#endif

/* hammer2_lk is lockmgr(9) in DragonFly. */
/* mutex(9) is spinlock in OpenBSD. */
typedef struct rwlock hammer2_lk_t;

#define hammer2_lk_init(p, s)		rw_init(p, s)
#define hammer2_lk_ex(p)		rw_enter_write(p)
#define hammer2_lk_unlock(p)		rw_exit_write(p)
#define hammer2_lk_destroy(p)		do {} while (0)

#define hammer2_lk_assert_ex(p)		KASSERT(rw_status(p) == RW_WRITE)
#define hammer2_lk_assert_unlocked(p)	KASSERT(rw_status(p) == 0)

typedef char * hammer2_lkc_t;

#define hammer2_lkc_init(c, s)		do { *(c) = kstrdup(s); } while (0)
#define hammer2_lkc_destroy(c)		kstrfree(*(c))
#define hammer2_lkc_sleep(c, p, s)	rwsleep(*(c), p, PCATCH, *(c), 0)
#define hammer2_lkc_wakeup(c)		wakeup(*(c))

/*
 * Mutex and spinlock shims.
 * Normal synchronous non-abortable locks can be substituted for spinlocks.
 * OpenBSD HAMMER2 currently uses rrwlock(9) for mtx and rwlock(9) for spinlock.
 */
typedef struct rrwlock hammer2_mtx_t;

#define hammer2_mtx_init(p, s)		rrw_init(p, s)
#define hammer2_mtx_init_recurse(p, s)	rrw_init(p, s)
#define hammer2_mtx_ex(p)		rrw_enter(p, RW_WRITE)
#define hammer2_mtx_ex_try(p)		rrw_enter(p, RW_WRITE|RW_NOSLEEP)
#define hammer2_mtx_sh(p)		rrw_enter(p, RW_READ)
#define hammer2_mtx_sh_try(p)		rrw_enter(p, RW_READ|RW_NOSLEEP)
#define hammer2_mtx_unlock(p)		rrw_exit(p)
#define hammer2_mtx_destroy(p)		do {} while (0)

/* Non-zero if exclusively locked by the calling thread. */
#define hammer2_mtx_owned(p)		(rrw_status(p) == RW_WRITE)

/* RW_READ doesn't necessarily mean read locked by calling thread. */
#define hammer2_mtx_assert_locked(p)	KASSERT(rrw_status(p) == RW_READ || rrw_status(p) == RW_WRITE)
#define hammer2_mtx_assert_unlocked(p)	KASSERT(rrw_status(p) == 0)
#define hammer2_mtx_assert_ex(p)	KASSERT(rrw_status(p) == RW_WRITE)
#define hammer2_mtx_assert_sh(p)	KASSERT(rrw_status(p) == RW_READ)

static __inline int
hammer2_mtx_upgrade_try(hammer2_mtx_t *p)
{
#define hammer2_mtx_status(p)		rrw_status(p)
	KASSERT(hammer2_mtx_status(p) != 0);
	KASSERT(hammer2_mtx_status(p) != RW_WRITE);

	hammer2_mtx_unlock(p); /* XXX */

	return (hammer2_mtx_ex_try(p) ? 1 : 0); /* 0 on success */
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

#define hammer2_spin_init(p, s)		rw_init(p, s)
#define hammer2_spin_ex(p)		rw_enter(p, RW_WRITE)
#define hammer2_spin_sh(p)		rw_enter(p, RW_READ)
#define hammer2_spin_unex(p)		rw_exit(p)
#define hammer2_spin_unsh(p)		rw_exit(p)
#define hammer2_spin_destroy(p)		do {} while (0)

#define hammer2_spin_assert_locked(p)	rw_assert_anylock(p)
#define hammer2_spin_assert_unlocked(p)	rw_assert_unlocked(p)
#define hammer2_spin_assert_ex(p)	rw_assert_wrlock(p)
#define hammer2_spin_assert_sh(p)	rw_assert_rdlock(p)

#endif /* !_FS_HAMMER2_OS_H_ */

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

#ifndef _FS_HAMMER2_COMPAT_H_
#define _FS_HAMMER2_COMPAT_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/stdint.h>
#include <sys/atomic.h>

#include <machine/cpufunc.h>

/* Taken from sys/sys/cdefs.h in FreeBSD. */
#define __DECONST(type, var)	((type)(__uintptr_t)(const void *)(var))

#if 0
#define HAMMER2_INVARIANTS
#endif

/* Emulate INVARIANTS in FreeBSD. */
#if 1
#define INVARIANTS	DIAGNOSTIC
#define __diagused	__unused
#else
#define INVARIANTS	DEBUG
#define __diagused	__unused
#endif

/* DragonFly KKASSERT is OpenBSD KASSERT equivalent. */
#define KKASSERT	KASSERT

#define rounddown2(x, y) ((x) & ~((y) - 1))	/* y power of two */

#define atomic_set_int		atomic_setbits_int
#define atomic_clear_int	atomic_clearbits_int

#define atomic_set_32		atomic_set_int
#define atomic_add_32		atomic_add_int

#define atomic_cmpset_int(ptr, old, new)	\
	(atomic_cas_uint((ptr), (old), (new)) == (old))

#define atomic_cmpset_32	atomic_cmpset_int

#define atomic_cmpset_64(ptr, old, new)		\
	(__sync_val_compare_and_swap((ptr), (old), (new)))

static __inline unsigned int
atomic_fetchadd_int(volatile unsigned int *p, unsigned int v)
{
	unsigned int value;

	do {
		value = *p;
	} while (!atomic_cmpset_int(p, value, value + v));
	return (value);
}

static __inline uint32_t
atomic_fetchadd_32(volatile uint32_t *p, uint32_t v)
{
	uint32_t value;

	do {
		value = *p;
	} while (!atomic_cmpset_32(p, value, value + v));
	return (value);
}

static __inline uint64_t
atomic_fetchadd_64(volatile uint64_t *p, uint64_t v)
{
	uint64_t value;

	do {
		value = *p;
	} while (!atomic_cmpset_64(p, value, value + v));
	return (value);
}

#define cpu_pause()	CPU_BUSY_CYCLE()

/* Taken from sys/sys/cdefs.h in FreeBSD. */
#define __compiler_membar()	__asm __volatile(" " : : : "memory")
#define cpu_ccfence()	__compiler_membar()

#define getticks()	(ticks)

#define bqrelse(bp)	brelse(bp)

#endif /* !_FS_HAMMER2_COMPAT_H_ */

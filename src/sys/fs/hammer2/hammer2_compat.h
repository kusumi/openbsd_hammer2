/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2023 Tomohiro Kusumi <tkusumi@netbsd.org>
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

#include <sys/stdint.h>
#include <sys/atomic.h>

#include <machine/cpufunc.h>

/* Taken from sys/sys/cdefs.h in FreeBSD. */
#ifndef __DECONST
#define __DECONST(type, var)	((type)(__uintptr_t)(const void *)(var))
#endif

/* Emulate INVARIANTS in FreeBSD. */
#if 1
#define INVARIANTS	DIAGNOSTIC
#define __debugvar	__diagused
#else
#define INVARIANTS	DEBUG
#define __debugvar	__debugused
#endif

/* DragonFly KKASSERT is NetBSD KASSERT equivalent. */
#define KKASSERT	KASSERT

#if 0
#define atomic_cmpset_uint(ptr, old, new)	\
	(atomic_cas_uint((ptr), (old), (new)) == (old))

#define atomic_cmpset_32(ptr, old, new)	\
	(atomic_cas_32((ptr), (old), (new)) == (old))

/* XXX Not atomic, but harmless with current read-only support. */
static __inline unsigned int
atomic_fetchadd_uint(volatile unsigned int *p, unsigned int v)
{
	unsigned int value;

	do {
		value = *p;
	} while (!atomic_cmpset_uint(p, value, value + v));
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

#define atomic_fetchadd_int	atomic_fetchadd_uint

/* XXX NetBSD only has arch dependent function. */
#if defined(__i386__) || defined(__x86_64__)
#define cpu_spinwait	x86_pause
#else
#define cpu_spinwait	do {} while (0)
#endif
#endif

#endif /* !_FS_HAMMER2_COMPAT_H_ */

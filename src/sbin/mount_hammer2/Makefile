.include <bsd.own.mk>

PROG=	mount_hammer2
SRCS=	mount_hammer2.c getmntopts.c
MAN=	mount_hammer2.8

WARNS=	5

CFLAGS+=	-I../../sys

MOUNT=		${BSDSRCDIR}/sbin/mount
CFLAGS+=	-I${MOUNT}
.PATH:		${MOUNT}

.include <bsd.prog.mk>

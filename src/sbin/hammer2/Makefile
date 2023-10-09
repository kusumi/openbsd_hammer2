.include <bsd.own.mk>

PROG=	hammer2
SRCS=	cmd_bulkfree.c cmd_cleanup.c cmd_debug.c cmd_destroy.c cmd_emergency.c \
	cmd_growfs.c cmd_pfs.c cmd_setcheck.c cmd_setcomp.c cmd_snapshot.c \
	cmd_stat.c cmd_volume.c main.c ondisk.c print_inode.c subs.c xxhash.c \
	icrc32.c
MAN=	hammer2.8

.PATH:	../../sys/libkern ../../sys/fs/hammer2/xxhash

WARNS=	5

CFLAGS+=	-I../../sys

DPADD+=		${LIBCRYPTO}
LDADD+=		-lcrypto

.include <bsd.prog.mk>

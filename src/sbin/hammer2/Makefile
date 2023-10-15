.include <bsd.own.mk>

PROG=	hammer2
SRCS=	cmd_bulkfree.c cmd_cleanup.c hammer2_compression.c cmd_debug.c \
	cmd_destroy.c cmd_emergency.c cmd_growfs.c cmd_pfs.c cmd_recover.c \
	cmd_setcheck.c cmd_setcomp.c cmd_snapshot.c cmd_stat.c cmd_volume.c \
	hammer2_lz4.c main.c ondisk.c print_inode.c subs.c xxhash.c icrc32.c
MAN=	hammer2.8

.PATH:	../../sys/libkern ../../sys/fs/hammer2 ../../sys/fs/hammer2/xxhash

WARNS=	5

CFLAGS+=	-I../../sys
CFLAGS+=	-DZLIB_CONST

# error: 'SHA256_xxx' is deprecated [-Werror,-Wdeprecated-declarations]
CFLAGS+=	-Wno-deprecated-declarations

DPADD+=		${LIBCRYPTO}
LDADD+=		-lcrypto

DPADD+=		${LIBZ}
LDADD+=		-lz

.include <bsd.prog.mk>

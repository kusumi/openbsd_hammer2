#!/usr/local/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=/usr/local
fi

[ -e /usr/bin/install ] || exit 1
[ -e /usr/bin/strip ] || exit 1

[ -d ${DIR} ] || /bin/mkdir -p ${DIR}
[ -d ${DIR}/sbin ] || /bin/mkdir -p ${DIR}/sbin
[ -d ${DIR}/man/man8 ] || /bin/mkdir -p ${DIR}/man/man8

/usr/bin/install -s -m 555 ./src/sbin/hammer2/hammer2 ${DIR}/sbin
/usr/bin/install -s -m 555 ./src/sbin/newfs_hammer2/newfs_hammer2 ${DIR}/sbin
/usr/bin/install -s -m 555 ./src/sbin/mount_hammer2/mount_hammer2 ${DIR}/sbin
/usr/bin/install -s -m 555 ./src/sbin/fsck_hammer2/fsck_hammer2 ${DIR}/sbin

/usr/bin/install -m 444 ./src/sbin/hammer2/hammer2.8 ${DIR}/man/man8
/usr/bin/install -m 444 ./src/sbin/newfs_hammer2/newfs_hammer2.8 ${DIR}/man/man8
/usr/bin/install -m 444 ./src/sbin/mount_hammer2/mount_hammer2.8 ${DIR}/man/man8
/usr/bin/install -m 444 ./src/sbin/fsck_hammer2/fsck_hammer2.8 ${DIR}/man/man8

/usr/bin/strip --strip-debug ${DIR}/sbin/hammer2
/usr/bin/strip --strip-debug ${DIR}/sbin/newfs_hammer2
/usr/bin/strip --strip-debug ${DIR}/sbin/mount_hammer2
/usr/bin/strip --strip-debug ${DIR}/sbin/fsck_hammer2

echo "install success"

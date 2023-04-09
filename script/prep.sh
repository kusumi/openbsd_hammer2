#!/usr/local/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=`pwd`
fi

[ -d ${DIR} ] || exit 1
[ -d /usr/src/sys ] || exit 1

HAMMER2_DIR=${DIR}/src/sys/fs/hammer2
if [ ! -d ${HAMMER2_DIR} ]; then
	echo "${HAMMER2_DIR} does not exist"
	exit 1
fi

HAMMER2_LNK=/usr/src/sys/hammer2
if [ -e ${HAMMER2_LNK} ]; then
	echo "${HAMMER2_LNK} already exists"
	exit 1
fi

ICRC32_REG=${DIR}/src/sys/libkern/icrc32.c
if [ ! -f ${ICRC32_REG} ]; then
	echo "${ICRC32_REG} does not exist"
	exit 1
fi

ICRC32_LNK=/usr/src/sys/lib/libkern/icrc32.c
if [ -e ${ICRC32_LNK} ]; then
	echo "${ICRC32_LNK} already exists"
	exit 1
fi

/bin/ln -s ${HAMMER2_DIR} ${HAMMER2_LNK}
/bin/ln -s ${ICRC32_REG} ${ICRC32_LNK}

/bin/ls -l ${HAMMER2_LNK}
/bin/ls -l ${ICRC32_LNK}

echo "prep success"

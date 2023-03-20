#!/usr/local/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=`pwd`
fi

[ -d /usr/src/sys ] || exit 1
[ -d ${DIR} ] || exit 1

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

/bin/ln -s ${HAMMER2_DIR} ${HAMMER2_LNK}
/bin/ls -l ${HAMMER2_LNK}

echo "prep success"

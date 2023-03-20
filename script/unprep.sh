#!/usr/local/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=`pwd`
fi

[ -d /usr/src/sys ] || exit 1
[ -d ${DIR} ] || exit 1

HAMMER2_LNK=/usr/src/sys/hammer2
if [ ! -e ${HAMMER2_LNK} ]; then
	echo "${HAMMER2_LNK} does not exist"
	exit 1
fi

/bin/rm ${HAMMER2_LNK}

echo "unprep success"

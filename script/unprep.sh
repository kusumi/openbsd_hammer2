#!/usr/local/bin/bash

set -e

[ -d /usr/src/sys ] || exit 1

HAMMER2_LNK=/usr/src/sys/hammer2
if [ ! -e ${HAMMER2_LNK} ]; then
	echo "${HAMMER2_LNK} does not exist"
	exit 1
fi

ICRC32_LNK=/usr/src/sys/lib/libkern/icrc32.c
if [ ! -e ${ICRC32_LNK} ]; then
	echo "${ICRC32_LNK} does not exist"
	exit 1
fi

/bin/rm ${HAMMER2_LNK}
/bin/rm ${ICRC32_LNK}

echo "unprep success"

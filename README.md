OpenBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## Requirements

+ OpenBSD 7.6

+ src tree under /usr/src

## OpenBSD build

        $ cd /path/to/openbsd_hammer2
        $ make prep
        $ cd /usr/src
        $ patch -p1 < /path/to/openbsd_hammer2/patch/openbsd76.patch
        $ <build src>

## Build

        $ cd openbsd_hammer2
        $ make

## Install

        $ cd openbsd_hammer2
        $ make install

## Uninstall

        $ cd openbsd_hammer2
        $ make uninstall

## Bugs

+ VOP\_READDIR implementation is known to not work with some user space libraries on 32 bit platforms.

## Notes

+ This repository will be abandoned once Linux or FreeBSD is stabilized with write support. OpenBSD is not the main area of interest.

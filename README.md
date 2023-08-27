OpenBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for OpenBSD (currently read-only support)

## Requirements

+ OpenBSD 7.3

+ OpenBSD 7.3 src tree under /usr/src

+ Bash

## OpenBSD build

1. Apply [patch/openbsd73.patch](patch/openbsd73.patch) against /usr/src.

2. Run *make prep* to create symlinks under /usr/src/sys which point to this repository. Run *make unprep* to undo.

        $ cd openbsd_hammer2
        $ make prep

3. Build and install /usr/src/sys.

4. Build and install /usr/src/sbin/sysctl.

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

+ VOP_READDIR implementation is known to not work with some user space libraries on 32 bit platforms.

## Notes

+ Tags are merely for packaging, nothing directly to do with file system version.

+ [makefs](https://github.com/kusumi/makefs) supports HAMMER2 image creation from a directory contents.

+ This repository will be abandoned once Linux or FreeBSD is stabilized with write support. OpenBSD is not the main target.

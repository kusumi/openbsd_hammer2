OpenBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for OpenBSD (read-only support)

+ OpenBSD version of https://github.com/kusumi/netbsd_hammer2

## Requirements

+ Recent OpenBSD

    + Compiles and tested with OpenBSD 7.2

    + Never compiled or tested with other releses or -CURRENT

+ OpenBSD src tree under /usr/src

+ Bash

## Build

        $ cd openbsd_hammer2
        $ make

## Install

        $ cd openbsd_hammer2
        $ make install

## Uninstall

        $ cd openbsd_hammer2
        $ make uninstall

## OpenBSD kernel build

+ Apply [patch/openbsd72.patch](patch/openbsd72.patch) or equivalent diff against /usr/src.

+ Run *make prep* to create a symlink under /usr/src/sys which points to this repository. Run *make unprep* to undo.

        $ cd openbsd_hammer2
        $ make prep

+ Build and install /usr/src/sys.

## Notes

+ Only read-only support is planned for OpenBSD.

+ Tags are merely for packaging, nothing directly to do with file system version.

+ [makefs(8) for Linux](https://github.com/kusumi/makefs) supports HAMMER2 image creation from a directory contents on Linux. There is currently no way to do this on OpenBSD.

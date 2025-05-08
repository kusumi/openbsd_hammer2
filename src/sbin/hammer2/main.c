/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2019 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 * by Venkatesh Srinivas <vsrinivas@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * XXX HAMMER2 userspace consists of sbin/{hammer2,newfs_hammer2,
 * mount_hammer2,fsck_hammer2}.  These are mostly portable, so avoid
 * non functional changes in the name of cleanup.
 */

#include "hammer2.h"

int VerboseOpt;
int QuietOpt;
int RecurseOpt;
size_t MemOpt;

static void usage(int code);

int
main(int ac, char **av)
{
	char *sel_path = NULL;
	const char *uuid_str = NULL;
	char *opt;
	int pfs_type = HAMMER2_PFSTYPE_NONE;
	int ecode = 0;
	int ch;

	/*
	 * Core options
	 */
	while ((ch = getopt(ac, av, "m:rs:t:u:vq")) != -1) {
		switch(ch) {
		case 'm':
			MemOpt = strtoul(optarg, &opt, 0);
			switch(*opt) {
			case 'g':
			case 'G':
				MemOpt *= 1024;
				/* FALLTHROUGH */
			case 'm':
			case 'M':
				MemOpt *= 1024;
				/* FALLTHROUGH */
			case 'k':
			case 'K':
				MemOpt *= 1024;
				break;
			case 0:
				break;
			default:
				fprintf(stderr, "-m: Unrecognized suffix\n");
				usage(1);
				break;
			}
			break;
		case 'r':
			RecurseOpt = 1;
			break;
		case 's':
			sel_path = strdup(optarg);
			break;
		case 't':
			/*
			 * set node type for pfs-create
			 */
			if (strcasecmp(optarg, "CACHE") == 0) {
				pfs_type = HAMMER2_PFSTYPE_CACHE;
			} else if (strcasecmp(optarg, "DUMMY") == 0) {
				pfs_type = HAMMER2_PFSTYPE_DUMMY;
			} else if (strcasecmp(optarg, "SLAVE") == 0) {
				pfs_type = HAMMER2_PFSTYPE_SLAVE;
			} else if (strcasecmp(optarg, "SOFT_SLAVE") == 0) {
				pfs_type = HAMMER2_PFSTYPE_SOFT_SLAVE;
			} else if (strcasecmp(optarg, "SOFT_MASTER") == 0) {
				pfs_type = HAMMER2_PFSTYPE_SOFT_MASTER;
			} else if (strcasecmp(optarg, "MASTER") == 0) {
				pfs_type = HAMMER2_PFSTYPE_MASTER;
			} else {
				fprintf(stderr, "-t: Unrecognized node type\n");
				usage(1);
			}
			break;
		case 'u':
			/*
			 * set uuid for pfs-create, else one will be generated
			 * (required for all except the MASTER node_type)
			 */
			uuid_str = optarg;
			break;
		case 'v':
			if (QuietOpt)
				--QuietOpt;
			else
				++VerboseOpt;
			break;
		case 'q':
			if (VerboseOpt)
				--VerboseOpt;
			else
				++QuietOpt;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", ch);
			usage(1);
			/* not reached */
			break;
		}
	}

	/*
	 * Adjust, then process the command
	 */
	ac -= optind;
	av += optind;
	if (ac < 1) {
		fprintf(stderr, "Missing command\n");
		usage(1);
		/* not reached */
	}

	if (strcmp(av[0], "dumpchain") == 0) {
		if (ac < 2)
			ecode = cmd_dumpchain(".", (u_int)-1);
		else if (ac < 3)
			ecode = cmd_dumpchain(av[1], (u_int)-1);
		else
			ecode = cmd_dumpchain(av[1],
					      (u_int)strtoul(av[2], NULL, 0));
	} else if (strcmp(av[0], "destroy") == 0) {
		if (ac < 2) {
			fprintf(stderr,
				"destroy: specify one or more paths to "
				"destroy\n");
			usage(1);
		}
		ecode = cmd_destroy_path(ac - 1, (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "destroy-inum") == 0) {
		if (ac < 2) {
			fprintf(stderr,
				"destroy-inum: specify one or more inode "
				"numbers to destroy\n");
			usage(1);
		}
		ecode = cmd_destroy_inum(sel_path, ac - 1,
					 (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "emergency-mode-enable") == 0) {
		ecode = cmd_emergency_mode(sel_path, 1, ac - 1,
					 (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "emergency-mode-disable") == 0) {
		ecode = cmd_emergency_mode(sel_path, 0, ac - 1,
					 (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "growfs") == 0) {
		ecode = cmd_growfs(sel_path, ac - 1,
					 (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "hash") == 0) {
		ecode = cmd_hash(ac - 1, (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "dhash") == 0) {
		ecode = cmd_dhash(ac - 1, (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "pfs-clid") == 0) {
		/*
		 * Print cluster id (uuid) for specific PFS
		 */
		if (ac < 2) {
			fprintf(stderr, "pfs-clid: requires name\n");
			usage(1);
		}
		ecode = cmd_pfs_getid(sel_path, av[1], 0);
	} else if (strcmp(av[0], "pfs-fsid") == 0) {
		/*
		 * Print private id (uuid) for specific PFS
		 */
		if (ac < 2) {
			fprintf(stderr, "pfs-fsid: requires name\n");
			usage(1);
		}
		ecode = cmd_pfs_getid(sel_path, av[1], 1);
	} else if (strcmp(av[0], "pfs-list") == 0) {
		/*
		 * List all PFSs
		 */
		if (ac >= 2) {
			ecode = cmd_pfs_list(ac - 1,
					     (char **)(void *)&av[1]);
		} else {
			ecode = cmd_pfs_list(1, &sel_path);
		}
	} else if (strcmp(av[0], "pfs-create") == 0) {
		/*
		 * Create new PFS using pfs_type
		 */
		if (ac < 2) {
			fprintf(stderr, "pfs-create: requires name\n");
			usage(1);
		}
		ecode = cmd_pfs_create(sel_path, av[1], pfs_type, uuid_str);
	} else if (strcmp(av[0], "pfs-delete") == 0) {
		/*
		 * Delete a PFS by name
		 */
		if (ac < 2) {
			fprintf(stderr, "pfs-delete: requires name\n");
			usage(1);
		}
		ecode = cmd_pfs_delete(sel_path, av, ac);
	} else if (strcmp(av[0], "recover") == 0 ||
		   strcmp(av[0], "recover-relaxed") == 0 ||
		   strcmp(av[0], "recover-file") == 0) {
		/*
		 * Recover a relative path (unanchored match), absolute path,
		 * specific file, or directory sub-tree.  File restorals are
		 * fully validated.
		 */
		if (ac != 4) {
			fprintf(stderr, "recover device [/]path destdir\n");
			usage(1);
		} else {
			int strict = (strcmp(av[0], "recover-relaxed") != 0);
			int isafile = (strcmp(av[0], "recover-file") == 0);
			cmd_recover(av[1], av[2], av[3], strict, isafile);
		}
	} else if (strcmp(av[0], "snapshot") == 0 ||
		   strcmp(av[0], "snapshot-debug") == 0) {
		/*
		 * Create snapshot with optional pfs-type and optional
		 * label override.
		 */
		uint32_t flags = 0;

		if (strcmp(av[0], "snapshot-debug") == 0)
			flags = HAMMER2_PFSFLAGS_NOSYNC;

		if (ac > 3) {
			fprintf(stderr, "%s: too many arguments\n", av[0]);
			usage(1);
		}
		switch(ac) {
		case 1:
			ecode = cmd_pfs_snapshot(sel_path, NULL, NULL, flags);
			break;
		case 2:
			ecode = cmd_pfs_snapshot(sel_path, av[1], NULL, flags);
			break;
		case 3:
			ecode = cmd_pfs_snapshot(sel_path, av[1], av[2], flags);
			break;
		}
	} else if (strcmp(av[0], "stat") == 0) {
		ecode = cmd_stat(ac - 1, (const char **)(void *)&av[1]);
	} else if (strcmp(av[0], "show") == 0) {
		/*
		 * Raw dump of filesystem.  Use -v to check all crc's, and
		 * -vv to dump bulk file data.
		 */
		if (ac != 2) {
			fprintf(stderr, "show: requires device path\n");
			usage(1);
		} else {
			cmd_show(av[1], 0);
		}
	} else if (strcmp(av[0], "freemap") == 0) {
		/*
		 * Raw dump of freemap.  Use -v to check all crc's, and
		 * -vv to dump bulk file data.
		 */
		if (ac != 2) {
			fprintf(stderr, "freemap: requires device path\n");
			usage(1);
		} else {
			cmd_show(av[1], 1);
		}
	} else if (strcmp(av[0], "volhdr") == 0) {
		/*
		 * Dump the volume header.
		 */
		if (ac != 2) {
			fprintf(stderr, "volhdr: requires device path\n");
			usage(1);
		} else {
			cmd_show(av[1], 2);
		}
	} else if (strcmp(av[0], "volume-list") == 0) {
		/*
		 * List all volumes
		 */
		int argc;
		char **argv;
		if (ac >= 2) {
			argc = ac - 1;
			argv = (char **)(void *)&av[1];
		} else {
			argc = 1;
			argv = &sel_path;
		}
		ecode = is_supported_volume_list(argv[0]);
		switch (ecode) {
		case 1:
			ecode = cmd_volume_list(argc, argv);
			break;
		case 0:
			ecode = cmd_volume_list2(argc, argv);
			break;
		default:
			break;
		}
	} else if (strcmp(av[0], "setcomp") == 0) {
		if (ac < 3) {
			/*
			 * Missing compression method and at least one
			 * path.
			 */
			fprintf(stderr,
				"setcomp: requires compression method and "
				"directory/file path\n");
			usage(1);
		} else {
			/*
			 * Multiple paths may be specified
			 */
			ecode = cmd_setcomp(av[1], &av[2]);
		}
	} else if (strcmp(av[0], "setcheck") == 0) {
		if (ac < 3) {
			/*
			 * Missing compression method and at least one
			 * path.
			 */
			fprintf(stderr,
				"setcheck: requires check code method and "
				"directory/file path\n");
			usage(1);
		} else {
			/*
			 * Multiple paths may be specified
			 */
			ecode = cmd_setcheck(av[1], &av[2]);
		}
	} else if (strcmp(av[0], "clrcheck") == 0) {
		ecode = cmd_setcheck("none", &av[1]);
	} else if (strcmp(av[0], "setcrc32") == 0) {
		ecode = cmd_setcheck("crc32", &av[1]);
	} else if (strcmp(av[0], "setxxhash64") == 0) {
		ecode = cmd_setcheck("xxhash64", &av[1]);
	} else if (strcmp(av[0], "setsha192") == 0) {
		ecode = cmd_setcheck("sha192", &av[1]);
	} else if (strcmp(av[0], "printinode") == 0) {
		if (ac != 2) {
			fprintf(stderr,
				"printinode: requires directory/file path\n");
			usage(1);
		} else {
			print_inode(av[1]);
		}
	} else if (strcmp(av[0], "bulkfree") == 0) {
		if (ac != 2) {
			fprintf(stderr, "bulkfree: requires path to mount\n");
			usage(1);
		} else {
			ecode = cmd_bulkfree(av[1]);
		}
	} else if (strcmp(av[0], "cleanup") == 0) {
		ecode = cmd_cleanup(av[1]);	/* can be NULL */
	} else {
		fprintf(stderr, "Unrecognized command: %s\n", av[0]);
		usage(1);
	}

	return (ecode);
}

static
void
usage(int code)
{
	fprintf(stderr,
		"hammer2 [options] command [argument ...]\n"
		"    -s path            Select filesystem\n"
		"    -t type            PFS type for pfs-create\n"
		"    -u uuid            uuid for pfs-create\n"
		"    -m mem[k,m,g]      buffer memory (bulkfree)\n"
		"\n"
		"    cleanup [<path>]                  "
			"Run cleanup passes\n"
		"    destroy <path>...                 "
			"Destroy directory entries (only use if inode bad)\n"
		"    destroy-inum <inum>...            "
			"Destroy inodes (only use if inode bad)\n"
		"    emergency-mode-enable <target>    "
			"Enable emergency operations mode on filesystem\n"
		"                                      "
			"THIS IS A VERY DANGEROUS MODE\n"
		"    emergency-mode-disable <target>   "
			"Disable emergency operations mode on filesystem\n"
		"    hash [<filename>...]              "
			"Print directory hash (key) for name\n"
		"    dhash [<filename>...]             "
			"Print data hash for long directory entry\n"
		"    pfs-list [<path>...]              "
			"List PFSs\n"
		"    pfs-clid <label>                  "
			"Print cluster id for specific PFS\n"
		"    pfs-fsid <label>                  "
			"Print private id for specific PFS\n"
		"    pfs-create <label>                "
			"Create a PFS\n"
		"    pfs-delete <label>                "
			"Destroy a PFS\n"
		"    recover <devpath> <path> <destdir> "
			"Recover deleted or corrupt files or trees\n"
		"    recover-relaxed <devpath> <path> <destdir> "
			"Recover deleted or corrupt files or trees\n"
		"    recover-file <devpath> <path> <destdir> "
			"Recover, target is explicitly a regular file\n"
		"    snapshot <path> [<label>]         "
			"Snapshot a PFS or directory\n"
		"    snapshot-debug <path> [<label>]   "
			"Snapshot without filesystem sync\n"
		"    stat [<path>...]                  "
			"Return inode quota & config\n"
		"    growfs [<path>...]                "
			"Grow a filesystem into resized partition\n"
		"    show <devpath>                    "
			"Raw hammer2 media dump for topology\n"
		"    freemap <devpath>                 "
			"Raw hammer2 media dump for freemap\n"
		"    volhdr <devpath>                  "
			"Raw hammer2 media dump for the volume header(s)\n"
		"    volume-list [<path>...]           "
			"List volumes\n"
		"    setcomp <comp[:level]> <path>...  "
			"Set comp algo {none, autozero, lz4, zlib} & level\n"
		"    setcheck <check> <path>...        "
			"Set check algo {none, crc32, xxhash64, sha192}\n"
		"    clrcheck [<path>...]              "
			"Clear check code override\n"
		"    setcrc32 [<path>...]              "
			"Set check algo to crc32\n"
		"    setxxhash64 [<path>...]           "
			"Set check algo to xxhash64\n"
		"    setsha192 [<path>...]             "
			"Set check algo to sha192\n"
		"    bulkfree <path>                   "
			"Run bulkfree pass\n"
		"    printinode <path>                 "
			"Dump inode\n"
		"    dumpchain [<path> [<chnflags>]]   "
			"Dump in-memory chain topology\n"
	);
	exit(code);
}

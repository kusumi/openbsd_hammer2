/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2013 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
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

#include "hammer2.h"

static int cmd_setcomp_core(uint8_t comp_algo, const char *path_str,
			    struct stat *st);

int
cmd_setcomp(const char *comp_str, char **paths)
{
	static const char *comps[] = HAMMER2_COMP_STRINGS;
	struct stat st;
	int comp_algo;
	int comp_level;
	int ecode;
	int res;
	char *str;
	const char *s1;
	const char *s2;

	str = strdup(comp_str);
	s1 = strtok(str, ":");
	s2 = s1 ? strtok(NULL, ":") : NULL;
	ecode = 0;

	if (isdigit((int)s1[0])) {
		comp_algo = strtol(s1, NULL, 0);
	} else {
		comp_algo = HAMMER2_COMP_STRINGS_COUNT;
		while (--comp_algo >= 0) {
			if (strcasecmp(s1, comps[comp_algo]) == 0)
				break;
		}
		if (comp_algo < 0 && strcasecmp(s1, "default") == 0) {
			comp_algo = HAMMER2_COMP_LZ4;
			s1 = "lz4";
		}
		if (comp_algo < 0 && strcasecmp(s1, "disabled") == 0) {
			comp_algo = HAMMER2_COMP_AUTOZERO;
			s1 = "autozero";
		}
		if (comp_algo < 0) {
			fprintf(stderr, "Unknown compression type: %s\n", s1);
			ecode = 3;
		}
	}
	if (s2 == NULL) {
		comp_level = 0;
	} else if (isdigit((int)s2[0])) {
		comp_level = strtol(s2, NULL, 0);
	} else if (strcasecmp(s2, "default") == 0) {
		comp_level = 0;
	} else {
		comp_level = 0;
		fprintf(stderr, "Unknown compression level: %s\n", s2);
		ecode = 3;
	}

	if (comp_level) {
		switch(comp_algo) {
		case HAMMER2_COMP_ZLIB:
			if (comp_level < 6 || comp_level > 9) {
				fprintf(stderr,
					"Unsupported comp_level %d for %s\n",
					comp_level, s1);
				ecode = 3;
			}
			break;
		default:
			fprintf(stderr,
				"Unsupported comp_level %d for %s\n",
				comp_level, s1);
			ecode = 3;
		}
	}

	if (ecode == 0) {
		while (*paths) {
			if (lstat(*paths, &st) == 0) {
				res = cmd_setcomp_core(
					HAMMER2_ENC_ALGO(comp_algo) |
					 HAMMER2_ENC_LEVEL(comp_level),
				        *paths,
					&st);
				if (res)
					ecode = res;
			} else {
				printf("%s: %s\n", *paths, strerror(errno));
				ecode = 3;
			}
			++paths;
		}
	}
	free (str);

	return ecode;
}

static int
cmd_setcomp_core(uint8_t comp_algo, const char *path_str, struct stat *st)
{
	hammer2_ioc_inode_t inode;
	int fd;
	int res;

	fd = hammer2_ioctl_handle(path_str);
	if (fd < 0) {
		res = 3;
		goto failed;
	}
	res = ioctl(fd, HAMMER2IOC_INODE_GET, &inode);
	if (res < 0) {
		fprintf(stderr,
			"%s: HAMMER2IOC_INODE_GET: error %s\n",
			path_str, strerror(errno));
		res = 3;
		goto failed;
	}
	printf("%s\tcomp_algo=0x%02x\n", path_str, comp_algo);
	inode.flags |= HAMMER2IOC_INODE_FLAG_COMP;
	inode.ip_data.meta.comp_algo = comp_algo;
	res = ioctl(fd, HAMMER2IOC_INODE_SET, &inode);
	if (res < 0) {
		fprintf(stderr,
			"%s: HAMMER2IOC_INODE_SET: error %s\n",
			path_str, strerror(errno));
		res = 3;
		goto failed;
	}
	res = 0;

	if (RecurseOpt && S_ISDIR(st->st_mode)) {
		DIR *dir;
		char *path;
		struct dirent *den;

		if ((dir = fdopendir(fd)) != NULL) {
			while ((den = readdir(dir)) != NULL) {
				if (strcmp(den->d_name, ".") == 0 ||
				    strcmp(den->d_name, "..") == 0) {
					continue;
				}
				asprintf(&path, "%s/%s", path_str, den->d_name);
				if (lstat(path, st) == 0)
					cmd_setcomp_core(comp_algo, path, st);
				free(path);
			}
			closedir(dir);
		}
	}
failed:
	close(fd);
	return res;
}

/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef _LIBFS_H
#define _LIBFS_H

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include "userconfig.h"

typedef enum { error = -3, not_found, no_access, no, yes } t_fsbool;

typedef struct type_filelist {
	char   *name;
	off_t  size;
	time_t time;
	bool   is_dir;

	struct type_filelist *next;
} t_filelist;

off_t filesize(char *filename);
char *make_path(char *dir, char *file);
t_fsbool contains_not_allowed_symlink(char *filename, char *webroot);
t_fsbool is_directory(char *file);
t_fsbool can_execute(char *file, uid_t uid, gid_t gid, t_groups *groups);
void touch_logfile(char *logfile, mode_t mode, uid_t uid, gid_t gid);
int  if_modified_since(int handle, char *datestr);
FILE *fopen_neighbour(char *filename, char *mode, char *neighbour);
t_filelist *read_filelist(char *directory);
t_filelist *sort_filelist(t_filelist *filelist);
void remove_filelist(t_filelist *filelist);
int write_buffer(int handle, const char *buffer, int size);
#ifdef CYGWIN
char *cygwin_to_windows(char *path);
#endif

#endif

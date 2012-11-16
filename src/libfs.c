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

#include "config.h"
#include <sys/types.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "libfs.h"
#include "libstr.h"

static char *months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/* Return the size of a file.
 */
off_t filesize(char *filename) {
	struct stat status;

	if (filename == NULL) {
		return -1;
	} else if (stat(filename, &status) == 0) {
		return status.st_size;
	} else {
		return -1;
	}
}

/* Combine two strings to one with a '/' in the middle.
 */
char *make_path(char *dir, char *file) {
	int dir_len, file_len;
	char *path;

	if ((dir == NULL) || (file == NULL)) {
		return NULL;
	}

	dir_len = strlen(dir);
	file_len = strlen(file);

	if ((path = (char*)malloc(dir_len + file_len + 2)) != NULL) {
		memcpy(path, dir, dir_len);
		path[dir_len] = '/';
		memcpy(path + dir_len + 1, file, file_len);
		path[dir_len + 1 + file_len] = '\0';
	}

	return path;
}

static t_fsbool outside_webroot(char *symlink, char *webroot) {
	char filename[257], *slash;
	int size, count;

	if ((symlink == NULL) || (webroot == NULL)) {
		return error;
	}

	if ((size = readlink(symlink, filename, 256)) > 0) {
		filename[size] = '\0';
		if (strchr(filename, '/') == NULL) {
			return no;
		}
		if (filename[0] == '/') {
			/* Symlink with complete path */
			if (strncmp(webroot, filename, strlen(webroot)) == 0) {
				return no;
			}
		} else if (strncmp(filename, "../", 3) == 0) {
			/* Symlink that starts wih ../ */
			count = 0;
			while (strncmp(filename + (3 * count), "../", 3) == 0) {
				count++;
			}
			slash = symlink + strlen(symlink);
			while (count-- > 0) {
				while ((slash > symlink) && (*slash != '/')) {
					slash--;
				}
				if (slash == symlink) {
					break;
				} else {
					slash--;
				}
			}
			if ((size_t)(slash - symlink) >= strlen(webroot)) {
				return no;
			}
		}
	} else switch (errno) {
		case EACCES:
			return no_access;
		case ENOENT:
			return not_found;
		default:
			return error;
	}

	return yes;
}

t_fsbool contains_not_allowed_symlink(char *filename, char *webroot) {
	t_fsbool contains = no, outside;
	struct stat status;
	char *slash;

	if ((filename == NULL) || (webroot == NULL)) {
		return error;
	}

	if (lstat(filename, &status) == -1) {
		switch (errno) {
			case EACCES:
				return no_access;
			case ENOENT:
				return not_found;
			default:
				return error;
		}
	} else if (((status.st_mode & S_IFMT) == S_IFLNK) && (status.st_uid != 0)) {
		if ((outside = outside_webroot(filename, webroot)) != no) {
			return outside;
		}
	}

	slash = filename + strlen(filename);
	while ((slash != filename) && (*slash != '/')) {
		slash--;
	}
	if (slash != filename) {
		*slash = '\0';
		contains = contains_not_allowed_symlink(filename, webroot);
		*slash = '/';
	}

	return contains;
}

/* Check whether a file is directory or not.
 */
t_fsbool is_directory(char *file) {
	DIR *dp;

	if (file == NULL) {
		return error;
	} else if ((dp = opendir(file)) != NULL) {
		closedir(dp);
		return yes;
	} else switch (errno) {
		case EACCES:
			return no_access;
		case ENOENT:
			return not_found;
		case ENOTDIR:
			return no;
		default:
			return error;
	}
}

/* Check whether a file can be executed or not.
 */
t_fsbool can_execute(char *file, uid_t uid, gid_t gid, t_groups *groups) {
	struct stat status;
	gid_t *group;
	int num = 0;

	if ((file == NULL) || (groups == NULL)) {
		return error;
	}

	if (stat(file, &status) == 0) {
		if (status.st_uid == uid) {
			/* Check user */
			if ((status.st_mode & S_IXUSR) == S_IXUSR) {
				return yes;
			} else {
				return no;
			}
		} else {
			/* Check group */
			if (status.st_gid == gid) {
				if ((status.st_mode & S_IXGRP) == S_IXGRP) {
					return yes;
				} else {
					return no;
				}
			} else if (groups != NULL) {
				group = groups->array;
				while (num < groups->number) {
					if (status.st_gid == *group) {
						if ((status.st_mode & S_IXGRP) == S_IXGRP) {
							return yes;
						} else {
							return no;
						}
					}
					group++;
					num++;
				}
			}

			/* Check others */
			if ((status.st_mode & S_IXOTH) == S_IXOTH) {
				return yes;
			} else {
				return no;
			}
		}
	} else switch (errno) {
		case EACCES:
			return no_access;
		case ENOENT:
			return not_found;
		default:
			return error;
	}
}

/* Create a file with the right ownership and accessrights.
 */
void touch_logfile(char *logfile, mode_t mode, uid_t uid, gid_t gid) {
	int fd;

	if (logfile == NULL) {
		return;
	}

	if ((fd = open(logfile, O_RDONLY)) != -1) {
		close(fd);
		return;
	}

	if ((fd = open(logfile, O_CREAT|O_APPEND, mode)) == -1) {
		fprintf(stderr, "Warning: couldn't create logfile %s\n", logfile);
		return;
	}

	if (getuid() == 0) {
		if (fchown(fd, uid, gid) == -1) {
			fprintf(stderr, "Warning: couldn't chown logfile %s\n", logfile);
		}
	}

	close(fd);
}

/* Month number to month name.
 */
static short month2int(char *month) {
	int i;

	if (month != NULL) {
		for (i = 0; i < 12; i++) {
			if (memcmp(month, months[i], 3) == 0) {
				return i;
			}
		}
	}

	return -1;
}

/* Parse a RFC 822 datestring.
 *
 * 0    5  8   12   17       26
 * Day, dd Mon yyyy hh:mm:ss GMT
 */
static int parse_datestr(char *org_datestr, struct tm *date) {
	int result = -1;
	char *datestr;

	if ((org_datestr == NULL) || (date == NULL)) {
		return -1;
	} else if (strlen(org_datestr) != 29) {
		return -1;
	} else if ((datestr = strdup(org_datestr)) == NULL) {
		return -1;
	}

	do {
		if (memcmp(datestr + 3, ", ", 2) != 0) {
			break;
		} else if ((*(datestr + 7) != ' ') || (*(datestr + 11) != ' ') || (*(datestr + 16) != ' ')) {
			break;
		} else if ((*(datestr + 19) != ':') || (*(datestr + 22) != ':')) {
			break;
		} else if (memcmp(datestr + 25, " GMT", 4) != 0) {
			break;
		}

		*(datestr + 7) = *(datestr + 11) = *(datestr + 16) = *(datestr + 19) = *(datestr + 22) = *(datestr + 25) = '\0';
		if ((*datestr + 5) == ' ') {
			*(datestr + 5) = '0';
		}

		if ((date->tm_mday = str2int(datestr + 5)) <= 0) {
			break;
		} else if ((date->tm_mon = month2int(datestr + 8)) == -1) {
			break;
		} else if ((date->tm_year = str2int(datestr + 12)) < 1900) {
			break;
		} else if ((date->tm_hour = str2int(datestr + 17)) == -1) {
			break;
		} else if ((date->tm_min = str2int(datestr + 20)) == -1) {
			break;
		} else if ((date->tm_sec = str2int(datestr + 23)) == -1) {
			break;
		}

		if (date->tm_mday > 31) {
			break;
		} else if (date->tm_hour > 23) {
			break;
		} else if (date->tm_min > 59) {
			break;
		} else if (date->tm_sec > 59) {
			break;
		}

		date->tm_year -= 1900;
		date->tm_isdst = 0;

		result = 0;
	} while (false);

	free(datestr);

	return result;
}

/* Check wheter a file has been modified since a certain date or not.
 */
int if_modified_since(int handle, char *datestr) {
	struct stat status;
	struct tm *fdate, rdate;
	time_t file_date, req_date;

	if (datestr == NULL) {
		return -1;
	} else if (fstat(handle, &status) == -1) {
		return -1;
	} else if ((fdate = gmtime(&(status.st_mtime))) == NULL) {
		return -1;
	} else if ((file_date = mktime(fdate)) == -1) {
		return -1;
	} else if (parse_datestr(datestr, &rdate) == -1) {
		return -1;
	} else if ((req_date = mktime(&rdate)) == -1) {
		return -1;
	} else if (file_date > req_date) {
		return 1;
	}

	return 0;
}

/* Open a file (searches in directory where file 'neighbour' is located if not found).
 */
FILE *fopen_neighbour(char *filename, char *mode, char *neighbour) {
	FILE *fp;
	char *file, *slash;
	int len;

	if ((filename == NULL) || (mode == NULL)) {
		return NULL;
	}

	if ((fp = fopen(filename, mode)) != NULL) {
		return fp;
	} else if ((errno != ENOENT) || (neighbour == NULL)) {
		return NULL;
	}

	if ((slash = strrchr(neighbour, '/')) == NULL) {
		return NULL;
	}

	len = slash - neighbour + 1;
	if ((file = (char*)malloc(len + strlen(filename) + 1)) == NULL) {
		return NULL;
	}

	memcpy(file, neighbour, len);
	strcpy(file + len, filename);
	fp = fopen(file, mode);
	free(file);

	return fp;
}

/*-----< filelist functions >-------------------------------------------------*/

/* Read a directory and place the filenames in a list.
 */
t_filelist *read_filelist(char *directory) {
	DIR *dp;
	t_filelist *filelist = NULL, *file;
	char *filename;
	int stat_status;
	struct stat status;
	struct dirent *dir_info;

	if (directory == NULL) {
		return NULL;
	} else if ((dp = opendir(directory)) == NULL) {
		return NULL;
	}

	while ((dir_info = readdir(dp)) != NULL) {
		if ((dir_info->d_name[0] != '.') || (strcmp(dir_info->d_name, "..") == 0)) {
			if ((filename = make_path(directory, dir_info->d_name)) == NULL) {
				remove_filelist(filelist);
				filelist = NULL;
				break;
			}
			stat_status = stat(filename, &status);
			free(filename);
			if (stat_status == -1) {
				continue;
			}

			if ((file = (t_filelist*)malloc(sizeof(t_filelist))) == NULL) {
				remove_filelist(filelist);
				filelist = NULL;
				break;
			} else if ((file->name = strdup(dir_info->d_name)) == NULL) {
				free(file);
				remove_filelist(filelist);
				filelist = NULL;
				break;
			} else {
				file->size = status.st_size;
				file->time = status.st_mtime;
				file->is_dir = S_ISDIR(status.st_mode);
				file->next = filelist;
			}
			filelist = file;
		}
	}
	closedir(dp);

	return filelist;
}

/* Sort a list of filenames alfabeticly.
 */
t_filelist *sort_filelist(t_filelist *filelist) {
	t_filelist *start = NULL, *newpos, *prev, *newitem;

	while (filelist != NULL) {
		newitem = filelist;
		filelist = filelist->next;

		prev = NULL;
		newpos = start;
		while (newpos != NULL) {
			if (newitem->is_dir && (newpos->is_dir == false)) {
				break;
			}
			if (newitem->is_dir == newpos->is_dir) {
				if (strcmp(newpos->name, newitem->name) >= 0) {
					break;
				}
			}
			prev = newpos;
			newpos = newpos->next;
		}

		if (prev == NULL) {
			newitem->next = start;
			start = newitem;
		} else {
			prev->next = newitem;
			newitem->next = newpos;
		}
	}

	return start;
}

/* free() a list of filenames.
 */
void remove_filelist(t_filelist *filelist) {
	t_filelist *file;

	while (filelist != NULL) {
		file = filelist;
		filelist = filelist->next;
		if (file->name != NULL) {
			free(file->name);
		}
		free(file);
	}
}

/* Send buffer to handle
 */
int write_buffer(int handle, const char *buffer, int size) {
	long total_written = 0;
	ssize_t bytes_written;

	if (size <= 0) {
		return 0;
	} else while (total_written < size) {
		if ((bytes_written = write(handle, buffer + total_written, size - total_written)) == -1) {
			if (errno != EINTR) {
				return -1;
			}
		} else {
			total_written += bytes_written;
		}
	}

	return 0;
}

#ifdef CYGWIN
char *cygwin_to_windows(char *path) {
	char *slash;

	if (path == NULL) {
		return NULL;
	}

	if (strncmp(path, "/cygdrive/", 10) != 0) {
		return path;
	}
	if (*(path + 10) == '\0') {
		return path;
	}
	if (*(path + 11) != '/') {
		return path;
	}

	path += 9;
	*path = *(path + 1);
	*(path + 1) = ':';

	slash = path;
	while (*slash != '\0') {
		if (*slash == '/') {
			*slash = '\\';
		}
		slash++;
	}

	return path;
}
#endif

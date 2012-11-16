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

#ifdef ENABLE_CACHE

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include "libfs.h"
#include "libip.h"
#include "session.h"
#include "cache.h"

#define MAX_CACHE_INDEX 250

extern char *hs_conlen;

static t_cached_object *cache[MAX_CACHE_INDEX];
static pthread_mutex_t cache_mutex[MAX_CACHE_INDEX];
static pthread_mutex_t cache_size_mutex;
static volatile off_t cache_size;

void init_cache_module(void) {
	int index;

	for (index = 0; index < MAX_CACHE_INDEX; index++) {
		cache[index] = NULL;
		pthread_mutex_init(&cache_mutex[index], NULL);
	}

	pthread_mutex_init(&cache_size_mutex, NULL);
	cache_size = 0;
}

static int cache_index(char *filename) {
	int index = 0;

	if (filename == NULL) {
		return -1;
	}

	while (*filename != '\0') {
		index += (unsigned char)*filename;
		filename++;
	}

	return abs(index) % MAX_CACHE_INDEX;
}

static t_cached_object *remove_from_cache(t_cached_object *object, int index) {
	t_cached_object *next;

	if (object->prev != NULL) {
		object->prev->next = object->next;
	}
	if ((next = object->next) != NULL) {
		object->next->prev = object->prev;
	}

	pthread_mutex_lock(&cache_size_mutex);
	cache_size -= object->size;
	pthread_mutex_unlock(&cache_size_mutex);

	if (object == cache[index]) {
		cache[index] = object->next;
	}

	free(object->data);
	free(object->file);
	free(object);

	return next;
}

static bool add_object_to_cache(t_cached_object *object) {
	int index;
	t_cached_object *search;

	if (object == NULL) {
		return false;
	} else if ((index = cache_index(object->file)) == -1) {
		return false;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object->prev = NULL;
	object->next = cache[index];
	if (cache[index] != NULL) {
		cache[index]->prev = object;

		search = cache[index];
		while (search != NULL) {
			if (strcmp(search->file, object->file) == 0) {
				search->deadline = 0;
				break;
			}
			search = search->next;
		}
	}
	cache[index] = object;

	pthread_mutex_lock(&cache_size_mutex);
	cache_size += object->size;
	pthread_mutex_unlock(&cache_size_mutex);

	pthread_mutex_unlock(&cache_mutex[index]);

	return true;
}

t_cached_object *add_file_to_cache(t_session *session, char *file) {
	t_cached_object *object;
	struct stat status;
	off_t size;
	int fd;
	ssize_t bytes_read, bytes_total = 0;

	if (file == NULL) {
		return NULL;
	} else if (stat(file, &status) == -1) {
		return NULL;
	} else if ((size = status.st_size) == -1) {
		return NULL;
	} else if ((size < session->config->cache_min_filesize) || (size > session->config->cache_max_filesize)) {
		return NULL;
	} else if (cache_size + size > session->config->cache_size) {
		return NULL;
	} else if ((object = (t_cached_object*)malloc(sizeof(t_cached_object))) == NULL) {
		return NULL;
	} else if ((object->file = strdup(file)) == NULL) {
		free(object);
		return NULL;
	} else if ((object->data = (char*)malloc(size)) == NULL) {
		free(object->file);
		free(object);
		return NULL;
	}

	if ((fd = open(file, O_RDONLY)) != -1) {
		while ((off_t)bytes_total < size) {
			if ((bytes_read = read(fd, object->data + bytes_total, size - bytes_total)) == -1) {
				if (errno != EINTR) {
					free(object->data);
					free(object->file);
					free(object);
					close(fd);

					return NULL;
				}
			} else {
				bytes_total += bytes_read;
			}
		}
		close(fd);
	} else {
		free(object->data);
		free(object->file);
		free(object);

		return NULL;
	}

	object->last_changed = status.st_mtime;
	object->deadline = session->time + TIME_IN_CACHE;
	object->size = size;
	object->in_use = 1;
	object->type = cot_file;
	copy_ip(&(object->last_ip), &(session->ip_address));

	if (add_object_to_cache(object) == false) {
		free(object->data);
		free(object->file);
		free(object);

		return NULL;
	}

	return object;
}

t_cached_object *search_cache_for_file(t_session *session, char *file) {
	t_cached_object *object, *result = NULL;
	struct stat status;
	off_t size;
	int index;

	if (file == NULL) {
		return NULL;
	} else if ((size = filesize(file)) == -1) {
		return NULL;
	} else if ((index = cache_index(file)) == -1) {
		return NULL;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object = cache[index];
	while (object != NULL) {
		if ((object->type == cot_file) && (object->size == size)) {
			if (strcmp(object->file, file) == 0) {
				if (stat(file, &status) == 0) {
					if ((object->deadline > session->time) && (status.st_mtime == object->last_changed)) {
						if (same_ip(&(object->last_ip), &(session->ip_address)) == false) {
							if ((object->deadline += TIME_IN_CACHE) > (session->time + MAX_CACHE_TIMER)) {
								object->deadline = session->time + MAX_CACHE_TIMER;
							}
							copy_ip(&(object->last_ip), &(session->ip_address));
						}
						object->in_use++;
						result = object;
					} else if (object->in_use <= 0) {
						remove_from_cache(object, index);
					}
				} else if (object->in_use <= 0) {
					remove_from_cache(object, index);
				}
				break;
			}
		}
		object = object->next;
	}

	pthread_mutex_unlock(&cache_mutex[index]);

	return result;
}

static char *make_url(t_session *session, char *request_uri) {
	char *url;
	size_t len;

	len = strlen(*(session->host->hostname.item));
	if (request_uri == NULL) {
		request_uri = session->request_uri;
	}

	if ((url = (char*)malloc(len + strlen(request_uri) + 1)) == NULL) {
		return NULL;
	}

	memcpy(url, *(session->host->hostname.item), len);
	strcpy(url + len, request_uri);

	return url;
}

t_cached_object *add_cgi_output_to_cache(t_session *session, char *cgi_output, int size, int time) {
	t_cached_object *object;
	size_t len;
	char *pos, *loc, *data, str[50];

	if ((pos = strstr(cgi_output, "\r\n\r\n")) == NULL) {
		return NULL;
	}
	*pos = '\0';
	loc = strcasestr(cgi_output, hs_conlen);
	*pos = '\r';

	if (loc == NULL) {
		/* Output has no Content-Length
		 */
		len = size - (pos + 4 - cgi_output);
		sprintf(str, "%s%ld\r\n", hs_conlen, (long)len);
		len = strlen(str);
		if ((data = (char*)malloc(len + size)) == NULL) {
			return NULL;
		}
		memcpy(data, str, len);
		memcpy(data + len, cgi_output, size);
		size += len;
	} else {
		/* Output has Content-Length
		 */
		if ((data = (char*)malloc(size)) == NULL) {
			return NULL;
		}
		memcpy(data, cgi_output, size);
	}

	if ((object = (t_cached_object*)malloc(sizeof(t_cached_object))) == NULL) {
		free(data);
		return NULL;
	} else if ((object->file = make_url(session, NULL)) == NULL) {
		free(object);
		free(data);
		return NULL;
	}

	object->deadline = session->time + time;
	object->size = size;
	object->in_use = 0;
	object->type = cot_cgi;
	object->data = data;
	copy_ip(&(object->last_ip), &(session->ip_address));

	if (add_object_to_cache(object) == false) {
		free(object->data);
		free(object->file);
		free(object);

		return NULL;
	}

	return object;
}

t_cached_object *search_cache_for_cgi_output(t_session *session) {
	t_cached_object *object, *result = NULL;
	char *url;
	int index;

	if ((url = make_url(session, NULL)) == NULL) {
		return NULL;
	} else if ((index = cache_index(url)) == -1) {
		free(url);
		return NULL;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object = cache[index];
	while (object != NULL) {
		if (object->type == cot_cgi) {
			if (strcmp(object->file, url) == 0) {
				if (object->deadline > session->time) {
					object->in_use++;
					result = object;
				} else if (object->in_use <= 0) {
					remove_from_cache(object, index);
				}
				break;
			}
		}
		object = object->next;
	}

	pthread_mutex_unlock(&cache_mutex[index]);

	free(url);

	return result;
}

void flush_cgi_output_cache(t_session *session) {
	t_cached_object *object;
	int index;
	size_t len;

	for (index = 0; index < MAX_CACHE_INDEX; index++) {
		pthread_mutex_lock(&cache_mutex[index]);

		object = cache[index];
		while (object != NULL) {
			if (object->type == cot_cgi) {
				len = strlen(*(session->host->hostname.item));
				if (strncmp(object->file, *(session->host->hostname.item), len) == 0) {
					if (*(object->file + len) == '/') {
						if (object->in_use <= 0) {
							object = remove_from_cache(object, index);
							continue;
						} else {
							object->deadline = 0;
						}
					}
				}
			}
			object = object->next;
		}

		pthread_mutex_unlock(&cache_mutex[index]);
	}
}

void remove_cgi_output_from_cache(t_session *session, char *request_uri) {
	t_cached_object *object;
	char *url;
	int index;

	if ((url = make_url(session, request_uri)) == NULL) {
		return;
	} else if ((index = cache_index(url)) == -1) {
		free(url);
		return;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object = cache[index];
	while (object != NULL) {
		if (object->type == cot_cgi) {
			if (strcmp(object->file, url) == 0) {
				if (object->in_use <= 0) {
					remove_from_cache(object, index);
				} else {
					object->deadline = 0;
				}
				break;
			}
		}
		object = object->next;
	}

	pthread_mutex_unlock(&cache_mutex[index]);

	free(url);
}

void done_with_cached_object(t_cached_object *object, bool remove_object) {
	if (remove_object) {
		object->deadline = 0;
	}
	object->in_use--;
}

void check_cache(time_t now) {
	t_cached_object *object;
	int index;

	for (index = 0; index < MAX_CACHE_INDEX; index++) {
		pthread_mutex_lock(&cache_mutex[index]);

		object = cache[index];
		while (object != NULL) {
			if (now > object->deadline) {
				if (object->in_use <= 0) {
					object = remove_from_cache(object, index);
					continue;
				}
			}
			object = object->next;
		}

		pthread_mutex_unlock(&cache_mutex[index]);
	}
}

int clear_cache() {
	t_cached_object *object, *list;
	int i, removed = 0;

	for (i = 0; i < MAX_CACHE_INDEX; i++) {
		pthread_mutex_lock(&cache_mutex[i]);

		list = cache[i];
		cache[i] = NULL;
		while (list != NULL) {
			object = list;
			list = list->next;

			if (object->in_use == 0) {
				/* Object unused, so remove
				 */
				pthread_mutex_lock(&cache_size_mutex);
				cache_size -= object->size;
				pthread_mutex_unlock(&cache_size_mutex);

				free(object->data);
				free(object->file);
				free(object);

				removed++;
			} else {
				/* Object in use, put back in list
				 */
				object->next = cache[i];
				cache[i] = object;
			}
		}

		pthread_mutex_unlock(&cache_mutex[i]);
	}

	return removed;
}

#ifdef ENABLE_TOMAHAWK
void print_cache_list(FILE *fp) {
	t_cached_object *object;
	int i, files = 0, secs;
	off_t size = 0;
	time_t now;

	now = time(NULL);

	/* File cache
	 */
	for (i = 0; i < MAX_CACHE_INDEX; i++) {
		pthread_mutex_lock(&cache_mutex[i]);

		object = cache[i];
		while (object != NULL) {
			fprintf(fp, "  Filename  : %s\n", object->file);
			fprintf(fp, "  File size : %.2f kB\n", (float)(object->size) / KILOBYTE);
			if ((secs = object->deadline - now) > 0) {
				fprintf(fp, "  Time left : %d seconds\n\n", secs);
			} else {
				fprintf(fp, "  File marked for removal from cache\n\n");
			}
			files++;
			size = size + object->size;
			object = object->next;
		}

		pthread_mutex_unlock(&cache_mutex[i]);
	}

	fprintf(fp, "  Total: %.2f MB in %d cache objects.\n", (float)(size) / MEGABYTE, files);
}

off_t size_of_cache(void) {
	return cache_size;
}
#endif

#endif

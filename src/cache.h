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

#ifndef _CACHE_H
#define _CACHE_H

#include "config.h"

#ifdef ENABLE_CACHE

#include "config.h"
#include <stdbool.h>
#include "global.h"
#include "libip.h"

#define TIME_IN_CACHE      MINUTE
#define MAX_CACHE_TIMER      HOUR
#define MIN_CGI_CACHE_TIMER     2
#define MAX_CGI_CACHE_TIMER  HOUR

typedef struct type_cached_object {
	char          *file;
	char          *data;
	off_t         size;
	time_t        deadline;
	time_t        last_changed;
	volatile int  in_use;
	t_ip_addr     last_ip;
	enum {cot_file, cot_cgi} type;

	struct type_cached_object *prev;
	struct type_cached_object *next;
} t_cached_object;

void init_cache_module(void);
t_cached_object *add_file_to_cache(t_session *session, char *file);
t_cached_object *search_cache_for_file(t_session *session, char *file);
t_cached_object *add_cgi_output_to_cache(t_session *session, char *cgi_output, int size, int time);
t_cached_object *search_cache_for_cgi_output(t_session *session);
void flush_cgi_output_cache(t_session *session);
void remove_cgi_output_from_cache(t_session *session, char *request_uri);
void done_with_cached_object(t_cached_object *object, bool remove_object);
void check_cache(time_t time);
int clear_cache(void);
#ifdef ENABLE_TOMAHAWK
void print_cache_list(FILE *fp);
off_t size_of_cache(void);
#endif

#endif

#endif

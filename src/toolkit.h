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

#ifndef _TOOLKIT_H
#define _TOOLKIT_H

#include "config.h"

#ifdef ENABLE_TOOLKIT

#include <stdbool.h>
#include <regex.h>
#include "liblist.h"

#define UT_ERROR        -1
#define UT_RETURN        0
#define UT_EXIT          1
#define UT_RPROXY        2
#define UT_REDIRECT    301
#define UT_DENY_ACCESS 403

#define IU_EXISTS        0
#define IU_ISFILE        1
#define IU_ISDIR         2

typedef enum { tc_none, tc_match, tc_requesturi,
#ifdef ENABLE_SSL
               tc_usessl,
#endif
               tc_oldbrowser } t_toolkit_condition;
typedef enum { to_none, to_rewrite, to_sub, to_expire, to_skip, to_denyaccess, to_redirect,
	to_fastcgi, to_ban, to_replace } t_toolkit_operation;
typedef enum { tf_continue, tf_return, tf_exit } t_toolkit_flow;

typedef struct type_toolkit_rule {
	t_toolkit_condition condition;
	t_toolkit_operation operation;
	t_toolkit_flow flow;

	regex_t pattern;
	int match_loop;
	char *parameter;
	int value;
	t_toolkit_flow conditional_flow;

	struct type_toolkit_rule *next;
} t_toolkit_rule;

typedef struct type_url_toolkit {
	char *toolkit_id;
	struct type_toolkit_rule *toolkit_rule;

	struct type_url_toolkit *next;
} t_url_toolkit;

typedef struct type_toolkit_options {
	int  sub_depth;
	char *new_url;
	char *website_root;
	char *fastcgi_server;
	int  ban;
	int  expire;
#ifdef ENABLE_SSL
	bool use_ssl;
#endif
	bool allow_dot_files;
	t_url_toolkit *url_toolkit;
	t_headerfield *headerfields;
} t_toolkit_options;

t_url_toolkit *find_toolkit(char *toolkit_id, t_url_toolkit *url_toolkit);
bool toolkit_setting(char *key, char *value, t_url_toolkit *toolkit);
bool toolkit_rules_oke(t_url_toolkit *url_toolkit);
void init_toolkit_options(t_toolkit_options *options, char *website_root, t_url_toolkit *toolkit,
#ifdef ENABLE_SSL
                          bool use_ssl,
#endif
                          bool allow_dot_files, t_headerfield *headerfields);
int use_toolkit(char *url, char *toolkit_id, t_toolkit_options *options);

#endif

#endif

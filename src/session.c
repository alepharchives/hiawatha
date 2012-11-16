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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/socket.h>
#include "global.h"
#include "alternative.h"
#include "libstr.h"
#include "libip.h"
#include "liblist.h"
#include "session.h"
#include "log.h"
#ifdef ENABLE_MONITOR
#include "monitor.h"
#endif
#ifdef ENABLE_TOMAHAWK
#include "tomahawk.h"
#endif
#include <regex.h>

static const struct {
	const char *text;
} sqli_detection[] = {
	{"union\\s*select"},
	{"[\\s'0-9a-z]\\s*--[ \\t]+.+"},
	{"'\\s*(and|or|&&|\\|\\|)\\s*('|[0-9]|[a-z.]*\\s*=)"},
	{NULL}
};

typedef struct type_sqli_pattern {
	regex_t regex;
	struct type_sqli_pattern *next;
} t_sqli_pattern;

t_sqli_pattern *sqli_patterns = NULL;
static int new_client_id = 0;

/* Set the entries in a session-record to the default values.
 */
static void clear_session(t_session *session) {
	session->time = time(NULL);
	session->cgi_type = no_cgi;
	session->cgi_handler = NULL;
	session->fcgi_server = NULL;
	session->method = NULL;
	session->uri = NULL;
	session->uri_len = 0;
	session->uri_is_dir = false;
	session->request_uri = NULL;
	session->request_method = unknown;
	session->extension = NULL;
	session->encode_gzip = false;
	session->path_info = NULL;
	session->alias_used = false;
	session->vars = NULL;
	session->http_version = NULL;
	session->headerfields = NULL;
	session->body = NULL;
	session->local_user = NULL;
	session->header_sent = false;
	session->data_sent = false;
	session->cause_of_301 = missing_slash;
	session->header_length = 0;
	session->content_length = 0;
	session->file_on_disk = NULL;
	session->mimetype = NULL;
	session->hostname = NULL;
	session->host = session->config->first_host;
	session->host_copied = false;
	session->throttle = 0;
	session->throttle_timer = 0;
	session->bytecounter = 0;
	session->part_of_dirspeed = false;
	session->remote_user = NULL;
	session->http_auth = no_auth;
	session->directory = NULL;
	session->handling_error = false;
	session->reason_for_403 = "";
	session->cookie = NULL;
	session->bytes_sent = 0;
	session->output_size = 0;
	session->return_code = 200;
	session->error_code = -1;
	session->tempdata = NULL;
	session->uploaded_file = NULL;
	session->uploaded_size = 0;
	session->location = NULL;
	session->expires = -1;
#ifdef ENABLE_TOOLKIT
	session->toolkit_fastcgi = NULL;
#endif
#ifdef ENABLE_XSLT
	session->xslt_file = NULL;
#endif
#ifdef ENABLE_DEBUG
	session->current_task = NULL;
#endif
}

/* Initialize a session-record.
 */
void init_session(t_session *session) {
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_CLIENT);
#endif
	if ((session->client_id = new_client_id++) == MAX_CHILD_ID) {
		new_client_id = 0;
	}
	session->request_limit = true;
	session->force_quit = false;
	session->keep_alive = false;
	session->kept_alive = 0;

	session->last_host = NULL;
	session->request = NULL;
	session->buffer_size = 0;
	session->bytes_in_buffer = 0;

	clear_session(session);

	session->socket_open = false;
	session->flooding_timer = session->time;
}

/* Reset a session-record for reuse.
 */
void reset_session(t_session *session) {
	int size;

	session->error_cause = ec_NONE;

	sfree(session->file_on_disk);
#ifdef CIFS
	sfree(session->extension);
#endif
	sfree(session->local_user);
	sfree(session->remote_user);
	sfree(session->path_info);
	sfree(session->request_uri);
	sfree(session->location);
#ifdef ENABLE_XSLT
	sfree(session->xslt_file);
#endif
	if (session->uploaded_file != NULL) {
		unlink(session->uploaded_file);
		free(session->uploaded_file);
	}
	session->headerfields = remove_headerfields(session->headerfields);
	if (session->directory != NULL) {
		pthread_mutex_lock(&(session->directory->client_mutex));
		if (session->part_of_dirspeed) {
			if (--session->directory->nr_of_clients == 0) {
				session->directory->session_speed = session->directory->upload_speed;
			} else {
				session->directory->session_speed = session->directory->upload_speed / session->directory->nr_of_clients;
			}
		}
		pthread_mutex_unlock(&(session->directory->client_mutex));
	}

	/* HTTP pipelining
	 */
	size = session->header_length + session->content_length;
	if ((session->bytes_in_buffer > size) && session->keep_alive) {
		session->bytes_in_buffer -= size;
		memmove(session->request, session->request + size, session->bytes_in_buffer);
		*(session->request + session->bytes_in_buffer) = '\0';
	} else {
		sfree(session->request);
		session->request = NULL;
		session->buffer_size = 0;
		session->bytes_in_buffer = 0;
	}

	remove_tempdata(session->tempdata);
	if (session->host_copied) {
		free(session->host);
	}

	clear_session(session);
}

/* Free all remaining buffers
 */
void destroy_session(t_session *session) {
	sfree(session->request);
	session->request = NULL;
}

/* Determine the request method
 */
void determine_request_method(t_session *session) {
	if (strncmp(session->request, "GET ", 4) == 0) {
		session->request_method = GET;
	} else if (strncmp(session->request, "POST ", 5) == 0) {
		session->request_method = POST;
	} else if (strncmp(session->request, "HEAD ", 5) == 0) {
		session->request_method = HEAD;
	} else if (strncmp(session->request, "TRACE ", 6) == 0) {
		session->request_method = TRACE;
	} else if (strncmp(session->request, "PUT ", 4) == 0) {
		session->request_method = PUT;
	} else if (strncmp(session->request, "DELETE ", 7) == 0) {
		session->request_method = DELETE;
	} else if (strncmp(session->request, "OPTIONS ", 8) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "CONNECT ", 8) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "PROPFIND ", 9) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "PROPPATCH ", 10) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "MKCOL ", 6) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "COPY ", 5) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "MOVE ", 5) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "LOCK ", 5) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "UNLOCK ", 7) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "REPORT ", 7) == 0) {
		session->request_method = unsupported;
	}
}

/* Get the extension of the file to be processed
 */
int get_target_extension(t_session *session) {
	char *last_slash;

#ifdef CIFS
	sfree(session->extension);
#endif

	if ((last_slash = strrchr(session->file_on_disk, '/')) == NULL) {
		return -1;
	}

	if ((session->extension = strrchr(last_slash, '.')) != NULL) {
		session->extension++;
	} else {
		session->extension = session->host->no_extension_as;
	}

#ifdef CIFS
	if (session->extension != NULL) {
		if ((session->extension = strdup(session->extension)) == NULL) {
			return -1;
		}
		strlower(session->extension);
	}
#endif

	return 0;
}

/* Return the path of the user's homedirectory.
 */
int get_homedir(t_session *session, char *username) {
	struct passwd *pwd;
	size_t len;
	char *old_root;

	if (username == NULL) {
		return 500;
	} else if ((pwd = getpwnam(username)) == NULL) {
		return 404;
	}

	old_root = session->host->website_root;

	len = strlen(pwd->pw_dir) + strlen(session->config->user_directory) + 2;
	if ((session->host->website_root = (char*)malloc(len)) == NULL) {
		session->host->website_root = old_root;
		return -1;
	}

	sprintf(session->host->website_root, "%s/%s", pwd->pw_dir, session->config->user_directory);
	if (register_tempdata(&(session->tempdata), session->host->website_root, tc_data) == -1) {
		free(session->host->website_root);
		session->host->website_root = old_root;
		return -1;
	}
	session->host->website_root_len = strlen(session->host->website_root);

	return 200;
}

/* Dupliacte the active host-record. The duplicate can now savely be altered
 * and will be used during the session.
 */
bool duplicate_host(t_session *session) {
	t_host *new_host;

	if ((session->host != NULL) && (session->host_copied == false)) {
		if ((new_host = (t_host*)malloc(sizeof(t_host))) == NULL) {
			return false;
		}

		memcpy(new_host, session->host, sizeof(t_host));
		new_host->next = NULL;
		session->host = new_host;
		session->host_copied = true;
	}

	return true;
}

/* Is the requested file marked as volatile?
 */
bool is_volatile_object(t_session *session) {
	int i;

	for (i = 0; i < session->host->volatile_object.size; i++) {
		if (strcmp(session->file_on_disk, *(session->host->volatile_object.item + i)) == 0) {
			return true;
		}
	}

	return false;
}

/* Load configfile from directories
 */
int load_user_config(t_session *session) {
	char *search, *conffile;
	int length, result;

	if (session->file_on_disk == NULL) {
		return 0;
	}

	search = session->file_on_disk;
	while (*search != '\0') {
		if (*search == '/') {
			length = search - session->file_on_disk + 1;
			if ((conffile = (char*)malloc(length + 10)) == NULL) {
				return -1;
			} else {
				memcpy(conffile, session->file_on_disk, length);
				memcpy(conffile + length, ".hiawatha\0", 10);
				result = read_user_configfile(conffile, session->host, &(session->tempdata));

				if (result != 0) {
					log_file_error(session, conffile, "error in configuration file on line %d", result);
					free(conffile);
					return -1;
				}

				free(conffile);
			}
		}

		search++;
	}

	return 0;
}

/* Copy the settings from a directory-record to the active host-record.
 */
int copy_directory_settings(t_session *session) {
	size_t path_length;
	t_directory *dir;
	bool match;

	dir = session->config->directory;
	while (dir != NULL) {
		path_length = strlen(dir->path);
		if (strlen(session->file_on_disk) >= path_length) {
			if (dir->path_match == root) {
				match = (strncmp(session->file_on_disk, dir->path, path_length) == 0);
			} else {
				match = (strstr(session->file_on_disk, dir->path) != NULL);
			}
			if (match) {
				session->directory = dir;

				if (dir->max_clients > -1) {
					pthread_mutex_lock(&(dir->client_mutex));
					if (dir->nr_of_clients < dir->max_clients) {
						session->throttle = dir->session_speed = dir->upload_speed / ++dir->nr_of_clients;
						pthread_mutex_unlock(&(dir->client_mutex));
						session->part_of_dirspeed = true;
					} else {
						pthread_mutex_unlock(&(dir->client_mutex));
						return 503;
					}
				}
				if (dir->wrap_cgi != NULL) {
					session->host->wrap_cgi = dir->wrap_cgi;
				}
				if (dir->start_file != NULL) {
					session->host->start_file = dir->start_file;
				}
				if (dir->execute_cgiset) {
					session->host->execute_cgi = dir->execute_cgi;
				}
#ifdef ENABLE_XSLT
				if (dir->show_index_set) {
					session->host->show_index = dir->show_index;
				}
#endif
				if (dir->follow_symlinks_set) {
					session->host->follow_symlinks = dir->follow_symlinks;
				}
				if (dir->use_gz_file_set) {
					session->host->use_gz_file = dir->use_gz_file;
				}
				if (dir->access_list != NULL) {
					session->host->access_list = dir->access_list;
				}
				if (dir->alter_list != NULL) {
					session->host->alter_list = dir->alter_list;
				}
				if (dir->alter_fmode != 0) {
					session->host->alter_fmode = dir->alter_fmode;
				}
				if (dir->image_referer.size > 0) {
					session->host->image_referer.size = dir->image_referer.size;
					session->host->image_referer.item = dir->image_referer.item;
					session->host->imgref_replacement = dir->imgref_replacement;
				}
				if (dir->passwordfile != NULL) {
					session->host->auth_method = dir->auth_method;
					session->host->passwordfile = dir->passwordfile;
					if (dir->groupfile != NULL) {
						session->host->groupfile = dir->groupfile;
					}
				}
				if (dir->required_group.size > 0) {
					session->host->required_group.size = dir->required_group.size;
					session->host->required_group.item = dir->required_group.item;
				}
				if (dir->alter_group.size > 0) {
					session->host->alter_group.size = dir->alter_group.size;
					session->host->alter_group.item = dir->alter_group.item;
				}
				if (dir->time_for_cgi > TIMER_OFF) {
					session->host->time_for_cgi = dir->time_for_cgi;
				}
				break;
			}
		}
		dir = dir->next;
	}

	return 200;
}

/* Check if User-Agent string contains deny_bot substring.
 */
bool client_is_rejected_bot(t_session *session) {
	int i, len;
	char *useragent;
	t_denybotlist *botlist;

	if (session->host->deny_bot == NULL) {
		return false;
	} else if ((useragent = get_headerfield("User-Agent:", session->headerfields)) == NULL) {
		return false;
	}

	botlist = session->host->deny_bot;
	while (botlist != NULL) {
		if (strcasestr(useragent, botlist->bot) != NULL) {
			for (i = 0; i < botlist->uri.size; i++) {
				len = strlen(*(botlist->uri.item + i));
				if (session->uri_len >= len) {
					if (memcmp(*(botlist->uri.item + i), session->uri, len) == 0) {
						return true;
					}
				}
			}
		}
		botlist = botlist->next;
	}

	return false;
}

/* Remove port from hostname
 */
int remove_port_from_hostname(char *hostname, t_binding *binding) {
	char *c;
#ifdef ENABLE_IPV6
	char old, ip[IPv6_LEN];
#endif

	if (hostname == NULL) {
		return -1;
	}

	if (binding->interface.family == AF_INET) {
		if ((c = strrchr(hostname, ':')) != NULL) {
			if (c == hostname) {
				return -1;
			}

			*c = '\0';
		}
#ifdef ENABLE_IPV6
	} else if (binding->interface.family == AF_INET6) {
		if ((c = strrchr(hostname, '.')) != NULL) {
			if (c == hostname) {
				return -1;
			}

			old = *c;
			*c = '\0';

			if ((*hostname == '[') && (*(c - 1) == ']')) {
				return 0;
			}

			if (inet_pton(AF_INET6, hostname, ip) <= 0) {
				*c = old;
			}
		}
#endif
	}

	return 0;
}

/* Prevent cross-site scripting.
 */
int prevent_xss(t_session *session) {
	int result = 0;
	short low, high;
	char *str, value;

	if ((str = session->vars) == NULL) {
		return 0;
	}

	while (*str != '\0') {
		if ((value = *str) == '%') {
			if ((high = hex_to_int(*(str + 1))) != -1) {
				if ((low = hex_to_int(*(str + 2))) != -1) {
					value = (char)(high<<4) + low;
				}
			}
		}

		if ((value == '\"') || (value == '<') || (value == '>') || (value == '\'')) {
			*str = '_';
			result += 1;
		}
		str++;
	}

	if (result > 0) {
		log_exploit_attempt(session, "XSS", session->vars);
#ifdef ENABLE_TOMAHAWK
		increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
		if (session->config->monitor_enabled) {
			monitor_counter_exploit_attempt(session);
		}
#endif
	}

	return result;
}

/* Initialize SQL injection detection
 */
int init_sqli_detection(void) {
	t_sqli_pattern *prev;
	int i;

	for (i = 0; sqli_detection[i].text != NULL; i++) {
		prev = sqli_patterns;
		if ((sqli_patterns = (t_sqli_pattern*)malloc(sizeof(t_sqli_pattern))) == NULL) {
			return -1;
		}
		sqli_patterns->next = prev;

		if (regcomp(&(sqli_patterns->regex), sqli_detection[i].text, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
			fprintf(stderr, "Error in regexp %s\n", sqli_detection[i].text);
			return -1;
		}
	}

	return 0;
}

/* Prevent SQL injection
 */
static int prevent_sqli_str(t_session *session, char *str, int length) {
	char *data;
	t_sqli_pattern *pattern;
	int result = 0;

	if ((str == NULL) || (length <= 0)) {
		return 0;
	}

	if ((data = (char*)malloc(length + 1)) == NULL) {
		return -1;
	}
	memcpy(data, str, length);
	data[length] = '\0';
	url_decode(data);

	pattern = sqli_patterns;
	while (pattern != NULL) {
		if (regexec(&(pattern->regex), data, 0, NULL, 0) != REG_NOMATCH) {
			log_exploit_attempt(session, "SQLi", str);
#ifdef ENABLE_TOMAHAWK
			increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
			if (session->config->monitor_enabled) {
				monitor_counter_exploit_attempt(session);
			}
#endif

			result = 1;
			break;
		}

		pattern = pattern->next;
	}

	free(data);

	return result;
}

int prevent_sqli(t_session *session) {
	if (session->request_uri != NULL) {
		switch (prevent_sqli_str(session, session->request_uri, strlen(session->request_uri))) {
			case -1:
				return 500;
			case 0:
				break;
			default:
				session->error_cause = ec_SQL_INJECTION;
				return -1;
		}
	}
/*
	if (session->vars != NULL) {
		switch (prevent_sqli_str(session, session->vars, strlen(session->vars))) {
			case -1:
				return 500;
			case 0:
				break;
			default:
				session->error_cause = ec_SQL_INJECTION;
				return -1;
		}
	}
*/

	if (session->body != NULL) {
		switch (prevent_sqli_str(session, session->body, session->content_length)) {
			case -1:
				return 500;
			case 0:
				break;
			default:
				session->error_cause = ec_SQL_INJECTION;
				return -1;
		}
	}

	if (session->cookie != NULL) {
		switch (prevent_sqli_str(session, session->cookie, strlen(session->cookie))) {
			case -1:
				return 500;
			case 0:
				break;
			default:
				session->error_cause = ec_SQL_INJECTION;
				return -1;
		}
	}

	return 0;
}

/* Prevent Cross-site Request Forgery
 */
int prevent_csrf(t_session *session) {
	char *referer, *slash;
	int i, n;

	if (strcmp(session->method, "POST") != 0) {
		return 0;
	}

	if ((referer = get_headerfield("Referer:", session->headerfields)) == NULL) {
		return 0;
	}

	if (strncmp(referer, "http://", 7) == 0) {
		referer += 7;
	} else if (strncmp(referer, "https://", 8) == 0) {
		referer += 8;
	} else {
		session->cookie = NULL;

		log_error(session, "invalid referer while checking for CSRF");

		return 1;
	}

	if ((slash = strchr(referer, '/')) != NULL) {
		n = slash - referer;
	} else {
		n = strlen(referer);
	}

	for (i = 0; i < session->host->hostname.size; i++) {
		if (strncasecmp(referer, *(session->host->hostname.item + i), n) == 0) {
			return 0;
		}
	}

	session->cookie = NULL;

	if (session->body != NULL) {
		log_exploit_attempt(session, "CSRF", session->body);
#ifdef ENABLE_TOMAHAWK
		increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
		if (session->config->monitor_enabled) {
			monitor_counter_exploit_attempt(session);
		}
#endif
	} else {
		log_error(session, "CSRF attempt detected with no request body");
	}

#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled) {
		monitor_counter_exploit_attempt(session);
	}
#endif

	return 1;
}

void close_socket(t_session *session) {
	if (session->socket_open) {
#ifdef ENABLE_SSL
		if (session->binding->use_ssl) {
			ssl_close(&(session->ssl_context));
		}
#endif
		fsync(session->client_socket);
		close(session->client_socket);
		session->socket_open = false;
	}
}

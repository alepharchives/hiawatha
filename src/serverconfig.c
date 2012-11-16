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
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef ENABLE_SSL
#include "libssl.h"
#include "polarssl/ssl.h"
#endif
#include <regex.h>
#include "serverconfig.h"
#include "libstr.h"
#include "libfs.h"

#define ID_NOBODY             65534
#define MAX_LENGTH_CONFIGLINE   512
#define MAX_CACHE_SIZE           50
#define MAX_UPLOAD_SIZE         100
#define MONITOR_HOSTNAME      "monitor"

enum t_section { syntax_error = -1, none, binding, virtual_host, directory, fcgi_server
#ifdef ENABLE_TOOLKIT
	, url_toolkit
#endif
	};

static bool including = false;
static t_keyvalue *variables = NULL;
#ifdef ENABLE_XSLT
static char *index_xslt = CONFIG_DIR"/index.xslt";
#endif

static t_host *new_host(void) {
	t_host *host;

	if ((host = (t_host*)malloc(sizeof(t_host))) == NULL) {
		perror("new_host()");
		exit(EXIT_FAILURE);
	}

	host->website_root       = NULL;
	host->website_root_len   = 0;
	host->start_file         = "index.html";
	host->error_handlers     = NULL;
	host->access_logfile     = LOG_DIR"/access.log";
	host->access_fileptr     = NULL;
	host->access_fp          = &(host->access_fileptr);
	host->access_time        = 0;
	host->error_logfile      = LOG_DIR"/error.log";
	init_charlist(&(host->hostname));
	host->user_websites      = false;
	host->execute_cgi        = false;
	host->time_for_cgi       = 5;
	host->no_extension_as    = NULL;
#ifdef ENABLE_XSLT
	host->show_index         = NULL;
	host->use_xslt           = false;
#endif
	host->allow_dot_files    = false;
	host->use_gz_file        = false;
	host->access_list        = NULL;
	host->alter_list         = NULL;
	host->alter_fmode        = S_IRUSR | S_IWUSR | S_IRGRP;
	host->run_on_alter       = NULL;
	host->login_message      = "Private page";
	host->passwordfile       = NULL;
	host->groupfile          = NULL;
	host->deny_bot           = NULL;
	init_charlist(&(host->required_binding));
	init_charlist(&(host->required_group));
	init_charlist(&(host->alter_group));
	host->custom_headers     = NULL;
#ifdef ENABLE_TOOLKIT
	init_charlist(&(host->toolkit_rules));
#endif
	host->wrap_cgi           = NULL;
	init_groups(&(host->groups));
	init_charlist(&(host->volatile_object));
	init_charlist(&(host->image_referer));
	host->imgref_replacement = NULL;
	host->envir_str          = NULL;
	host->alias              = NULL;
#ifdef ENABLE_SSL
	host->require_ssl        = false;
	host->key_cert_file      = NULL;
	host->ca_cert_file       = NULL;
	host->ca_crl_file        = NULL;
	host->private_key        = NULL;
	host->certificate        = NULL;
	host->ca_certificate     = NULL;
	host->ca_crl             = NULL;
#endif
#ifdef ENABLE_RPROXY
	host->rproxy             = NULL;
#endif
	host->prevent_sqli       = false;
	host->prevent_xss        = false;
	host->prevent_csrf       = false;
	host->follow_symlinks    = false;
	host->enable_path_info   = false;
	host->trigger_on_cgi_status = false;
	init_charlist(&(host->fast_cgi));
	host->secure_url         = true;
	host->deny_body          = NULL;
	host->webdav_app         = false;
#ifdef ENABLE_MONITOR
	host->monitor_stats      = NULL;
	host->monitor_requests   = false;
	host->monitor_host       = false;
#endif

	host->next               = NULL;

	return host;
}

static t_directory *new_directory(void) {
	t_directory *directory;

	if ((directory = (t_directory*)malloc(sizeof(t_directory))) == NULL) {
		perror("new_directory()");
		exit(EXIT_FAILURE);
	}

	directory->path                = NULL;
	directory->wrap_cgi            = NULL;
	directory->start_file          = NULL;
	directory->execute_cgiset      = false;
#ifdef ENABLE_XSLT
	directory->show_index          = NULL;
	directory->show_index_set      = false;
#endif
	directory->use_gz_file_set     = false;
	directory->follow_symlinks_set = false;
	directory->access_list         = NULL;
	directory->alter_list          = NULL;
	directory->alter_fmode         = 0;
	init_groups(&(directory->groups));
	directory->passwordfile        = NULL;
	directory->groupfile           = NULL;
	init_charlist(&(directory->required_group));
	init_charlist(&(directory->image_referer));
	init_charlist(&(directory->alter_group));
	directory->imgref_replacement  = NULL;
	directory->max_clients         = -1;
	directory->nr_of_clients       = 0;
	directory->upload_speed        = 0;
	directory->session_speed       = 0;
	directory->envir_str           = NULL;
	directory->time_for_cgi        = TIMER_OFF;
	directory->run_on_download     = NULL;
	pthread_mutex_init(&(directory->client_mutex), NULL);

	directory->next                = NULL;

	return directory;
}

static t_fcgi_server *new_fcgi_server(void) {
	t_fcgi_server *fcgi_server;

	if ((fcgi_server = (t_fcgi_server*)malloc(sizeof(t_fcgi_server))) == NULL) {
		perror("new_fcgi_server()");
		exit(EXIT_FAILURE);
	}

	fcgi_server->fcgi_id          = NULL;
	fcgi_server->connect_to       = NULL;
	fcgi_server->session_timeout  = 900;
	fcgi_server->chroot           = NULL;
	fcgi_server->chroot_len       = 0;
	init_charlist(&(fcgi_server->extension));

	return fcgi_server;
}

static t_binding *new_binding(void) {
	t_binding *binding;

	if ((binding = (t_binding*)malloc(sizeof(t_binding))) == NULL) {
		perror("new_binding()");
		exit(EXIT_FAILURE);
	}

	binding->port                 = -1;
	default_ipv4(&(binding->interface));
#ifdef ENABLE_SSL
	binding->use_ssl              = false;
	binding->key_cert_file        = NULL;
	binding->ca_cert_file         = NULL;
	binding->ca_crl_file          = NULL;
	binding->private_key          = NULL;
	binding->certificate          = NULL;
	binding->ca_certificate       = NULL;
	binding->ca_crl               = NULL;
#endif
	binding->binding_id           = NULL;
	binding->enable_trace         = false;
	binding->enable_alter         = false;
	binding->max_keepalive        = 50;
	binding->max_request_size     = 64 * KILOBYTE;
	binding->max_upload_size      = MEGABYTE;
	binding->time_for_1st_request = 5;
	binding->time_for_request     = 30;

	binding->socket               = -1;
	binding->poll_data            = NULL;

	binding->next                 = NULL;

	return binding;
}

#ifdef ENABLE_TOOLKIT
t_url_toolkit *new_url_toolkit(void) {
	t_url_toolkit *url_toolkit;

	if ((url_toolkit = (t_url_toolkit*)malloc(sizeof(t_url_toolkit))) == NULL) {
		perror("new_url_toolkit()");
		exit(EXIT_FAILURE);
	}

	url_toolkit->toolkit_id = NULL;
	url_toolkit->toolkit_rule = NULL;

	url_toolkit->next = NULL;

	return url_toolkit;
}
#endif

t_config *default_config(void) {
	t_config *config;

	if ((config = (t_config*)malloc(sizeof(t_config))) == NULL) {
		perror("default_config()");
		exit(EXIT_FAILURE);
	}

	config->mimetype_config    = "mimetype.conf";

	config->binding            = NULL;
#ifdef ENABLE_TOMAHAWK
	config->tomahawk_port      = NULL;
#endif

	config->server_uid         = (uid_t)ID_NOBODY;
	config->server_gid         = (gid_t)ID_NOBODY;
	config->server_string      = "Hiawatha v"VERSION;
	init_groups(&(config->groups));
	init_charlist(&(config->cgi_extension));
	config->total_connections  = 100;
	config->connections_per_ip = 10;
	config->socket_send_timeout = 3;
	config->kill_timedout_cgi  = true;
	config->wait_for_cgi       = true;
	config->first_host         = new_host();
	config->mimetype           = NULL;
	config->directory          = NULL;
	config->throttle           = NULL;
	config->cgi_handler        = NULL;
	config->cgi_wrapper        = SBIN_DIR"/cgi-wrapper";
	config->wrap_user_cgi      = false;
	config->log_format         = hiawatha;
	config->user_directory     = "public_html";
	config->user_directory_set = false;
	config->hide_proxy         = NULL;
	config->request_limit_mask = NULL;
	config->max_url_length     = 1000;

	config->pidfile            = PID_DIR"/hiawatha.pid";
	config->system_logfile     = LOG_DIR"/system.log";
	config->garbage_logfile    = NULL;
	config->exploit_logfile    = LOG_DIR"/exploit.log";
	config->logfile_mask       = NULL;

	config->ban_on_denied_body = 0;
	config->ban_on_garbage     = 0;
	config->ban_on_max_per_ip  = 2;
	config->ban_on_flooding    = 0;
	config->ban_on_max_request_size = 0;
	config->ban_on_sqli        = 0;
	config->ban_on_timeout     = 0;
	config->ban_on_wrong_password = 0;
	config->ban_on_invalid_url = 0;
	config->kick_on_ban        = false;
	config->reban_during_ban   = false;
	config->max_wrong_passwords = 0;
	config->flooding_count     = 0;
	config->flooding_time      = 0;
	config->reconnect_delay    = 0;
	config->banlist_mask       = NULL;
	config->fcgi_server        = NULL;
	config->work_directory     = WORK_DIR;
	config->upload_directory   = NULL;
	config->upload_directory_len = 0;
#ifdef ENABLE_TOOLKIT
	config->url_toolkit        = NULL;
#endif
#ifdef CYGWIN
	config->platform           = windows;
#endif

#ifdef ENABLE_LOADCHECK
	config->max_server_load    = 0;
#endif

#ifdef ENABLE_CACHE
	config->cache_size         = 10 * MEGABYTE;
	config->cache_max_filesize = 256 * KILOBYTE;
	config->cache_min_filesize = 1;
#endif

#ifdef ENABLE_TOMAHAWK
	config->tomahawk_port      = NULL;
#endif

#ifdef ENABLE_MONITOR
	config->monitor_enabled    = false;
	config->monitor_directory  = WORK_DIR"/monitor";
	config->monitor_stats_interval = 60 * MINUTE;
#endif

#ifdef ENABLE_SSL
	config->min_ssl_version    = SSL_MINOR_VERSION_0;
#endif
	return config;
}

static int fgets_multi(char *line, int size, FILE *fp) {
	int lines;
	char *pos;

	if ((line == NULL) || (size <= 1)) {
		return -1;
	} else if (fgets(line, size, fp) != NULL) {
		if ((pos = strstr(line, " \\\n")) == NULL) {
			pos = strstr(line, " \\\r");
		}

		if (pos == NULL) {
			lines = 0;
		} else if ((lines = fgets_multi(pos, size - (pos - line), fp)) == -1) {
			return -1;
		}
		return 1 + lines;
	} else {
		return 0;
	}
}

static bool valid_start_file(char *file) {
	bool retval = false;

	if (file != NULL) {
		if (strchr(file, '/') == NULL) {
			if (strlen(file) <= MAX_START_FILE_LENGTH) {
				retval = true;
			}
		}
	}

	return retval;
}

static bool valid_directory(char *dir) {
	size_t len;

	if (dir == NULL) {
		return false;
	} else if ((len = strlen(dir)) <= 1) {
		return false;
	} else if ((*dir == '/') && (*(dir + len - 1) != '/')) {
		return true;
	}

	return false;
}

static int parse_mode(char *line, mode_t *mode) {
	mode_t mod = 0;
	int i;

	if (strlen(line) != 3) {
		return -1;
	}

	for (i = 0; i < 3; i++) {
		if ((line[i] < '0') || (line[i] > '9')) {
			return -1;
		}
		mod = (8 * mod) + (line[i] - '0');
	}
	*mode = mod;

	return 0;
}

static int parse_yesno(char *yesno, bool *result) {
	if ((strcmp(yesno, "yes") == 0) || (strcmp(yesno, "true") == 0)) {
		*result = true;
	} else if ((strcmp(yesno, "no") == 0) || (strcmp(yesno, "false") == 0)) {
		*result = false;
	} else {
		return -1;
	}

	return 0;
}

static int parse_credentialfiles(char *line, t_auth_method *auth_method, char **pwdfile, char **groupfile) {
	char *file, *group;

	split_string(line, &line, &group, ',');
	if (strcmp(line, "none") == 0) {
		*pwdfile = NULL;
	} else if (strcmp(line, "") == 0) {
		if (group == NULL) {
			return -1;
		}
	} else {
		if (split_string(line, &line, &file, ':') == -1) {
			return -1;
		}

		strlower(line);
		if (strcmp(line, "basic") == 0) {
			*auth_method = basic;
		} else if (strcmp(line, "digest") == 0) {
			*auth_method = digest;
		} else {
			return -1;
		}

		if ((*pwdfile = strdup(file)) == NULL) {
			return -1;
		}
	}

	if (group != NULL) {
		if ((*groupfile = strdup(group)) == NULL) {
			return -1;
		}
	}

	return 0;
}

static bool replace_variables(char **line) {
	bool replaced = false;
	t_keyvalue *variable;
	char *new;

	variable = variables;
	while (variable != NULL) {
		if (str_replace(*line, variable->key, variable->value, &new) > 0) {
			if (replaced) {
				free(*line);
			}
			*line = new;
			replaced = true;
		}
		variable = variable->next;
	}

	return replaced;
}

#ifdef CYGWIN
static int fix_windows_path(char *value, char *key) {
	char *pos;
	size_t len;

	if (key != NULL) {
		if (strcmp(key, "setenv") == 0) {
			return 0;
		}
	}

	if (value == NULL) {
		return -1;
	} else if (strlen(value) + 40 > MAX_LENGTH_CONFIGLINE) {
		return -1;
	}
	if ((pos = strstr(value, ":\\")) == NULL) {
		return 0;
	}
	pos--;
	if (pos > value) {
		if ((*(pos - 1) != ':') && (*(pos - 1) != ',')) {
			return 0;
		}
	} else if (pos != value) {
		return 0;
	}
	if ((*pos >= 'A') && (*pos <= 'Z')) {
		*pos += 32;
	} else if ((*pos < 'a') || (*pos > 'z')) {
		return 0;
	}
	len = strlen(pos) - 2;
	memmove(pos + 12, pos + 3, len);
	*(pos + 10) = *pos;
	*(pos + 11) = '/';
	memcpy(pos, "/cygdrive/", 10);

	pos = pos + 12;
	while (*pos != '\0') {
		if (*pos == '\\') {
			*pos = '/';
		} else if ((*pos == ':') || (*pos == ',')) {
			break;
		}
		pos++;
	}

	return 1;
}
#endif

void close_bindings(t_binding *binding) {
	while (binding != NULL) {
		close(binding->socket);

		binding = binding->next;
	}
}

int check_configuration(t_config *config) {
	t_fcgi_server *fcgi_server;
	t_connect_to *connect_to;
	t_host *host;
	char c;
	int i;
	size_t len;

	if (config->first_host->hostname.size == 0) {
		fprintf(stderr, "The default website has no hostname.\n");
		return -1;
	}

	if (config->first_host->website_root == NULL) {
		fprintf(stderr, "The default website has no websiteroot.\n");
		return -1;
	}

	len = strlen(config->work_directory);

	config->upload_directory_len = len + 7;
	if ((config->upload_directory = (char*)malloc(config->upload_directory_len + 1)) == NULL) {
		return -1;
	}
	memcpy(config->upload_directory, config->work_directory, len);
	strcpy(config->upload_directory + len, "/upload");

#ifdef ENABLE_MONITOR
	if ((config->monitor_directory = (char*)malloc(len + 9)) == NULL) {
		return -1;
	}
	memcpy(config->monitor_directory, config->work_directory, len);
	strcpy(config->monitor_directory + len, "/monitor");

	if ((config->monitor_enabled) && (config->first_host->next != NULL)) {
		host = config->first_host->next;
		if (strcmp(host->hostname.item[0], MONITOR_HOSTNAME) == 0) {
			host->website_root = config->monitor_directory;
			host->website_root_len = strlen(host->website_root);
		}
	}
#endif

	host = config->first_host;
	while (host != NULL) {
		for (i = 0; i < host->hostname.size; i++) {
			if (strchr(*(host->hostname.item + i), '/') != NULL) {
				fprintf(stderr, "The hostname '%s' contains a path.\n", *(host->hostname.item + i));
				return -1;
			}
		}

		if ((host->wrap_cgi != NULL) && (host->fast_cgi.size != 0)) {
			fprintf(stderr, "The host '%s' contains both a WrapCGI and FastCGI option.\n", *(host->hostname.item));
			return -1;
		}

		host = host->next;
	}

	fcgi_server = config->fcgi_server;
	while (fcgi_server != NULL) {
		connect_to = fcgi_server->connect_to;
		while (connect_to->next != NULL) {
			connect_to = connect_to->next;
		}
		connect_to->next = fcgi_server->connect_to;

		host = config->first_host;
		if ((fcgi_server->chroot != NULL) && (fcgi_server->chroot_len > 0)) {
			while (host != NULL) {
				if (host->fast_cgi.size != 0) {
					if (in_charlist(fcgi_server->fcgi_id, &(host->fast_cgi))) {
						/* FastCGIid match
						 */
						do {
							if (strncmp(fcgi_server->chroot, host->website_root, fcgi_server->chroot_len) == 0) {
								c = host->website_root[fcgi_server->chroot_len];
								if ((c == '/') || (c == '\0')) {
									break;
								}
							}
							fprintf(stderr, "The ServerRoot of FastCGI server '%s' is not located with the DocumentRoot of virtual host '%s'.\n", fcgi_server->fcgi_id, *(host->hostname.item));
							return -1;
						} while (false);
					}
				}
				host = host->next;
			}
		}

		fcgi_server = fcgi_server->next;
	}

#ifdef ENABLE_TOOLKIT
	if (toolkit_rules_oke(config->url_toolkit) == false) {
		return -1;
	}
#endif

	if (config->binding == NULL) {
		fprintf(stderr, "No binding defined.\n");
		return -1;
	}

	if ((config->first_host->required_binding.size > 0)
#ifdef ENABLE_SSL
		|| (config->first_host->require_ssl == true)
#endif
	) {
		fprintf(stderr,
#ifdef ENABLE_SSL
			"RequireSSL and "
#endif
			"RequiredBinding not allowed outside VirtualHost section.\n");
		return -1;
	}

	return 0;
}

static bool system_setting(char *key, char *value, t_config *config) {
	char *uid, *gid, *rest;
	t_cgi_handler *cgi;
	t_throttle *throt;
	int speed;
#ifdef ENABLE_TOMAHAWK
	t_binding *binding;
	char *port, *password;
#endif
#ifdef ENABLE_MONITOR
	t_host *monitor_host;
	char *alist;
#endif

	if (strcmp(key, "banlistmask") == 0) {
		if ((config->banlist_mask = parse_accesslist(value, false, config->banlist_mask)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "banondeniedbody") == 0) {
		if ((config->ban_on_denied_body = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonflooding") == 0) {
		if (split_string(value, &value, &rest, '/') == -1) {
		} else if ((config->flooding_count = str2int(value)) <= 0) {
		} else if (split_string(rest, &value, &rest, ':') != 0) {
		} else if ((config->flooding_time = str2int(value)) <= 0) {
		} else if ((config->ban_on_flooding = str2int(rest)) > 0) {
			return true;
		}
	} else if (strcmp(key, "banongarbage") == 0) {
		if ((config->ban_on_garbage = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banoninvalidurl") == 0) {
		if ((config->ban_on_invalid_url = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonmaxperip") == 0) {
		if ((config->ban_on_max_per_ip = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonmaxreqsize") == 0) {
		if ((config->ban_on_max_request_size = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonsqli") == 0) {
		if ((config->ban_on_sqli = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banontimeout") == 0) {
		if ((config->ban_on_timeout = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonwrongpassword") == 0) {
		if (split_string(value, &value, &rest, ':') == -1) {
		} else if ((config->max_wrong_passwords = str2int(value)) <= 0) {
		} else if ((config->ban_on_wrong_password = str2int(rest)) > 0) {
			return true;
		}
#ifdef ENABLE_CACHE
	} else if (strcmp(key, "cachemaxfilesize") == 0) {
		if ((config->cache_max_filesize = str2int(value)) != -1) {
			config->cache_max_filesize <<= 10 /* convert to kB */;
			return true;
		}
	} else if (strcmp(key, "cacheminfilesize") == 0) {
		if ((config->cache_min_filesize = str2int(value)) > 0) {
			return true;
		}
	} else if (strcmp(key, "cachesize") == 0) {
		if ((config->cache_size = str2int(value)) != -1) {
			if (config->cache_size <= MAX_CACHE_SIZE) {
				config->cache_size <<= 20 /* convert to MB */;
				return true;
			}
		}
#endif
	} else if (strcmp(key, "cgiextension") == 0) {
#ifdef CIFS
		strlower(value);
#endif
		if (parse_charlist(value, &(config->cgi_extension)) != -1) {
			return true;
		}
	} else if (strcmp(key, "cgihandler") == 0) {
		if (split_string(value, &value, &rest, ':') == 0) {
			if ((*value != '\0') && (*rest != '\0')) {
				cgi = config->cgi_handler;
				if ((config->cgi_handler = (t_cgi_handler*)malloc(sizeof(t_cgi_handler))) != NULL) {
					config->cgi_handler->next = cgi;
					if ((config->cgi_handler->handler = strdup(value)) != NULL) {
#ifdef CIFS
						strlower(rest);
#endif
						init_charlist(&(config->cgi_handler->extension));
						if (parse_charlist(rest, &(config->cgi_handler->extension)) != -1) {
							return true;
						}
					}
				}
			}
		}
	} else if (strcmp(key, "cgiwrapper") == 0) {
		if ((config->cgi_wrapper = strdup(value)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "connectionsperip") == 0) {
		if ((config->connections_per_ip = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "connectionstotal") == 0) {
		if ((config->total_connections = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "exploitlogfile") == 0) {
		if (*value == '/') {
			if ((config->exploit_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "garbagelogfile") == 0) {
		if (*value == '/') {
			if ((config->garbage_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "hideproxy") == 0) {
		if (parse_iplist(value, &(config->hide_proxy)) != -1) {
			return true;
		}
	} else if (strcmp(key, "kickonban") == 0) {
		if (parse_yesno(value, &(config->kick_on_ban)) == 0) {
			return true;
		}
	} else if (strcmp(key, "killtimedoutcgi") == 0) {
		if (parse_yesno(value, &(config->kill_timedout_cgi)) == 0) {
			return true;
		}
	} else if (strcmp(key, "logformat") == 0) {
		if (strcmp(value, "hiawatha") == 0) {
			config->log_format = hiawatha;
			return true;
		} else if (strcmp(value, "common") == 0) {
			config->log_format = common;
			return true;
		} else if (strcmp(value, "extended") == 0) {
			config->log_format = extended;
			return true;
		}
	} else if (strcmp(key, "rebanduringban") == 0) {
		if (parse_yesno(value, &(config->reban_during_ban)) == 0) {
			return true;
		}
	} else if (strcmp(key, "logfilemask") == 0) {
		if ((config->logfile_mask = parse_accesslist(value, false, config->logfile_mask)) != NULL) {
			return true;
		}
#ifdef ENABLE_LOADCHECK
	} else if (strcmp(key, "maxserverload") == 0) {
		if ((config->max_server_load = atof(value)) > 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "maxurllength") == 0) {
		if (strcmp(value, "none") == 0) {
			config->max_url_length = 0;
			return true;
		} else if ((config->max_url_length = str2int(value)) >= 0) {
			return true;
		}
	} else if (strcmp(key, "mimetypeconfig") == 0) {
		if ((config->mimetype_config = strdup(value)) != NULL) {
			return true;
		}
#ifdef ENABLE_SSL
	} else if (strcmp(key, "minsslversion") == 0) {
		if (strcasecmp(value, "ssl3.0") == 0) { 
			config->min_ssl_version = SSL_MINOR_VERSION_0;
			return true;
		} else if (strcasecmp(value, "tls1.0") == 0) { 
			config->min_ssl_version = SSL_MINOR_VERSION_1;
			return true;
		} else if (strcasecmp(value, "tls1.1") == 0) { 
			config->min_ssl_version = SSL_MINOR_VERSION_2;
			return true;
		} else if (strcasecmp(value, "tls1.2") == 0) { 
			config->min_ssl_version = SSL_MINOR_VERSION_3;
			return true;
		}
#endif
#ifdef ENABLE_MONITOR
	} else if (strcmp(key, "monitorserver") == 0) {
		monitor_host = new_host();
		monitor_host->next = config->first_host->next;
		config->first_host->next = monitor_host;

		if (parse_charlist(MONITOR_HOSTNAME, &(monitor_host->hostname)) == -1) {
			return false;
		}

		monitor_host->website_root = config->monitor_directory;
		monitor_host->website_root_len = strlen(monitor_host->website_root);

		if ((monitor_host->access_logfile = strdup(LOG_DIR"/monitor-access.log")) == NULL) {
			return false;
		} else if ((monitor_host->error_logfile = strdup(LOG_DIR"/monitor-error.log")) == NULL) {
			return false;
		}


		rest = "allow %s, deny all";
		if ((alist = (char*)malloc(strlen(rest) + strlen(value) + 1)) == NULL) {
			return false;
		}
		sprintf(alist, rest, value);
		if ((monitor_host->access_list = parse_accesslist(alist, false, NULL)) == NULL) {
			return false;
		}
		free(alist);

#ifdef ENABLE_XSLT
		if ((monitor_host->show_index = strdup("xml")) == NULL) {
			return false;
		}
#endif

		monitor_host->monitor_host = true;
		config->monitor_enabled = true;

		return true;
	} else if (strcmp(key, "monitorstatsinterval") == 0) {
		if ((config->monitor_stats_interval = str2int(value)) > 0) {
			if (config->monitor_stats_interval < 360) {
				config->monitor_stats_interval *= MINUTE;
				return true;
			}
		}
#endif
	} else if (strcmp(key, "pidfile") == 0) {
		if (*value == '/') {
			if ((config->pidfile = strdup(value)) != NULL) {
				return true;
			}
		}
#ifdef CYGWIN
	} else if (strcmp(key, "platform") == 0) {
		if (strcmp(value, "windows") == 0) {
			config->platform = windows;
			return true;
		} else if (strcmp(value, "cygwin") == 0) {
			config->platform = cygwin;
			return true;
		}
#endif
	} else if (strcmp(key, "reconnectdelay") == 0) {
		if ((config->reconnect_delay = str2int(value)) > 0) {
			return true;
		}
	} else if (strcmp(key, "requestlimitmask") == 0) {
		if ((config->request_limit_mask = parse_accesslist(value, false, config->request_limit_mask)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "serverid") == 0) {
		split_string(value, &uid, &gid, ':');
		if (parse_userid(uid, &(config->server_uid)) == 1) {
			if (gid != NULL) {
				if (parse_groups(gid, &(config->server_gid), &(config->groups)) == 1) {
					return true;
				}
			} else {
				if (lookup_group_ids(config->server_uid, &(config->server_gid), &(config->groups)) == 1) {
					return true;
				}
			}
		}
	} else if (strcmp(key, "serverstring") == 0) {
		if ((strcmp(value, "none") == 0) || (strcmp(value, "null") == 0)) {
			config->server_string = NULL;
			return true;
		} else if (strlen(value) < 128) {
			if ((config->server_string = strdup(remove_spaces(value))) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "socketsendtimeout") == 0) {
		if ((config->socket_send_timeout = str2int(value)) >= 0) {
			return true;
		}
	} else if (strcmp(key, "systemlogfile") == 0) {
		if (*value == '/') {
			if ((config->system_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "throttle") == 0) {
		if (split_string(value, &rest, &value, ':') != -1) {
			if (((*rest == '.') || (strchr(rest, '/') != NULL)) && (speed = str2int(value)) > 0) {
				if (config->throttle == NULL) {
					if ((config->throttle = (t_throttle*)malloc(sizeof(t_throttle))) == NULL) {
						return false;
					}
					throt = config->throttle;
				} else {
					throt = config->throttle;
					while (throt->next != NULL) {
						throt = throt->next;
					}
					if ((throt->next = (t_throttle*)malloc(sizeof(t_throttle))) == NULL) {
						return false;
					}
					throt = throt->next;
				}
				throt->next = NULL;

				if ((throt->filetype = strlower(strdup(rest))) != NULL) {
					throt->upload_speed = speed << 10; /* convert to kB/s */
					return true;
				}
			}
		}
#ifdef ENABLE_TOMAHAWK
	} else if (strcmp(key, "tomahawk") == 0) {
		if (split_string(value, &port, &password, ',') == 0) {
			binding = new_binding();
			set_to_localhost(&(binding->interface));

			binding->next = config->tomahawk_port;
			config->tomahawk_port = binding;

			if ((config->tomahawk_port->port = str2int(port)) > 0) {
				if ((config->tomahawk_port->binding_id = strdup(password)) != NULL) {
					return true;
				}
			} else {
				free(config->tomahawk_port);
			}
		}
#endif
	} else if (strcmp(key, "userdirectory") == 0) {
		if ((*value != '/') && (strchr(value, '.') == NULL)) {
			if ((config->user_directory = strdup(value)) != NULL) {
				config->user_directory_set = true;
				return true;
			}
		}
	} else if (strcmp(key, "waitforcgi") == 0) {
		if (parse_yesno(value, &(config->wait_for_cgi)) == 0) {
			return true;
		}
	} else if (strcmp(key, "workdirectory") == 0) {
		if (valid_directory(value) == false) {
			return false;
		} else if (strchr(value + 1, '/') == NULL) {
			return false;
		} else if ((config->work_directory = strdup(value)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "wrapusercgi") == 0) {
		if (parse_yesno(value, &(config->wrap_user_cgi)) == 0) {
			return true;
		}
	}

	return false;
}

static bool user_setting(char *key, char *value, t_host *host, t_tempdata **tempdata) {
	char *pwd = NULL, *grp = NULL;
	t_error_handler *handler;
	t_keyvalue *kv;

	if (strcmp(key, "accesslist") == 0) {
		if ((host->access_list = parse_accesslist(value, true, host->access_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altergroup") == 0) {
		if (parse_charlist(value, &(host->alter_group)) != -1) {
			return true;
		}
	} else if (strcmp(key, "alterlist") == 0) {
		if ((host->alter_list = parse_accesslist(value, true, host->alter_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altermode") == 0) {
		if (parse_mode(value, &(host->alter_fmode)) != -1) {
			return true;
		}
	} else if (strcmp(key, "errorhandler") == 0) {
		if (parse_error_handler(value, &(host->error_handlers)) == -1) {
			return false;
		}

		if (register_tempdata(tempdata, host->error_handlers, tc_errorhandler) == -1) {
			handler = host->error_handlers;
			host->error_handlers = host->error_handlers->next;
			remove_error_handler(handler);
			return false;
		}

		return true;
	} else if (strcmp(key, "loginmessage") == 0) {
		if (strlen(value) < 64) {
			if ((host->login_message = strdup(value)) != NULL) {
				if (register_tempdata(tempdata, host->login_message, tc_data) != -1) {
					return true;
				} else {
					free(host->login_message);
					host->login_message = NULL;
				}
			}
		}
	} else if (strcmp(key, "passwordfile") == 0) {
		if (parse_credentialfiles(value, &(host->auth_method), &pwd, &grp) == 0) {
			if (pwd != NULL) {
				if (register_tempdata(tempdata, pwd, tc_data) == -1) {
					free(pwd);
					if (grp != NULL) {
						free(grp);
					}
					return false;
				}
				host->passwordfile = pwd;
			}
			if (grp != NULL) {
				if (register_tempdata(tempdata, grp, tc_data) == -1) {
					free(grp);
					return false;
				}
				host->groupfile = grp;
			}
			return true;
		}
	} else if (strcmp(key, "requiredgroup") == 0) {
		if (parse_charlist(value, &(host->required_group)) != -1) {
			return true;
		}
#ifdef ENABLE_SSL
	} else if (strcmp(key, "requiressl") == 0) {
		if (parse_yesno(value, &(host->require_ssl)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "runonalter") == 0) {
		if ((host->run_on_alter = strdup(value)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "setenv") == 0) {
		if (parse_keyvalue(value, &(host->envir_str), "=") != -1) {
			if (register_tempdata(tempdata, host->envir_str, tc_keyvalue) != -1) {
				return true;
			} else {
				kv = host->envir_str;
				host->envir_str = host->envir_str->next;
				free(kv->key);
				free(kv->value);
				free(kv);
			}
		}
#ifdef ENABLE_XSLT
	} else if (strcmp(key, "showindex") == 0) {
		if (strcmp(value, "yes") == 0) {
			host->show_index = index_xslt;
			return true;
		} else if (strcmp(value, "no") == 0) {
			host->show_index = NULL;
			return true;
		} else if ((*value == '/') || (strcmp(value, "xml") == 0)) {
			if ((host->show_index = strdup(value)) != NULL) {
				return true;
			}
		}
#endif
	} else if (strcmp(key, "startfile") == 0) {
		if (valid_start_file(value)) {
			if ((value = strdup(value)) != NULL) {
				if (register_tempdata(tempdata, value, tc_data) != -1) {
					host->start_file = value;
					return true;
				} else {
					free(value);
				}
			}
		}
	} else if (strcmp(key, "usegzfile") == 0) {
		if (parse_yesno(value, &(host->use_gz_file)) == 0) {
			return true;
		}
	}

	return false;
}

static bool host_setting(char *key, char *value, t_host *host) {
	char *botname;
#ifdef ENABLE_SSL
	char *rest;
#endif
	t_denybotlist *deny_bot;
	t_deny_body *deny_body;
#ifdef ENABLE_RPROXY
	t_rproxy *rproxy, *list;
#endif

	if (strcmp(key, "accesslogfile") == 0) {
		if (*value == '/') {
			if ((host->access_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "alias") == 0) {
		if (parse_keyvalue(value, &(host->alias), ":") != -1) {
			if (valid_directory(host->alias->key) && valid_directory(host->alias->value)) {
				return true;
			}
		}
	} else if (strcmp(key, "allowdotfiles") == 0) {
		if (parse_yesno(value, &(host->allow_dot_files)) == 0) {
			return true;
		}
	} else if (strcmp(key, "customheader") == 0) {
		if (parse_keyvalue(value, &(host->custom_headers), ":") != -1) {
			return true;
		}
	} else if (strcmp(key, "denybody") == 0) {
		if (host->deny_body == NULL) {
			host->deny_body = (t_deny_body*)malloc(sizeof(t_deny_body));
			deny_body = host->deny_body;
		} else {
			deny_body = host->deny_body;
			while (deny_body->next != NULL) {
				deny_body = deny_body->next;
			}
			deny_body->next = (t_deny_body*)malloc(sizeof(t_deny_body));
			deny_body = deny_body->next;
		}
		if (deny_body != NULL) {
			deny_body->next = NULL;
			if (regcomp(&(deny_body->pattern), value, REG_EXTENDED | REG_NOSUB) == 0) {
				return true;
			}
		}
	} else if (strcmp(key, "denybot") == 0) {
		if (split_string(value, &botname, &value, ':') == 0) {
			if ((deny_bot = (t_denybotlist*)malloc(sizeof(t_denybotlist))) != NULL) {
				deny_bot->next = host->deny_bot;
				host->deny_bot = deny_bot;

				init_charlist(&(deny_bot->uri));
				if ((deny_bot->bot = strdup(botname)) != NULL) {
					if (parse_charlist(value, &(deny_bot->uri)) == 0) {
						return true;
					}
				}
			}
		}
	} else if (strcmp(key, "enablepathinfo") == 0) {
		if (parse_yesno(value, &(host->enable_path_info)) == 0) {
			return true;
		}
	} else if (strcmp(key, "errorlogfile") == 0) {
		if (*value == '/') {
			if ((host->error_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "executecgi") == 0) {
		if (parse_yesno(value, &(host->execute_cgi)) == 0) {
			return true;
		}
	} else if (strcmp(key, "followsymlinks") == 0) {
		if (parse_yesno(value, &(host->follow_symlinks)) == 0) {
			return true;
		}
	} else if (strcmp(key, "hostname") == 0) {
		strlower(value);
#ifdef ENABLE_MONITOR
		if (strcmp(value, MONITOR_HOSTNAME) == 0) {
			return false;
		}
#endif
		if (parse_charlist(value, &(host->hostname)) == 0) {
			return true;
		}
	} else if (strcmp(key, "imagereferer") == 0) {
		if (split_string(value, &value, &(host->imgref_replacement), ':') == 0) {
			if ((host->imgref_replacement = strdup(host->imgref_replacement)) != NULL) {
				if (parse_charlist(value, &(host->image_referer)) == 0) {
					return true;
				}
			}
		}
#ifdef ENABLE_MONITOR
	} else if (strcmp(key, "monitorrequests") == 0) {
		if (parse_yesno(value, &(host->monitor_requests)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "noextensionas") == 0) {
		if ((host->no_extension_as = strdup(value)) != NULL) {
			return true;
		}
	} else if ((strcmp(key, "preventcsrf") == 0) || (strcmp(key, "preventxsrf") == 0)) {
		if (parse_yesno(value, &(host->prevent_csrf)) == 0) {
			return true;
		}
	} else if (strcmp(key, "preventsqli") == 0) {
		if (parse_yesno(value, &(host->prevent_sqli)) == 0) {
			return true;
		}
	} else if (strcmp(key, "preventxss") == 0) {
		if (parse_yesno(value, &(host->prevent_xss)) == 0) {
			return true;
		}
	} else if (strcmp(key, "requiredbinding") == 0) {
		if (parse_charlist(value, &(host->required_binding)) == 0) {
			return true;
		}
#ifdef ENABLE_SSL
	} else if (strcmp(key, "requiredca") == 0) {
		split_string(value, &value, &rest, ',');
		if ((host->ca_cert_file = strdup(value)) != NULL) {
			if (rest != NULL) {
				if ((host->ca_crl_file = strdup(rest)) == NULL) {
					return false;
				}
			}
			return true;
		}
#endif
#ifdef ENABLE_RPROXY
	} else if (strcmp(key, "reverseproxy") == 0) {
		if ((rproxy = rproxy_setting(value)) != NULL) {
			if (host->rproxy == NULL) {
				host->rproxy = rproxy;
				return true;
			} else {
				list = host->rproxy;
				while (list->next != NULL) {
					list = list->next;
				}
				list->next = rproxy;
				return true;
			}
		}
#endif
	} else if (strcmp(key, "secureurl") == 0) {
		if (parse_yesno(value, &(host->secure_url)) == 0) {
			return true;
		}
#ifdef ENABLE_SSL
	} else if (strcmp(key, "sslcertfile") == 0) {
		if ((host->key_cert_file = strdup(value)) != NULL) {
			return true;
		}
#endif
	} else if (strcmp(key, "timeforcgi") == 0) {
		if ((host->time_for_cgi = str2int(value)) > TIMER_OFF) {
			return true;
		}
	} else if (strcmp(key, "triggeroncgistatus") == 0) {
		if (parse_yesno(value, &(host->trigger_on_cgi_status)) == 0) {
			return true;
		}
	} else if (strcmp(key, "usefastcgi") == 0) {
		if (parse_charlist(value, &(host->fast_cgi)) != -1) {
			host->execute_cgi = true;
			return true;
		}
#ifdef ENABLE_TOOLKIT
	} else if (strcmp(key, "usetoolkit") == 0) {
		if (parse_charlist(value, &(host->toolkit_rules)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "userwebsites") == 0) {
		if (parse_yesno(value, &(host->user_websites)) == 0) {
			return true;
		}
#ifdef ENABLE_XSLT
	} else if (strcmp(key, "usexslt") == 0) {
		if (parse_yesno(value, &(host->use_xslt)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "volatileobject") == 0) {
		if (*value == '/') {
			host->volatile_object.size++;
			if ((host->volatile_object.item = (char**)realloc(host->volatile_object.item, host->volatile_object.size * sizeof(char*))) != NULL) {
				if ((*(host->volatile_object.item + host->volatile_object.size - 1) = strdup(value)) != NULL) {
					return true;
				}
			}
		}
	} else if (strcmp(key, "webdavapp") == 0) {
		if (parse_yesno(value, &(host->webdav_app)) == 0) {
			if (host->webdav_app) {
				host->execute_cgi = true;
				host->enable_path_info = true;
			}
			return true;
		}
	} else if (strcmp(key, "websiteroot") == 0) {
		if (valid_directory(value)) {
			if ((host->website_root = strdup(value)) != NULL) {
				host->website_root_len = strlen(host->website_root);
				return true;
			}
		}
	} else if (strcmp(key, "wrapcgi") == 0) {
		if ((host->wrap_cgi = strdup(value)) != NULL) {
			return true;
		}
	}

	return false;
}

static bool directory_setting(char *key, char *value, t_directory *directory) {
	char *maxclients;
	size_t length;

	if (strcmp(key, "accesslist") == 0) {
		if ((directory->access_list = parse_accesslist(value, true, directory->access_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altergroup") == 0) {
		if (parse_charlist(value, &(directory->alter_group)) != -1) {
			return true;
		}
	} else if (strcmp(key, "alterlist") == 0) {
		if ((directory->alter_list = parse_accesslist(value, true, directory->access_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altermode") == 0) {
		if (parse_mode(value, &(directory->alter_fmode)) != -1) {
			return true;
		}
	} else if (strcmp(key, "wrapcgi") == 0) {
		if ((directory->wrap_cgi = strdup(value)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "executecgi") == 0) {
		if (parse_yesno(value, &(directory->execute_cgi)) == 0) {
			directory->execute_cgiset = true;
			return true;
		}
	} else if (strcmp(key, "followsymlink") == 0) {
		if (parse_yesno(value, &(directory->follow_symlinks)) == 0) {
			directory->follow_symlinks_set = true;
			return true;
		}
	} else if (strcmp(key, "imagereferer") == 0) {
		if (split_string(value, &value, &(directory->imgref_replacement), ':') == 0) {
			if ((directory->imgref_replacement = strdup(directory->imgref_replacement)) != NULL) {
				if (parse_charlist(value, &(directory->image_referer)) == 0) {
					return true;
				}
			}
		}
	} else if (strcmp(key, "passwordfile") == 0) {
		if (parse_credentialfiles(value, &(directory->auth_method), &(directory->passwordfile), &(directory->groupfile)) == 0) {
			return true;
		}
	} else if (strcmp(key, "path") == 0) {
		if (directory->path != NULL) {
			return false;
		}
		length = strlen(value);
		if ((length < 128) && (*value == '/')) {
			if (*(value + length - 1) == '/') {
				if (length >= 3) {
					directory->path_match = part;
					if ((directory->path = strdup(value)) != NULL) {
						return true;
					}
				}
			} else {
				if (length >= 2) {
					directory->path_match = root;
					if ((directory->path = (char*)malloc(length + 2)) != NULL) {
						memcpy(directory->path, value, length);
						memcpy(directory->path + length, "/\0", 2);
						return true;
					}
				}
			}
		}
	} else if (strcmp(key, "requiredgroup") == 0) {
		if (parse_charlist(value, &(directory->required_group)) != -1) {
			return true;
		}
	} else if (strcmp(key, "runondownload") == 0) {
		if ((directory->run_on_download = strdup(value)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "setenv") == 0) {
		if (parse_keyvalue(value, &(directory->envir_str), "=") != -1) {
			return true;
		}
#ifdef ENABLE_XSLT
	} else if (strcmp(key, "showindex") == 0) {
		if (strcmp(value, "yes") == 0) {
			directory->show_index = index_xslt;
			directory->show_index_set = true;
			return true;
		} else if (strcmp(value, "no") == 0) {
			directory->show_index = NULL;
			directory->show_index_set = true;
			return true;
		} else if ((*value == '/') || (strcmp(value, "xml") == 0)) {
			if ((directory->show_index = strdup(value)) != NULL) {
				directory->show_index_set = true;
				return true;
			}
		}
#endif
	} else if (strcmp(key, "startfile") == 0) {
		if (valid_start_file(value)) {
			if ((directory->start_file = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "timeforcgi") == 0) {
		if ((directory->time_for_cgi = str2int(value)) > TIMER_OFF) {
			return true;
		}
	} else if (strcmp(key, "uploadspeed") == 0) {
		if (split_string(value, &value, &maxclients, ',') == 0) {
			if ((directory->upload_speed = str2int(value)) > 0) {
				directory->upload_speed <<= 10 /* convert to kB/s */;
				if ((directory->max_clients = str2int(maxclients)) > 0) {
					return true;
				}
			}
		}
	} else if (strcmp(key, "usegzfile") == 0) {
		if (parse_yesno(value, &(directory->use_gz_file)) == 0) {
			directory->use_gz_file_set = true;
			return true;
		}
	}

	return false;
}

static bool binding_setting(char *key, char *value, t_binding *binding) {
	char *rest;

	if (strcmp(key, "enablealter") == 0) {
		if (parse_yesno(value, &(binding->enable_alter)) == 0) {
			return true;
		}
	}else if (strcmp(key, "enabletrace") == 0) {
		if (parse_yesno(value, &(binding->enable_trace)) == 0) {
			return true;
		}
	} else if (strcmp(key, "interface") == 0) {
		if (parse_ip(value, &(binding->interface)) != -1) {
			return true;
		}
	} else if (strcmp(key, "maxkeepalive") == 0) {
		if ((binding->max_keepalive = str2int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "maxrequestsize") == 0) {
		if ((binding->max_request_size = str2int(value)) > 0) {
			binding->max_request_size <<= 10 /* convert to kB */;
			return true;
		}
	} else if (strcmp(key, "maxuploadsize") == 0) {
		if ((binding->max_upload_size = str2int(value)) > 0) {
			if (binding->max_upload_size <= MAX_UPLOAD_SIZE) {
				binding->max_upload_size <<= 20 /* convert to MB */;
				return true;
			}
		}
	} else if (strcmp(key, "bindingid") == 0) {
		if (binding->binding_id == NULL) {
			if ((binding->binding_id = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "port") == 0) {
		if ((binding->port = str2int(value)) > 0) {
			if (binding->port < 65536) {
				return true;
			}
		}
#ifdef ENABLE_SSL
	} else if (strcmp(key, "requiredca") == 0) {
		split_string(value, &value, &rest, ',');
		if ((binding->ca_cert_file = strdup(value)) != NULL) {
			if (rest != NULL) {
				if ((binding->ca_crl_file = strdup(rest)) == NULL) {
					return false;
				}
			}
			return true;
		}
	} else if (strcmp(key, "sslcertfile") == 0) {
		if ((binding->key_cert_file = strdup(value)) != NULL) {
			binding->use_ssl = true;
			return true;
		}
#endif
	} else if (strcmp(key, "timeforrequest") == 0) {
		if (split_string(value, &value, &rest, ',') == 0) {
			if ((binding->time_for_1st_request = str2int(value)) >= 1) {
				if ((binding->time_for_request = str2int(rest)) >= 1) {
					return true;
				}
			}
		} else if ((binding->time_for_request = str2int(value)) >= 1) {
			binding->time_for_1st_request = binding->time_for_request;
			return true;
		}
	}

	return false;
}

static bool fcgi_server_setting(char *key, char *value, t_fcgi_server *fcgi_server) {
	char *rest;
	t_connect_to *connect_to;

	if (strcmp(key, "connectto") == 0) {
		while (value != NULL) {
			split_string(value, &value, &rest, ',');

			if ((connect_to = (t_connect_to*)malloc(sizeof(t_connect_to))) == NULL) {
				return false;
			}
			connect_to->next = fcgi_server->connect_to;
			connect_to->available = true;
			fcgi_server->connect_to = connect_to;

			if (*value == '/') {
				if ((connect_to->unix_socket = strdup(value)) == NULL) {
					return false;
				}
			} else {
				connect_to->unix_socket = NULL;
				if (parse_ip_port(value, &(connect_to->ip_addr), &(connect_to->port)) == -1) {
					return false;
				}
			}
			value = rest;
		}
		return true;
	} else if (strcmp(key, "extension") == 0) {
#ifdef CIFS
		strlower(value);
#endif
		if (parse_charlist(value, &(fcgi_server->extension)) != -1) {
			return true;
		}
	} else if (strcmp(key, "fastcgiid") == 0) {
		if (fcgi_server->fcgi_id == NULL) {
			if ((fcgi_server->fcgi_id = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "serverroot") == 0) {
		if ((fcgi_server->chroot = strdup(value)) != NULL) {
			fcgi_server->chroot_len = strlen(fcgi_server->chroot);
			return true;
		}
	} else if (strcmp(key, "sessiontimeout") == 0) {
		if ((fcgi_server->session_timeout = MINUTE * str2int(value)) >= 0) {
			return true;
		}
	}

	return false;
}

static int read_config_directory(char *dir, t_config *config, bool config_check) {
	t_filelist *filelist, *file;
	char *path;
	int retval = 0;

	if ((filelist = read_filelist(dir)) == NULL) {
		return -1;
	}
	file = filelist = sort_filelist(filelist);

	while (file != NULL) {
		if (strcmp(file->name, "..") != 0) {
			if ((path = make_path(dir, file->name)) != NULL) {
				if (file->is_dir) {
					retval = read_config_directory(path, config, config_check);
				} else {
					retval = read_main_configfile(path, config, config_check);
				}
				free(path);

				if (retval == -1) {
					break;
				}
			} else {
				retval = -1;
				break;
			}
		}
		file = file->next;
	}
	remove_filelist(filelist);

	return retval;
}

int read_main_configfile(char *configfile, t_config *config, bool config_check) {
	int  retval = 0, counter = 0, lines_read;
	FILE *fp;
	char line[MAX_LENGTH_CONFIGLINE + 1], *key, *value;
	bool variables_replaced;
	enum t_section section = none;
	t_host *current_host;
	t_directory *current_directory = NULL;
	t_binding *current_binding = NULL;
	t_fcgi_server *current_fcgi_server = NULL;
#ifdef ENABLE_TOOLKIT
	t_url_toolkit *current_toolkit = NULL;
#endif

	/* Read and parse Hiawatha configurationfile.
	 */
	if ((fp = fopen(configfile, "r")) == NULL) {
		fprintf(stderr, "Can't read file %s.\n", configfile);
		return -1;
	} else if (config_check) {
		printf("Reading %s\n", configfile);
	}

	current_host = config->first_host;
	line[MAX_LENGTH_CONFIGLINE] = '\0';

	while ((lines_read = fgets_multi(line, MAX_LENGTH_CONFIGLINE, fp)) != 0) {
		if ((lines_read == -1) || (strlen(line) > MAX_LENGTH_CONFIGLINE - 1)) {
			retval = counter + 1;
			fprintf(stderr, "Line %d in %s is too long.\n", retval, configfile);
			break;
		}
		counter += lines_read;

		key = uncomment(line);
		if (*key != '\0') {
			variables_replaced = false;

			if (key[strlen(key) - 1] == '{') {
				/* Section start
				 */
				key[strlen(key) - 1] = '\0';
				key = strlower(remove_spaces(key));

				if (section != none) {
					retval = counter;
				} else if (strcmp(key, "binding") == 0) {
					if (config->binding != NULL) {
						current_binding = config->binding;
						while (current_binding->next != NULL) {
							current_binding = current_binding->next;
						}
						current_binding->next = new_binding();
						current_binding = current_binding->next;
					} else {
						config->binding = new_binding();
						current_binding = config->binding;
					}
					section = binding;
				} else if (strcmp(key, "directory") == 0) {
					if (config->directory != NULL) {
						current_directory = config->directory;
						while (current_directory->next != NULL) {
							current_directory = current_directory->next;
						}
						current_directory->next = new_directory();
						current_directory = current_directory->next;
					} else {
						config->directory = new_directory();
						current_directory = config->directory;
					}
					section = directory;
				} else if (strcmp(key, "fastcgiserver") == 0) {
					current_fcgi_server = new_fcgi_server();
					current_fcgi_server->next = config->fcgi_server;
					config->fcgi_server = current_fcgi_server;
					section = fcgi_server;
				} else if (strcmp(key, "virtualhost") == 0) {
					while (current_host->next != NULL) {
						current_host = current_host->next;
					}
					current_host->next = new_host();
					current_host = current_host->next;
					section = virtual_host;
#ifdef ENABLE_TOOLKIT
				} else if (strcmp(key, "urltoolkit") == 0) {
					current_toolkit = new_url_toolkit();
					current_toolkit->next = config->url_toolkit;
					config->url_toolkit = current_toolkit;
					section = url_toolkit;
#endif
				} else {
					retval = counter;
				}
			} else if (strcmp(key, "}") == 0) {
				/* Section end
				 */
				switch (section) {
					case binding:
						if (current_binding->port == -1) {
							fprintf(stderr, "A Port is missing in a binding section in %s.\n", configfile);
							retval = -1;
						} else {
							current_binding = NULL;
						}
						break;
					case directory:
						if (config->directory->path == NULL) {
							fprintf(stderr, "A Path is missing in a directory section in %s.\n", configfile);
							retval = -1;
						} else {
							current_directory = NULL;
						}
						break;
					case fcgi_server:
						if ((config->fcgi_server->fcgi_id == NULL) || (config->fcgi_server->connect_to == NULL)) {
							fprintf(stderr, "A FastCGIid or ConnectTo is missing in a FastCGIserver section in %s.\n", configfile);
							retval = -1;
						} else {
							current_fcgi_server = NULL;
						}
						break;
					case virtual_host:
						if (current_host->hostname.size == 0) {
							fprintf(stderr, "A Hostname is missing in a VirtualHost section in %s\n", configfile);
							retval = -1;
						} else if (current_host->website_root == NULL) {
							fprintf(stderr, "A WebsiteRoot is missing for %s in %s\n", current_host->hostname.item[0], configfile);
							retval = -1;
						} else {
							current_host = config->first_host;
						}
						break;
#ifdef ENABLE_TOOLKIT
					case url_toolkit:
						if (current_toolkit->toolkit_id == NULL) {
							fprintf(stderr, "A ToolkitID is missing in a UrlToolkit section in %s\n", configfile);
							retval = -1;
						} else {
							current_toolkit = NULL;
						}
						break;
#endif
					default:
						retval = counter;
				}
				section = none;
			} else if (split_configline(key, &key, &value) != -1) {
				/* Configuration option
				 */
				strlower(key);

				if (strcmp(key, "set") == 0) {
					if (parse_keyvalue(key + 4, &variables, "=") == -1) {
						retval = counter;
					}
				} else if (strcmp(key, "include") == 0) {
					value = key + 8;
#ifdef CYGWIN
					if (fix_windows_path(value, NULL) == -1) {
						retval = counter;
					} else
#endif
					{
						variables_replaced = replace_variables(&value);
						if ((section == none) && (including == false)) {
							including = true;
							switch (is_directory(value)) {
								case error:
								case no_access:
								case not_found:
									fprintf(stderr, "Error while including '%s'\n", value);
									retval = -1;
									break;
								case no:
									retval = read_main_configfile(value, config, config_check);
									break;
								case yes:
									retval = read_config_directory(value, config, config_check);
									break;
							}
							including = false;
						} else {
							retval = counter;
						}
					}
				} else if (strlen(value) > 0) {
#ifdef CYGWIN
					if (strlen(key) > 25) {
						retval = counter;
					} else if (fix_windows_path(value, key) == -1) {
						retval = counter;
					} else
#endif
					{
						variables_replaced = replace_variables(&value);
						do {
							if (section == none) {
								if (system_setting(key, value, config)) {
									break;
								}
							}
							if ((section == none) || (section == virtual_host)) {
								if (host_setting(key, value, current_host)) {
									break;
								} else if (user_setting(key, value, current_host, NULL)) {
									break;
								}
							} else if (section == directory) {
								if (directory_setting(key, value, current_directory)) {
									break;
								}
							} else if (section == binding) {
								if (binding_setting(key, value, current_binding)) {
									break;
								}
							} else if (section == fcgi_server) {
								if (fcgi_server_setting(key, value, current_fcgi_server)) {
									break;
								}
#ifdef ENABLE_TOOLKIT
							} else if (section == url_toolkit) {
								if (toolkit_setting(key, value, current_toolkit)) {
									break;
								}
#endif
							}
							retval = counter;
						} while (false);
					}
				} else {
					retval = counter;
				}
			} else {
				retval = counter;
			}

			if (variables_replaced) {
				free(value);
			}
		}
		if (retval != 0) {
			break;
		}
	} /* while */

	fclose(fp);
	if (including == false) {
		remove_keyvaluelist(variables);
		variables = NULL;
	}

	if ((retval == 0) && (section != none)) {
		retval = counter;
	}

	if (retval > 0) {
		fprintf(stderr, "Syntax error in %s on line %d.\n", configfile, retval);
		return -1;
	}

	return retval;
}

int read_user_configfile(char *configfile, t_host *host, t_tempdata **tempdata) {
	int  retval, counter, lines_read;
	FILE *fp;
	char line[MAX_LENGTH_CONFIGLINE + 1], *key, *value;
	t_accesslist *acs_list = NULL, *alt_list = NULL;
	t_charlist req_grp, alt_grp;

	if ((fp = fopen(configfile, "r")) == NULL) {
		return 0;
	}

	line[MAX_LENGTH_CONFIGLINE] = '\0';
	counter = retval = 0;

	if (tempdata != NULL) {
		acs_list = host->access_list;
		host->access_list = NULL;
		alt_list = host->alter_list;
		host->alter_list = NULL;

		copy_charlist(&alt_grp, &(host->alter_group));
		init_charlist(&(host->alter_group));
		copy_charlist(&req_grp, &(host->required_group));
		init_charlist(&(host->required_group));
	}

	while ((lines_read = fgets_multi(line, MAX_LENGTH_CONFIGLINE, fp)) != 0) {
		if ((lines_read == -1) || (strlen(line) > MAX_LENGTH_CONFIGLINE - 1)) {
			retval = counter + 1;
			fprintf(stderr, "Line %d in %s is too long.\n", retval, configfile);
			break;
		}
		counter += lines_read;

		key = uncomment(line);
		if (*key != '\0') {
			if (split_configline(key, &key, &value) != -1) {
				strlower(key);
				if (user_setting(key, value, host, tempdata) == false) {
					retval = counter;
					break;
				}
			} else {
				retval = counter;
				break;
			}
		}
	}

	fclose(fp);

	if (tempdata != NULL) {
		if (host->access_list == NULL) {
			host->access_list = acs_list;
		} else if (register_tempdata(tempdata, host->access_list, tc_accesslist) == -1) {
			host->access_list = remove_accesslist(host->access_list);
			retval = -1;
		}
		if (host->alter_list == NULL) {
			host->alter_list = alt_list;
		} else if (register_tempdata(tempdata, host->alter_list, tc_accesslist) == -1) {
			host->alter_list = remove_accesslist(host->alter_list);
			retval = -1;
		}

		if (host->alter_group.size == 0) {
			copy_charlist(&(host->alter_group), &alt_grp);
		} else if (register_tempdata(tempdata, &(host->alter_group), tc_charlist) == -1) {
			remove_charlist(&(host->alter_group));
			retval = -1;
		}
		if (host->required_group.size == 0) {
			copy_charlist(&(host->required_group), &req_grp);
		} else if (register_tempdata(tempdata, &(host->required_group), tc_charlist) == -1) {
			remove_charlist(&(host->required_group));
			retval = -1;
		}
	}

	return retval;
}

t_host *get_hostrecord(t_host *host, char *hostname, t_binding *binding) {
	size_t len_hostname;
	int i;

	if (hostname == NULL) {
		return NULL;
	}

	if ((len_hostname = strlen(hostname)) == 0) {
		return NULL;
	}

	/* Hostname ends with a dot
	 */
	if (hostname[len_hostname - 1] == '.') {
		len_hostname--;
		hostname[len_hostname] = '\0';
	}

	while (host != NULL) {
		if (host->required_binding.size > 0) {
			if (in_charlist(binding->binding_id, &(host->required_binding)) == false) {
				/* Binding not allowed
				 */
				host = host->next;
				continue;
			}
		}

		for (i = 0; i < host->hostname.size; i++) {
			if (hostname_match(hostname, *(host->hostname.item + i))) {
				return host;
			}
		}

		host = host->next;
	}

	return NULL;
}

unsigned short get_throttlespeed(char *type, t_throttle *throttle) {
	t_throttle *throt;
	unsigned long speed = 0;
	int len_type, len_throt;
	char *type_lower;

	if (type == NULL) {
		return 0;
	} else if ((type_lower = strlower(strdup(type))) == NULL) {
		return 0;
	}

	len_type = strlen(type);
	throt = throttle;
	while (throt != NULL) {
		len_throt = strlen(throt->filetype);
		if (len_type >= len_throt) {
			if (memcmp(throt->filetype, type_lower, len_throt) == 0) {
				speed = throt->upload_speed;
				break;
			}
		}
		throt = throt->next;
	}
	free(type_lower);

	return speed;
}

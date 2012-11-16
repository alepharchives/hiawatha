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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <grp.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "global.h"
#include "alternative.h"
#include "mimetype.h"
#include "serverconfig.h"
#include "libfs.h"
#include "liblist.h"
#include "libstr.h"
#include "cgi.h"
#include "userconfig.h"
#include "session.h"
#include "httpauth.h"
#include "http.h"
#include "send.h"
#include "client.h"
#include "target.h"
#include "log.h"
#include "envir.h"
#include "global.h"
#ifdef ENABLE_TOMAHAWK
#include "tomahawk.h"
#endif
#ifdef ENABLE_SSL
#include "libssl.h"
#endif
#ifdef ENABLE_CACHE
#include "cache.h"
#endif
#ifdef ENABLE_TOOLKIT
#include "toolkit.h"
#endif
#ifdef ENABLE_XSLT
#include "xslt.h"
#endif
#ifdef ENABLE_MONITOR
#include "monitor.h"
#endif

#define rs_NONE                  0
#define rs_QUIT_SERVER           1
#define rs_UNBAN_CLIENTS         2
#define rs_UNLOCK_LOGFILES       3
#define rs_CLEAR_CACHE           4

#define PTHREAD_STACK_SIZE 512 * KILOBYTE
#define LOG_PERM (S_IRUSR|S_IWUSR|S_IRGRP)
#define MAX_ADMIN_CONNECTIONS 3

typedef struct {
	char *config_dir;
	bool daemon;
	bool config_check;
} t_settings;

static volatile int received_signal = rs_NONE;
static bool must_quit = false;
#ifdef ENABLE_MONITOR
static int open_connections = 0;
#endif
#ifdef ENABLE_LOADCHECK
static double current_server_load = 0;
#endif

char *hs_conlen      = "Content-Length: "; /* 16 */
char *hs_forwarded   = "X-Forwarded-For:"; /* 16 */
char *fb_filesystem  = "access denied via filesystem";
char *fb_symlink     = "symlink not allowed";
char *fb_accesslist  = "access denied via accesslist";
char *fb_alterlist   = "access denied via alterlist";
char *version_string = "Hiawatha v"VERSION
#ifdef ENABLE_CACHE
	", cache"
#endif
#ifdef ENABLE_DEBUG
	", debug"
#endif
#ifdef ENABLE_IPV6
	", IPv6"
#endif
#ifdef ENABLE_MONITOR
	", Monitor"
#endif
#ifdef ENABLE_RPROXY
	", reverse proxy"
#endif
#ifdef ENABLE_SSL
	", SSL"
#endif
#ifdef ENABLE_TOMAHAWK
	", Tomahawk"
#endif
#ifdef ENABLE_TOOLKIT
	", URL toolkit"
#endif
#ifdef ENABLE_XSLT
	", XSLT"
#endif
;

/* Create all logfiles with the right ownership and accessrights
 */
void touch_logfiles(t_config *config) {
	t_host *host;

	touch_logfile(config->system_logfile, LOG_PERM, config->server_uid, config->server_gid);
	if (config->garbage_logfile != NULL) {
		touch_logfile(config->garbage_logfile, LOG_PERM, config->server_uid, config->server_gid);
	}
	if (config->exploit_logfile != NULL) {
		touch_logfile(config->exploit_logfile, LOG_PERM, config->server_uid, config->server_gid);
	}
#ifdef ENABLE_DEBUG
	touch_logfile(LOG_DIR"/debug.log", LOG_PERM, config->server_uid, config->server_gid);
#endif

	host = config->first_host;
	while (host != NULL) {
		if (host->access_fileptr != NULL) {
			fflush(host->access_fileptr);
		}
		touch_logfile(host->access_logfile, LOG_PERM, config->server_uid, config->server_gid);
		touch_logfile(host->error_logfile, LOG_PERM, config->server_uid, config->server_gid);
		host = host->next;
	}
}

/* Check if the requested file is a CGI program.
 */
t_cgi_type check_target_is_cgi(t_session *session) {
	t_cgi_handler *cgi;

	session->cgi_handler = NULL;
#ifdef ENABLE_TOOLKIT
	if ((session->fcgi_server = find_fcgi_server(session->config->fcgi_server, session->toolkit_fastcgi)) != NULL) {
		session->cgi_type = fastcgi;
		session->host->execute_cgi = true;
	} else
#endif
	if ((session->fcgi_server = fcgi_server_match(session->config->fcgi_server, &(session->host->fast_cgi), session->extension)) != NULL) {
		session->cgi_type = fastcgi;
	} else if (in_charlist(session->extension, &(session->config->cgi_extension))) {
		session->cgi_type = binary;
	} else {
		session->cgi_type = no_cgi;
		cgi = session->config->cgi_handler;
		while (cgi != NULL) {
			if (in_charlist(session->extension, &(cgi->extension))) {
				session->cgi_handler = cgi->handler;
				session->cgi_type = script;
				break;
			}
			cgi = cgi->next;
		}
	}

	return session->cgi_type;
}

/* Handle an HTTP error.
 */
int handle_error(t_session *session, int error_code) {
	t_error_handler *error_handler;
	char *new_fod;
	int result = -1;

	error_handler = session->host->error_handlers;
	while (error_handler != NULL) {
		if (error_handler->code == error_code) {
			break;
		}
		error_handler = error_handler->next;
	}

	if (error_handler == NULL) {
		return 0;
	}

	session->return_code = error_code;
	session->error_code = error_code;
	session->handling_error = true;
	session->mimetype = NULL;
	session->vars = error_handler->parameters;

	if ((new_fod = (char*)malloc(session->host->website_root_len + strlen(error_handler->handler) + 4)) == NULL) { /* + 3 for .gz (gzip encoding) */
		return 500;
	}

	if (session->file_on_disk != NULL) {
		free(session->file_on_disk);
	}
	session->file_on_disk = new_fod;

	memcpy(session->file_on_disk, session->host->website_root, session->host->website_root_len);
	strcpy(session->file_on_disk + session->host->website_root_len, error_handler->handler);

	if (get_target_extension(session) == -1) {
		return 500;
	}
	check_target_is_cgi(session);

	if (session->cgi_type != no_cgi) {
		result = execute_cgi(session);
#ifdef ENABLE_XSLT
	} else if (can_transform_with_xslt(session)) {
		result = handle_xml_file(session);
#endif
	} else switch (is_directory(session->file_on_disk)) {
		case error:
			result = 500;
			break;
		case yes:
			result = 301;
			break;
		case no:
			result = send_file(session);
			break;
		case no_access:
			result = 403;
			break;
		case not_found:
			result = 404;
			break;
	}

	switch (result) {
		case 301:
			log_error(session, "ErrorHandler is a directory");
			break;
		case 403:
			log_error(session, "no access to ErrorHandler");
			break;
		case 404:
			log_error(session, "ErrorHandler not found");
			break;
		case 500:
			log_file_error(session, error_handler->handler, "internal error for ErrorHandler");
			session->keep_alive = false;
			break;
		case 503:
			log_file_error(session, error_handler->handler, "FastCGI for ErrorHandler not available");
			break;
	}

	return result;
}

/* Run a program
 */
int run_program(t_session *session, char *program, int return_code) {
	pid_t pid;
	char ip[MAX_IP_STR_LEN], value[10], *pos, slash = '/';

	switch (pid = fork()) {
		case -1:
			log_file_error(session, program, "fork() error");
			return -1;
		case 0:
			if (setsid() == -1) {
				log_file_error(session, program, "setsid() error");
			} else {
				/* Close all other open filedescriptors.
				 */
				close_bindings(session->config->binding);
				close_client_sockets_for_cgi_run();
				close_logfiles_for_cgi_run(session->config->first_host);

				/* Set environment variables
				 */
				setenv("REQUEST_METHOD", session->method, 1);
				setenv("DOCUMENT_ROOT", session->host->website_root, 1);
				setenv("REQUEST_URI", session->request_uri, 1);
				if (session->remote_user != NULL) {
					setenv("REMOTE_USER", session->remote_user, 1);
				}
				if (inet_ntop(session->ip_address.family, &(session->ip_address.value), ip, MAX_IP_STR_LEN) != NULL) {
					setenv("REMOTE_ADDR", ip, 1);
				}
				snprintf(value, 9, "%d", return_code);
				setenv("HTTP_RETURN_CODE", value, 1);

				headerfield_to_environment(session, NULL, "Range:", "HTTP_RANGE");
				headerfield_to_environment(session, NULL, "Referer:", "HTTP_REFERER");
				headerfield_to_environment(session, NULL, "User-Agent:", "HTTP_USER_AGENT");

				/* Change directory to program's directory
				 */
				pos = strrchr(program, slash);
#ifdef CYGWIN
				if ((pos == NULL) && (session->config->platform == windows)) {
					slash = '\\';
					pos = strrchr(program, slash);
				}
#endif
				if (pos != NULL) {
					*pos = '\0';
					if (chdir(program) == -1) {
						exit(EXIT_FAILURE);
					}
					*pos = slash;
				}

				/* Execute program
				 */
				execlp(program, program, (char*)NULL);
				log_file_error(session, program, "exec() error");
			}
			exit(EXIT_FAILURE);
		default:
			if (session->config->wait_for_cgi) {
				waitpid(pid, NULL, 0);
			}
	}

	return 0;
}

t_access allow_client(t_session *session) {
	char *x_forwarded_for;
	t_ip_addr forwarded_ip;
	t_access access;

	if ((access = ip_allowed(&(session->ip_address), session->host->access_list)) != allow) {
		return access;
	} else if ((x_forwarded_for = get_headerfield(hs_forwarded, session->headerfields)) == NULL) {
		return allow;
	} else if (parse_ip(x_forwarded_for, &forwarded_ip) == -1) {
		return allow;
	} else if (ip_allowed(&forwarded_ip, session->host->access_list) == deny) {
		return deny;
	}

	return unspecified;
}

/* Serve the client that connected to the webserver
 */
int serve_client(t_session *session) {
	int result, length, auth_result;
	char *search, *qmark, chr, *client_ip;
	t_host *host_record;
	t_access access;
	t_deny_body *deny_body;
	t_req_method request_method;
	t_ip_addr ip;
#ifdef ENABLE_TOOLKIT
	int i;
	t_toolkit_options toolkit_options;
#endif
#ifdef ENABLE_RPROXY
	t_rproxy *rproxy;
#endif

#ifdef ENABLE_DEBUG
	session->current_task = "fetch & parse request";
#endif

	if ((result = fetch_request(session)) != 200) {
		session->request_method = GET;
		return result;
	} else if ((result = parse_request(session, session->header_length + session->content_length)) != 200) {
		session->request_method = GET;
		return result;
	}

#ifdef ENABLE_DEBUG
	session->current_task = "serve client";
#endif

	session->time = time(NULL);

	/* Hide reverse proxies
	 */
	if (in_iplist(session->config->hide_proxy, &(session->ip_address))) {
		if ((client_ip = get_headerfield(hs_forwarded, session->headerfields)) != NULL) {
			if ((search = strrchr(client_ip, ',')) != NULL) {
				client_ip = search + 1;
			}

			while ((*client_ip == ' ') && (*client_ip != '\0')) {
				client_ip++;
			}

			if (*client_ip != '\0') {
				if (parse_ip(client_ip, &ip) != -1) {
					if (reposition_client(session, &ip) != -1) {
						copy_ip(&(session->ip_address), &ip);
					}
				}
			}
		}
	}

	/* Find host record
	 */
	if (session->hostname != NULL) {
		remove_port_from_hostname(session->hostname, session->binding);

		if ((host_record = get_hostrecord(session->config->first_host, session->hostname, session->binding)) != NULL) {
			session->host = host_record;
#ifdef ENABLE_TOMAHAWK
			session->last_host = host_record;
#endif
		}
	}
	session->host->access_time = session->time;

	/* Reject bots
	 */
	if (client_is_rejected_bot(session)) {
		log_error(session, "bot rejected");
		return 403;
	}

	/* Enforce usage of SSL
	 */
#ifdef ENABLE_SSL
	if (session->host->require_ssl && (session->binding->use_ssl == false)) {
		if ((qmark = strchr(session->uri, '?')) != NULL) {
			*qmark = '\0';
			session->vars = qmark + 1;
			session->uri_len = strlen(session->uri);
		}
		session->cause_of_301 = require_ssl;
		return 301;
	}
#endif

	/* Deny matching bodies
	 */
	if (session->body != NULL) {
		chr = *(session->body + session->content_length);
		*(session->body + session->content_length) = '\0';

		deny_body = session->host->deny_body;
		while (deny_body != NULL) {
			if (strpcmp(session->body, &(deny_body->pattern)) == 0) {
				if ((session->config->ban_on_denied_body > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
					ban_ip(&(session->ip_address), session->config->ban_on_denied_body, session->config->kick_on_ban);
					log_system(session, "Client banned because of denied body");
#ifdef ENABLE_MONITOR
					if (session->config->monitor_enabled) {
						monitor_counter_ban(session);
					}
#endif
				}

				log_exploit_attempt(session, "denied body", session->body);
#ifdef ENABLE_TOMAHAWK
				increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_counter_exploit_attempt(session);
				}
#endif

				*(session->body + session->content_length) = chr;

				return 403;
			}
			deny_body = deny_body->next;
		}

		*(session->body + session->content_length) = chr;
	}

#ifdef ENABLE_RPROXY
	/* Reverse proxy
	 */
	rproxy = session->host->rproxy;
	while (rproxy != NULL) {
		if (rproxy_match(rproxy, session->request_uri)) {
			if (rproxy_loop_detected(session->headerfields)) {
				return 508;
			}

			if ((qmark = strchr(session->uri, '?')) != NULL) {
				*qmark = '\0';
				session->vars = qmark + 1;
			}

			if (validate_url(session) == false) {
				return -1;
			}

			if ((session->vars != NULL) && (session->host->secure_url)) {
				if (forbidden_chars_present(session->vars)) {
					return 403;
				}
			}

			if (duplicate_host(session) == false) {
				return 500;
			} else if ((result = uri_to_path(session)) != 200) {
				return result;
			} else if (load_user_config(session) == -1) {
				return 500;
			} else if ((result = copy_directory_settings(session)) != 200) {
				return result;
			}

			switch (access = allow_client(session)) {
				case deny:
					log_error(session, fb_accesslist);
					return 403;
				case allow:
					break;
				case pwd:
				case unspecified:
					if ((auth_result = http_authentication_result(session, access == unspecified)) != 200) {
						return auth_result;
					}
			}

			if (session->host->prevent_xss) {
				prevent_xss(session);
			}

			if (session->host->prevent_csrf) {
				prevent_csrf(session);
			}

			if (session->host->prevent_sqli) {
				if ((result = prevent_sqli(session)) != 0) {
					return result;
				}
			}

			return proxy_request(session, rproxy);
		}

		rproxy = rproxy->next;
	}
#endif

	/* Actions based on request method
	 */
	switch (session->request_method) {
		case TRACE:
			if (session->binding->enable_trace == false) {
				return 501;
			}
			return handle_trace_request(session);
		case PUT:
		case DELETE:
			if ((session->binding->enable_alter == false) && (session->host->webdav_app == false)) {
				return 501;
			}
			break;
		case unknown:
			return 400;
		case unsupported:
			if (session->host->webdav_app == false) {
				return 501;
			}
			break;
		default:
			break;
	}

#ifdef ENABLE_TOOLKIT
	/* URL toolkit
	 */
#ifdef ENABLE_SSL
	init_toolkit_options(&toolkit_options, session->host->website_root, session->config->url_toolkit,
	                     session->binding->use_ssl, session->host->allow_dot_files, session->headerfields);
#else
	init_toolkit_options(&toolkit_options, session->host->website_root, session->config->url_toolkit,
	                     session->host->allow_dot_files, session->headerfields);
#endif

	if ((session->request_method != PUT) && (session->request_method != DELETE)) {
		for (i = 0; i < session->host->toolkit_rules.size; i++) {
			if ((result = use_toolkit(session->uri, session->host->toolkit_rules.item[i], &toolkit_options)) == UT_ERROR) {
				return 500;
			}

			if ((toolkit_options.ban > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				ban_ip(&(session->ip_address), toolkit_options.ban, session->config->kick_on_ban);
				log_system(session, "Client banned because of URL match in UrlToolkit rule");
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_counter_ban(session);
				}
#endif
				return 403;
			}

			session->toolkit_fastcgi = toolkit_options.fastcgi_server;
			if (toolkit_options.new_url != NULL) {
				if (register_tempdata(&(session->tempdata), toolkit_options.new_url, tc_data) == -1) {
					free(toolkit_options.new_url);
					return 500;
				}
				session->uri = toolkit_options.new_url;
			}

			if (result == UT_REDIRECT) {
				if ((session->location = strdup(toolkit_options.new_url)) == NULL) {
					return -1;
				}
				session->cause_of_301 = location;
				return 301;
			}

			if (result == UT_DENY_ACCESS) {
				log_error(session, "access denied via URL toolkit rule");
				return 403;
			}

			if (toolkit_options.expire > -1) {
				session->expires = toolkit_options.expire;
			}
		}
	}
#endif

	/* Find GET data
	 */
	if ((qmark = strchr(session->uri, '?')) != NULL) {
		*qmark = '\0';
		session->vars = qmark + 1;
	}

	url_decode(session->uri);
	session->uri_len = strlen(session->uri);

	if ((session->vars != NULL) && (session->host->secure_url)) {
		if (forbidden_chars_present(session->vars)) {
			return 403;
		}
	}

	if (duplicate_host(session) == false) {
		return 500;
	}

	if (validate_url(session) == false) {
		return -1;
	}

	if ((result = uri_to_path(session)) != 200) {
		return result;
	}

	/* Load configfile from directories
	 */
	if (load_user_config(session) == -1) {
		return 500;
	}

	if ((result = copy_directory_settings(session)) != 200) {
		return result;
	}

	switch (access = allow_client(session)) {
		case deny:
			log_error(session, fb_accesslist);
			return 403;
		case allow:
			break;
		case pwd:
		case unspecified:
			if ((auth_result = http_authentication_result(session, access == unspecified)) != 200) {
				return auth_result;
			}
	}

	switch (is_directory(session->file_on_disk)) {
		case error:
			return 500;
		case yes:
			session->uri_is_dir = true;
			break;
		case no:
			if (((session->request_method != PUT) || session->host->webdav_app) && (session->host->enable_path_info)) {
				if ((result = get_path_info(session)) != 200) {
					return result;
				}
			}
			break;
		case no_access:
			log_error(session, fb_filesystem);
			return 403;
		case not_found:
			if (session->request_method == DELETE) {
				return 404;
			}
	}

#ifdef ENABLE_TOOLKIT
	if ((session->toolkit_fastcgi == NULL) && session->uri_is_dir) {
#else
	if (session->uri_is_dir) {
#endif
		length = strlen(session->file_on_disk);
		if (*(session->file_on_disk + length - 1) == '/') {
			strcpy(session->file_on_disk + length, session->host->start_file);
		} else {
			return 301;
		}
	}

	if (get_target_extension(session) == -1) {
		return 500;
	}

	if (((session->request_method != PUT) && (session->request_method != DELETE)) || session->host->webdav_app) {
		check_target_is_cgi(session);
	}

	/* Handle request based on request method
	 */
	request_method = session->request_method;
	if (session->host->webdav_app) {
		if ((request_method == PUT) || (request_method == DELETE)) {
			request_method = POST;
		}
	}

	switch (request_method) {
		case GET:
		case HEAD:
			if (session->cgi_type != no_cgi) {
				session->body = NULL;
				result = execute_cgi(session);
#ifdef ENABLE_XSLT
			} else if (can_transform_with_xslt(session)) {
				result = handle_xml_file(session);
#endif
			} else {
				result = send_file(session);
			}
			if (result == 404) {
#ifdef ENABLE_XSLT
				if ((session->host->show_index != NULL) && (session->uri[session->uri_len - 1] == '/')) {
					result = show_index(session);
				}
#endif
#ifdef ENABLE_MONITOR
			} else if (session->config->monitor_enabled) {
				if ((result == 200) && (session->host->monitor_host)) {
					unlink(session->file_on_disk);
				}
#endif
			}

			if ((session->request_method == GET) && (session->cgi_type == no_cgi) && (session->directory != NULL)) {
				if (session->directory->run_on_download != NULL) {
					run_program(session, session->directory->run_on_download, result);
				}
			}
			break;
		case POST:
		case unsupported:
			if (session->cgi_type != no_cgi) {
				result = execute_cgi(session);
#ifdef ENABLE_XSLT
			} else if (can_transform_with_xslt(session)) {
				result = handle_xml_file(session);
#endif
			} else {
				result = 405;
			}
			break;
		case PUT:
			result = handle_put_request(session);
			if (((result == 201) || (result == 204)) && (session->host->run_on_alter != NULL)) {
				run_program(session, session->host->run_on_alter, result);
			}
			break;
		case DELETE:
			result = handle_delete_request(session);
			if ((result == 204) && (session->host->run_on_alter != NULL)) {
				run_program(session, session->host->run_on_alter, result);
			}
			break;
		default:
			result = 400;
	}

	return result;
}

/* Handle timeout upon sending request
 */
void handle_timeout(t_session *session) {
	if ((session->config->ban_on_timeout > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
		ban_ip(&(session->ip_address), session->config->ban_on_timeout, session->config->kick_on_ban);
		log_system(session, "Client banned because of connection timeout");
#ifdef ENABLE_MONITOR
		if (session->config->monitor_enabled) {
			monitor_counter_ban(session);
		}
#endif
	} else {
		log_system(session, "Timeout while waiting for request");
	}
}

/* Request has been handled, handle the return code.
 */
void handle_request_result(t_session *session, int result) {
#ifdef ENABLE_DEBUG
	session->current_task = "handle request result";
#endif

	if (result == -1) switch (session->error_cause) {
		case ec_MAX_REQUESTSIZE:
			log_system(session, "Maximum request size reached");
			session->return_code = 413;
			send_code(session);
			if ((session->config->ban_on_max_request_size > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				ban_ip(&(session->ip_address), session->config->ban_on_max_request_size, session->config->kick_on_ban);
				log_system(session, "Client banned because of sending a too large request");
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_counter_ban(session);
				}
#endif
			}
			break;
		case ec_TIMEOUT:
			if (session->kept_alive == 0) {
				session->return_code = 408;
				send_code(session);
				handle_timeout(session);
			}
			break;
		case ec_CLIENT_DISCONNECTED:
			if (session->kept_alive == 0) {
				log_system(session, "Client disconnected");
			}
			break;
		case ec_SOCKET_READ_ERROR:
			if (errno != ECONNRESET) {
				log_system(session, "Error while reading request");
			}
			break;
		case ec_SOCKET_WRITE_ERROR:
			log_request(session);
			break;
		case ec_FORCE_QUIT:
			log_system(session, "Client kicked");
			break;
		case ec_SQL_INJECTION:
			if ((session->config->ban_on_sqli > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				ban_ip(&(session->ip_address), session->config->ban_on_sqli, session->config->kick_on_ban);
				log_system(session, "Client banned because of SQL injection");
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_counter_ban(session);
				}
#endif
			}
			session->return_code = 409;
			send_code(session);
			log_request(session);
			break;
		case ec_INVALID_URL:
			if ((session->config->ban_on_invalid_url > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				ban_ip(&(session->ip_address), session->config->ban_on_invalid_url, session->config->kick_on_ban);
				log_system(session, "Client banned because of invalid URL");
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_counter_ban(session);
				}
#endif
			}
			send_code(session);
			break;
		default:
			if (session->data_sent == false) {
				session->return_code = 500;
				send_code(session);
			}
	} else switch (result) {
		case 200:
			break;
		case 201:
		case 204:
		case 304:
		case 412:
			if (session->data_sent == false) {
				session->return_code = result;
				send_header(session);
				send_buffer(session, "Content-Length: 0\r\n\r\n", 21);
			}
			break;
		case 411:
		case 413:
			session->keep_alive = false;
			if (session->data_sent == false) {
				session->return_code = result;
				send_header(session);
				send_buffer(session, "Content-Length: 0\r\n\r\n", 21);
			}
			break;
		case 400:
			log_garbage(session);
			if (session->data_sent == false) {
				session->return_code = 400;
				if (send_code(session) == -1) {
					session->keep_alive = false;
				}
			}
			if ((session->config->ban_on_garbage > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				ban_ip(&(session->ip_address), session->config->ban_on_garbage, session->config->kick_on_ban);
				log_system(session, "Client banned because of sending garbage");
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_counter_ban(session);
				}
#endif
			}
			break;
		case 401:
		case 403:
		case 404:
		case 501:
		case 503:
			if (session->data_sent == false) {
				switch (handle_error(session, result)) {
					case -1:
						session->keep_alive = false;
						break;
					case 200:
						break;
					default:
						if (session->data_sent == false) {
							session->return_code = result;
							if (send_code(session) == -1) {
								session->keep_alive = false;
							}
						}
				}
			}
			break;
		case 500:
			session->keep_alive = false;
		default:
			if (session->data_sent == false) {
				session->return_code = result;
				send_code(session);
			}
	}

	if ((result > 0) && (result != 400)) {
		log_request(session);
	} else {
		session->keep_alive = false;
	}
}

/* Handle the connection of a client.
 */
void connection_handler(t_session *session) {
	int result;
#ifdef ENABLE_SSL
	int timeout;
	t_ssl_accept_data sad;
#endif
#ifdef ENABLE_MONITOR
	int connections;

#ifdef ENABLE_DEBUG
	session->current_task = "thread started";
#endif

	connections = ++open_connections;
	if (session->config->monitor_enabled) {
		if (connections > session->config->monitor_stats.simultaneous_connections) {
			session->config->monitor_stats.simultaneous_connections = connections;
		}
	}
#endif

#ifdef ENABLE_SSL
	if (session->binding->use_ssl) {
		timeout = session->kept_alive == 0 ? session->binding->time_for_1st_request : session->binding->time_for_request;

		sad.context        = &(session->ssl_context);
		sad.client_fd      = &(session->client_socket);
		sad.private_key    = session->binding->private_key;
		sad.certificate    = session->binding->certificate;
		sad.ca_certificate = session->binding->ca_certificate;
		sad.ca_crl         = session->binding->ca_crl;

#ifdef ENABLE_DEBUG
		session->current_task = "ssl accept";
#endif
		switch (ssl_accept(&sad, timeout, session->config->min_ssl_version)) {
			case -2:
				handle_timeout(session);
				break;
			case 0:
				session->socket_open = true;
				break;
		}
	} else
#endif
		session->socket_open = true;

	if (session->socket_open) {
		do {
			result = serve_client(session);
			handle_request_result(session, result);

#ifdef ENABLE_DEBUG
			session->current_task = "request done";
#endif

			if (session->socket_open) {
				send_buffer(session, NULL, 0); /* Flush the output-buffer */
			}

#ifdef ENABLE_MONITOR
			if (session->config->monitor_enabled) {
				monitor_counter_request(session);
				if (session->host->monitor_requests && (result > 0)) {
					monitor_request(session);
				}
			}
#endif
			reset_session(session);
#ifdef ENABLE_DEBUG
			session->current_task = "session reset";
#endif

			if ((session->kept_alive > 0) && (session->config->ban_on_flooding > 0)) {
				if (client_is_flooding(session)) {
					if (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny) {
						ban_ip(&(session->ip_address), session->config->ban_on_flooding, session->config->kick_on_ban);
						log_system(session, "Client banned because of flooding");
						session->keep_alive = false;
#ifdef ENABLE_MONITOR
						if (session->config->monitor_enabled) {
							monitor_counter_ban(session);
						}
#endif
					}
				}
			}
		} while (session->keep_alive && session->socket_open);
#ifdef ENABLE_DEBUG
		session->current_task = "session done";
#endif

		destroy_session(session);
		close_socket(session);
	} else {
		close(session->client_socket);
	}

#ifdef ENABLE_MONITOR
	open_connections--;
#endif

	if (session->config->reconnect_delay > 0) {
		mark_client_for_removal(session, session->config->reconnect_delay);
	} else {
		remove_client(session, true);
	}

	/* Client session ends here
	 */
	pthread_exit(NULL);
}

/* Task-runner starts periodic tasks
 */
void task_runner(t_config *config) {
	t_ip_addr ip_addr;
	int delay = 0;
	time_t now;
#ifdef ENABLE_LOADCHECK
	FILE *load_fp = NULL;
	char load_str[50], *c;
#ifdef ENABLE_MONITOR
	int  load_monitor_timer = 0;
#endif
#endif

	do {
		sleep(1);

		if (delay == TASK_RUNNER_INTERVAL) {
			now = time(NULL);

			/* Client checks
			 */
			check_ban_list(config, now);
			check_remove_deadlines(config, now);
			remove_wrong_password_list(config);

			/* FastCGI check
			 */
			check_load_balancer(config, now);

			/* Close idle logfile handles
			 */
			close_logfiles(config->first_host, now);

#ifdef ENABLE_CACHE
			/* Cache check
			 */
			check_cache(now);
#endif

#ifdef ENABLE_MONITOR
			/* Monitor stats
			 */
			if (config->monitor_enabled) {
				monitor_stats(config, now);
			}
#endif

			delay = 0;
		} else {
			delay++;
		}

#ifdef ENABLE_TOMAHAWK
		/* Tomahawk check
		 */
		check_admin_list();
#endif

#ifdef ENABLE_LOADCHECK
		if (config->max_server_load > 0) {
			if ((load_fp = fopen("/proc/loadavg", "r")) != NULL) {
				if (fgets(load_str, 49, load_fp) != NULL) {
					load_str[49] = '\0';
					if ((c = strchr(load_str, ' ')) != NULL) {
						*c = '\0';
						current_server_load = atof(load_str);
#ifdef ENABLE_MONITOR
						if (config->monitor_enabled) {
							if ((current_server_load > config->max_server_load) && (load_monitor_timer == 0)) {
								monitor_high_server_load(current_server_load);
								load_monitor_timer = 60;
							}
						}
#endif
					} else {
						current_server_load = 0;
					}
				} else {
					current_server_load = 0;
				}

				fclose(load_fp);
			} else {
				current_server_load = 0;
			}

#ifdef ENABLE_MONITOR
			if (load_monitor_timer > 0) {
				load_monitor_timer--;
			}
#endif
		}
#endif

		switch (received_signal) {
			case rs_NONE:
				break;
			case rs_QUIT_SERVER:
				must_quit = true;
				break;
			case rs_UNBAN_CLIENTS:
				default_ipv4(&ip_addr);
				unban_ip(&ip_addr);
#ifdef ENABLE_IPV6
				default_ipv6(&ip_addr);
				unban_ip(&ip_addr);
#endif
				received_signal = rs_NONE;
				break;
			case rs_UNLOCK_LOGFILES:
				close_logfiles(config->first_host, 0);
				received_signal = rs_NONE;
				break;
#ifdef ENABLE_CACHE
			case rs_CLEAR_CACHE:
				clear_cache();
				received_signal = rs_NONE;
				break;
#endif
		}
	} while (must_quit == false);

	pthread_exit(NULL);
}

/* Signal handlers
 */
void SEGV_handler() {
	syslog(LOG_DAEMON | LOG_ALERT, "segmentation fault!");
	exit(EXIT_FAILURE);
}

void TERM_handler() {
	received_signal = rs_QUIT_SERVER;
}

void HUP_handler() {
	received_signal = rs_UNLOCK_LOGFILES;
}

void USR1_handler() {
	received_signal = rs_UNBAN_CLIENTS;
}

#ifdef ENABLE_CACHE
void USR2_handler() {
	received_signal = rs_CLEAR_CACHE;
}
#endif

/* Create a socketlist.
 */
int bind_sockets(t_binding *binding) {
	char ip_address[MAX_IP_STR_LEN], separator;
	struct sockaddr_in  saddr4;
#ifdef ENABLE_IPV6
	struct sockaddr_in6 saddr6;
#endif
	int domain, one, result;

	while (binding != NULL) {
#ifdef ENABLE_IPV6
		domain = (binding->interface.family == AF_INET ? PF_INET : PF_INET6);
#else
		domain = PF_INET;
#endif
		if ((binding->socket = socket(domain, SOCK_STREAM, 0)) == -1) {
			perror("socket()");
			return -1;
		}

		one = 1;
		if (setsockopt(binding->socket, SOL_SOCKET, SO_REUSEADDR, (void*)&one, sizeof(int)) == -1) {
			perror("setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		}
		one = 1;
		if (setsockopt(binding->socket, IPPROTO_TCP, TCP_NODELAY, (void*)&one, sizeof(int)) == -1) {
			perror("setsockopt(IPPROTO_TCP, TCP_NODELAY)");
		}

		if (binding->interface.family == AF_INET) {
			/* IPv4
			 */
			memset(&saddr4, 0, sizeof(struct sockaddr_in));
			//saddr4.sin_len = sizeof(struct sockaddr_in);
			saddr4.sin_family = AF_INET;
			memcpy(&(saddr4.sin_addr.s_addr), &(binding->interface.value), IPv4_LEN);
			saddr4.sin_port = htons(binding->port);

			result = bind(binding->socket, (struct sockaddr*)&saddr4, sizeof(struct sockaddr_in));

			separator = ':';
#ifdef ENABLE_IPV6
		} else if (binding->interface.family == AF_INET6) {
			/* IPv6
			 */
			memset(&saddr6, 0, sizeof(struct sockaddr_in6));
			//saddr6.sin6_len = sizeof(struct sockaddr_in6);
			saddr6.sin6_family = AF_INET6;
			memcpy(&(saddr6.sin6_addr.s6_addr), &(binding->interface.value), IPv6_LEN);
			saddr6.sin6_port = htons(binding->port);

			result = bind(binding->socket, (struct sockaddr*)&saddr6, sizeof(struct sockaddr_in6));

			separator = '.';
#endif
		} else {
			fprintf(stderr, "Unknown protocol (family %d).\n", binding->interface.family);
			return -1;
		}

		if (result == -1) {
			/* Handle error
		 	 */
			if (inet_ntop(binding->interface.family, &(binding->interface.value), ip_address, MAX_IP_STR_LEN) == NULL) {
				strcpy(ip_address, "?.?.?.?");
			}
			fprintf(stderr, "Error binding %s%c%d\n", ip_address, separator, binding->port);
			return -1;
		}

		binding = binding->next;
	}

	return 0;
}

/* Accept or deny an incoming connection.
 */
int accept_connection(t_binding *binding, t_config *config) {
	socklen_t           size;
	bool                kick_client;
	t_session           *session;
	struct sockaddr_in  caddr4;
#ifdef ENABLE_IPV6
	struct sockaddr_in6 caddr6;
#endif
	pthread_attr_t      child_attr;
	pthread_t           child_thread;
	int                 total_conns, one, conns_per_ip;
	struct timeval      timer;
#ifdef ENABLE_DEBUG
	static int          thread_id = 0;
#endif

	if ((session = (t_session*)malloc(sizeof(t_session))) == NULL) {
		return -1;
	}
#ifdef ENABLE_DEBUG
	session->thread_id = thread_id++;
	session->current_task = "new";
#endif
	session->config = config;
	session->binding = binding;
	init_session(session);

	if (binding->interface.family == AF_INET) {
		/* IPv4
		 */
		size = sizeof(struct sockaddr_in);
		memset((void*)&caddr4, 0, (size_t)size);
		if ((session->client_socket = accept(binding->socket, (struct sockaddr*)&caddr4, &size)) == -1) {
			free(session);
			log_string(config->system_logfile, "Error accepting incoming IPv4 connection: %s", strerror(errno));
			if (errno == EINTR) {
				return 0;
			}
			return -1;
		}

		session->ip_address.family = AF_INET;
		session->ip_address.size   = IPv4_LEN;
		memcpy(&(session->ip_address.value), (char*)&caddr4.sin_addr.s_addr, session->ip_address.size);
#ifdef ENABLE_IPV6
	} else if (binding->interface.family == AF_INET6) {
		/* IPv6
		 */
		size = sizeof(struct sockaddr_in6);
		memset((void*)&caddr6, 0, (size_t)size);
		if ((session->client_socket = accept(binding->socket, (struct sockaddr*)&caddr6, &size)) == -1) {
			free(session);
			log_string(config->system_logfile, "Error accepting incoming IPv6 connection: %s", strerror(errno));
			if (errno == EINTR) {
				return 0;
			}
			return -1;
		}

		session->ip_address.family = AF_INET6;
		session->ip_address.size   = IPv6_LEN;
		memcpy(&(session->ip_address.value), (char*)&caddr6.sin6_addr.s6_addr, session->ip_address.size);
#endif
	} else {
		log_system(session, "Incoming connection via unknown protocol");
		free(session);
		return -1;
	}

	session->request_limit = (ip_allowed(&(session->ip_address), session->config->request_limit_mask) != deny);

#ifdef ENABLE_LOADCHECK
	if ((session->config->max_server_load > 0) && session->request_limit) {
		if (current_server_load > session->config->max_server_load) {
			close(session->client_socket);
			free(session);
			log_string(config->system_logfile, "Connection dropped due to high server load.");
			return -1;
		}
	}
#endif

	if (session->request_limit == false) {
		conns_per_ip = config->total_connections;
	} else {
		conns_per_ip = config->connections_per_ip;
	}

	kick_client = true;

	if ((total_conns = connection_allowed(&(session->ip_address), conns_per_ip, config->total_connections)) >= 0) {
		if (total_conns < (config->total_connections >> 2)) {
			one = 1;
			if (setsockopt(session->client_socket, IPPROTO_TCP, TCP_NODELAY, (void*)&one, sizeof(int)) == -1) {
				close(session->client_socket);
				free(session);
				log_string(config->system_logfile, "error setsockopt(TCP_NODELAY)");
				return -1;
			}
		}

		if (config->socket_send_timeout > 0) {
			timer.tv_sec  = config->socket_send_timeout;
			timer.tv_usec = 0;
			if (setsockopt(session->client_socket, SOL_SOCKET, SO_SNDTIMEO, &timer, sizeof(struct timeval)) == -1) {
				close(session->client_socket);
				free(session);
				log_string(config->system_logfile, "error setsockopt(SO_SNDTIMEO)");
				return -1;
			}
		}

		/* Pthread initialization
		 */
		if (pthread_attr_init(&child_attr) != 0) {
			log_system(session, "pthread init error");
		} else {
			if (pthread_attr_setdetachstate(&child_attr, PTHREAD_CREATE_DETACHED) != 0) {
				log_system(session, "pthread set detach state error");
			} else if (pthread_attr_setstacksize(&child_attr, PTHREAD_STACK_SIZE) != 0) {
				log_system(session, "pthread set stack size error");
			} else if (add_client(session) == 0) {
				if (pthread_create(&child_thread, &child_attr, (void*)connection_handler, (void*)session) == 0) {
					/* Thread started
					 */
					kick_client = false;
				} else {
					remove_client(session, false);
					log_system(session, "pthread create error");
				}
			}
			pthread_attr_destroy(&child_attr);
		}
	} else switch (total_conns) {
		case ca_TOOMUCH_PERIP:
			log_system(session, "Maximum number of connections for IP address reached");
			if ((config->ban_on_max_per_ip > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				log_system(session, "Client banned because of too many simultaneous connections");
				ban_ip(&(session->ip_address), config->ban_on_max_per_ip, config->kick_on_ban);
#ifdef ENABLE_MONITOR
				if (config->monitor_enabled) {
					monitor_counter_ban(session);
				}
#endif
			}
			break;
		case ca_TOOMUCH_TOTAL:
			log_system(session, "Maximum number of total connections reached");
			break;
		case ca_BANNED:
			if (config->reban_during_ban && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				reban_ip(&(session->ip_address));
			}
#ifdef ENABLE_TOMAHAWK
			increment_counter(COUNTER_DENY);
#endif
			break;
	}

	if (kick_client) {
		close(session->client_socket);
		free(session);
	}

	return 0;
}

/* Run the Hiawatha webserver.
 */
int run_server(t_settings *settings) {
	int                number_of_bindings;
	pthread_attr_t     task_runner_attr;
	pthread_t          task_runner_thread;
	struct pollfd      *poll_data, *current_poll;
#ifdef ENABLE_TOMAHAWK
	int                number_of_admins;
	t_admin            *admin;
	struct sockaddr_in caddr;
	socklen_t          size;
	int                admin_socket;
	FILE               *admin_fp;
#endif
	pid_t              pid;
	t_binding          *binding;
	t_config           *config;
#ifndef CYGWIN
	struct stat        status;
	mode_t             access_rights;
#endif
#ifdef ENABLE_SSL
	t_host             *host;
#endif

	config = default_config();
	if (chdir(settings->config_dir) == -1) {
		perror(settings->config_dir);
		return -1;
	} else if (settings->config_check) {
		printf("Using %s\n", settings->config_dir);
	}
	if (read_main_configfile("hiawatha.conf", config, settings->config_check) == -1) {
		return -1;
	} else if (check_configuration(config) == -1) {
		return -1;
	}

	if (read_mimetypes(config->mimetype_config, &(config->mimetype), settings->config_check) == -1) {
		fprintf(stderr, "Error while reading mimetype configuration.\n");
		return -1;
	}

	if (settings->config_check) {
		printf("Configuration OK.\n");
		return 0;
	}

	/* Bind Serverports
	 */
	if (bind_sockets(config->binding) == -1) {
		return -1;
	}

#ifdef ENABLE_SSL
	ssl_initialize(config->system_logfile);

	/* Load private keys and certificate for bindings
	 */
	binding = config->binding;
	while (binding != NULL) {
		if (binding->use_ssl) {
			if (ssl_load_key_cert(binding->key_cert_file, &(binding->private_key), &(binding->certificate)) != 0) {
				return -1;
			}

			if (binding->ca_cert_file != NULL) {
				if (ssl_load_ca_cert(binding->ca_cert_file, &(binding->ca_certificate)) != 0) {
					return -1;
				}
				if (binding->ca_crl_file != NULL) {
					if (ssl_load_ca_crl(binding->ca_crl_file, &(binding->ca_crl)) != 0) {
						return -1;
					}
				}
			}
		}
		binding = binding->next;
	}

	host = config->first_host;
	while (host != NULL) {
		/* Load private key and certificates for virtual hosts
		 */
		if (host->key_cert_file != NULL) {
			if (ssl_load_key_cert(host->key_cert_file, &(host->private_key), &(host->certificate)) != 0) {
				return -1;
			}
		}
		if (host->ca_cert_file != NULL) {
			if (ssl_load_ca_cert(host->ca_cert_file, &(host->ca_certificate)) != 0) {
				return -1;
			}
			if (host->ca_crl_file != NULL) {
				if (ssl_load_ca_crl(host->ca_crl_file, &(host->ca_crl)) != 0) {
					return -1;
				}
			}
		}

		/* Initialize Server Name Indication
		 */
		if ((host->private_key != NULL) && (host->certificate != NULL)) {
			if (ssl_register_sni(&(host->hostname), host->private_key, host->certificate,
			                     host->ca_certificate, host->ca_crl) == -1) {
				return -1;
			}
		}

		host = host->next;
	}

#endif

#ifdef ENABLE_TOMAHAWK
	/* Bind Tomahawk
	 */
	if (bind_sockets(config->tomahawk_port) == -1) {
		return -1;
	}
#endif

	/* Misc settings
	 */
	tzset();
	clearenv();

	/* Become a daemon
	 */
	if (settings->daemon) {
		switch (pid = fork()) {
			case -1:
				perror("fork()");
				return -1;
			case 0:
				if (setsid() == -1) {
					perror("setsid()");
					return -1;
				}
				break;
			default:
				log_pid(config, pid, config->server_uid);
				return 0;
		}
	} else {
		log_pid(config, getpid(), config->server_uid);
	}

	/* Create work directory
	 */
	if (mkdir(config->work_directory, S_IRWXU) == -1) {
		if (errno != EEXIST) {
			fprintf(stderr, "Error creating work directory '%s'\n", config->work_directory);
			return -1;
#ifndef CYGWIN
		} else if (chmod(config->work_directory, S_IRWXU) == -1) {
			fprintf(stderr, "Can't change access permissions of work directory '%s'\n", config->work_directory);
			return -1;
#endif
		}
	}
#ifndef CYGWIN
	if ((getuid() == 0) || (geteuid() == 0)) {
		if (chown(config->work_directory, config->server_uid, config->server_gid) == -1) {
			perror("chown(WorkDirectory)");
			return -1;
		}
	}
#endif

	/* Create the upload directory for PUT requests
	 */
	if (mkdir(config->upload_directory, S_IRWXU | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1) {
		if (errno != EEXIST) {
			fprintf(stderr, "Error while creating UploadDirectory '%s'\n", config->upload_directory);
			return -1;
		}
	}

#ifndef CYGWIN
	if (stat(config->upload_directory, &status) == -1) {
		perror("stat(UploadDirectory)");
		return -1;
	}
	access_rights = 01733;
	if (status.st_uid != 0) {
		if ((getuid() == 0) || (geteuid() == 0)) {
			if (chown(config->upload_directory, 0, 0) == -1) {
				perror("chown(UploadDirectory, 0, 0)");
				return -1;
			}
		} else {
			access_rights = 01333;
		}
	}

	if ((status.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != access_rights) {
		if (chmod(config->upload_directory, access_rights) == -1) {
			fprintf(stderr, "Can't change access permissions of UploadDirectory '%s'.\n", config->upload_directory);
			return -1;
		}
	}
#endif

#ifdef ENABLE_MONITOR
	/* Create monitor cache directory
	 */
	if (mkdir(config->monitor_directory, S_IRWXU) == -1) {
		if (errno != EEXIST) {
			fprintf(stderr, "Error creating monitor directory '%s'\n", config->monitor_directory);
			return -1;
#ifndef CYGWIN
		} else if (chmod(config->monitor_directory, S_IRWXU) == -1) {
			fprintf(stderr, "Can't change access permissions of monitor directory '%s'\n", config->monitor_directory);
			return -1;
#endif
		}
	}
#ifndef CYGWIN
	if ((getuid() == 0) || (geteuid() == 0)) {
		if (chown(config->monitor_directory, config->server_uid, config->server_gid) == -1) {
			perror("chown(MonitorDirectory)");
			return -1;
		}
	}
#endif
#endif

	/* Create logfiles
	 */
	touch_logfiles(config);

	/* Change userid
	 */
#ifndef CYGWIN
	if ((getuid() == 0) || (geteuid() == 0)) do {
		if (setgroups(config->groups.number, config->groups.array) != -1) {
			if (setgid(config->server_gid) != -1) {
				if (setuid(config->server_uid) != -1) {
					break;
				}
			}
		}
		fprintf(stderr, "\nError while changing uid/gid!\n");
		return -1;
	} while (false);
#endif

	if (settings->daemon == false) {
		printf("Press Ctrl-C to shutdown the Hiawatha webserver.\n");
		signal(SIGINT, TERM_handler);
	} else {
		signal(SIGINT, SIG_IGN);
	}

	/* Set signal handlers
	 */
	if (config->wait_for_cgi == false) {
		signal(SIGCHLD, SIG_IGN);
	}
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGABRT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGSEGV, SEGV_handler);
	signal(SIGTERM, TERM_handler);
	signal(SIGHUP,  HUP_handler);
	signal(SIGUSR1, USR1_handler);
#ifdef ENABLE_CACHE
	signal(SIGUSR2, USR2_handler);
#endif

	/* Start listening for incoming connections
	 */
	binding = config->binding;
	while (binding != NULL) {
		if (listen(binding->socket, 16) == -1) {
			perror("listen(http(s))");
			return -1;
		}
		binding = binding->next;
	}
#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		if (listen(binding->socket, 1) == -1) {
			perror("listen(tomahawk)");
			return -1;
		}
		binding = binding->next;
	}
#endif

	init_send_module();
	init_log_module();
	init_client_module();
	init_load_balancer(config->fcgi_server);
#ifdef ENABLE_CACHE
	init_cache_module();
#endif
#ifdef ENABLE_TOMAHAWK
	init_tomahawk_module();
#endif
#ifdef ENABLE_XSLT
	init_xslt_module();
#endif
#ifdef ENABLE_RPROXY
	if (init_rproxy_module() == -1) {
		fprintf(stderr, "Error initializing reverse proxy module.\n");
		return -1;
	}
#endif
	if (init_sqli_detection() == -1) {
		fprintf(stderr, "Error initializing SQL injection detection.\n");
		return -1;
	}
#ifdef ENABLE_MONITOR
	if (config->monitor_enabled) {
		if (init_monitor_module(config) == -1) {
			fprintf(stderr, "Error initializing Monitor module.\n");
			return -1;
		}
		monitor_server_start();
	}
#endif

	/* Redirecting I/O to /dev/null
	 */
	if (settings->daemon) {
		if (close(STDIN_FILENO) == -1) {
			fprintf(stderr, "Warning: error closing STDIN\n");
		} else if (open("/dev/null", O_RDONLY) == -1) {
			fprintf(stderr, "Warning: error redirecting stdin\n");
		}
		if (close(STDOUT_FILENO) == -1) {
			fprintf(stderr, "Warning: error closing STDOUT\n");
		} else if (open("/dev/null", O_WRONLY) == -1) {
			fprintf(stderr, "Warning: error redirecting stdout\n");
		}
		if (close(STDERR_FILENO) == -1) {
			fprintf(stderr, "Warning: error closing STDERR\n");
		} else if (open("/dev/null", O_WRONLY) == -1) {
			log_string(config->system_logfile, "Warning: error redirecting stderr\n");
		}
	}

	log_string(config->system_logfile, "Hiawatha v"VERSION" started");

	/* Start task_runner
	 */
	if (pthread_attr_init(&task_runner_attr) != 0) {
		log_string(config->system_logfile, "Task-runner pthread init error");
		return -1;
	} else if (pthread_attr_setdetachstate(&task_runner_attr, PTHREAD_CREATE_DETACHED) != 0) {
		log_string(config->system_logfile, "Task-runner pthread set detach state error");
		return -1;
	} else if (pthread_attr_setstacksize(&task_runner_attr, PTHREAD_STACK_SIZE) != 0) {
		log_string(config->system_logfile, "Task-runner pthread set stack size error");
		return -1;
	} else if (pthread_create(&task_runner_thread, &task_runner_attr, (void*)task_runner, (void*)config) != 0) {
		log_string(config->system_logfile, "Task-runner pthread create error");
		return -1;
	}
	pthread_attr_destroy(&task_runner_attr);

	/* Count bindings
	 */
	number_of_bindings = 0;

	binding = config->binding;
	while (binding != NULL) {
		number_of_bindings++;
		binding = binding->next;
	}

#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		number_of_bindings++;
		binding = binding->next;
	}
#endif

	/* Setup poll data
	 */
	if ((poll_data = (struct pollfd*)malloc((number_of_bindings + MAX_ADMIN_CONNECTIONS) * sizeof(struct pollfd*))) == NULL) {
		return -1;
	}

	current_poll = poll_data;

	binding = config->binding;
	while (binding != NULL) {
		current_poll->fd = binding->socket;
		current_poll->events = POLL_EVENT_BITS;
		binding->poll_data = current_poll;

		current_poll++;
		binding = binding->next;
	}

#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		current_poll->fd = binding->socket;
		current_poll->events = POLL_EVENT_BITS;
		binding->poll_data = current_poll;

		current_poll++;
		binding = binding->next;
	}
#endif

	/* Main loop
	 */
	do {
#ifdef ENABLE_TOMAHAWK
		current_poll = poll_data + number_of_bindings;
		number_of_admins = 0;
		admin = first_admin();
		while (admin != NULL) {
			current_poll->fd = admin->socket;
			current_poll->events = POLL_EVENT_BITS;
			admin->poll_data = current_poll;

			number_of_admins++;
			current_poll++;
			admin = next_admin();
		}

		switch (poll(poll_data, number_of_bindings + number_of_admins, 1000)) {
#else
		switch (poll(poll_data, number_of_bindings, 1000)) {
#endif
			case -1:
				if (errno != EINTR) {
					log_string(config->system_logfile, "Fatal error selecting connection");
					usleep(1000);
				}
				break;
			case 0:
				break;
			default:
#ifdef ENABLE_TOMAHAWK
				/* Connected admins */
				admin = first_admin();
				while (admin != NULL) {
					if (admin->poll_data->revents != 0) {
						if (handle_admin(admin, config) == cc_DISCONNECT) {
							remove_admin(admin->socket);
						}
					}
					admin = next_admin();
				}
#endif

				/* HTTP(S) ports */
				binding = config->binding;
				while (binding != NULL) {
					if (binding->poll_data->revents != 0) {
						if (accept_connection(binding, config) != 0) {
							usleep(1000);
							break;

						}
					}
					binding = binding->next;
				}

#ifdef ENABLE_TOMAHAWK
				/* Tomahawk ports */
				binding = config->tomahawk_port;
				while (binding != NULL) {
					if (binding->poll_data->revents != 0) {
						size = sizeof(struct sockaddr_in);
						memset((void*)&caddr, 0, (size_t)size);
						if ((admin_socket = accept(binding->socket, (struct sockaddr*)&caddr, &size)) == -1) {
							if (errno != EINTR) {
								log_string(config->system_logfile, "Fatal error accepting Tomahawk connection");
								usleep(1000);
								break;
							}
						} else if (number_of_admins >= MAX_ADMIN_CONNECTIONS) {
							if ((admin_fp = fdopen(admin_socket, "r+")) != NULL) {
								fprintf(admin_fp, "Maximum number of admin connections reached.\n\n");
							}
							fclose(admin_fp);
						} else if (add_admin(admin_socket) == -1) {
							close(admin_socket);
						}
					}
					binding = binding->next;
				}
#endif
		}
	} while (must_quit == false);

	signal(SIGTERM, SIG_DFL);

	close_bindings(config->binding);

	disconnect_clients(config);
#ifdef ENABLE_TOMAHAWK
	disconnect_admins();
#endif

#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		close(binding->socket);
		binding = binding->next;
	}
#endif

#ifdef ENABLE_MONITOR
	if (config->monitor_enabled) {
		monitor_server_stop();
		shutdown_monitor_module(config);
	}
#endif

	log_string(config->system_logfile, "Hiawatha v"VERSION" stopped");
	close_logfiles(config->first_host, 0);

	return 0;
}

void show_help(char *hiawatha) {
	printf("Usage: %s [options]\n", hiawatha);
	printf("Options: -c <path>: path to where the configrationfiles are located.\n");
	printf("         -d: don't fork to the background.\n");
	printf("         -h: show this information and exit.\n");
	printf("         -k: check configuration and exit.\n");
	printf("         -v: show version and compile information and exit.\n");
}

/* Main and stuff...
 */
int main(int argc, char *argv[]) {
	int i = 0;
	t_settings settings;

	/* Default settings
	 */
	settings.config_dir   = CONFIG_DIR;
	settings.daemon       = true;
	settings.config_check = false;

	/* Read commandline parameters
	 */
	while (++i < argc) {
		if (strcmp(argv[i], "-c") == 0) {
			if (++i < argc) {
				settings.config_dir = argv[i];
			} else {
				fprintf(stderr, "Specify a directory.\n");
				return EXIT_FAILURE;
			}
		} else if (strcmp(argv[i], "-d") == 0) {
			settings.daemon = false;
		} else if (strcmp(argv[i], "-h") == 0) {
			show_help(argv[0]);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[i], "-k") == 0) {
			settings.config_check = true;
		} else if (strcmp(argv[i], "-v") == 0) {
			printf("%s\n", version_string);
			printf("Copyright (C) by Hugo Leisink <hugo@leisink.net>\n");
			return EXIT_SUCCESS;
		} else {
			fprintf(stderr, "Unknown option. Use '-h' for help.\n");
			return EXIT_FAILURE;
		}
	}

	/* Run Hiawatha
	 */
	if (run_server(&settings) == -1) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

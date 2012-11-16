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
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "global.h"
#include "liblist.h"
#include "libip.h"
#include "log.h"

#define BUFFER_SIZE        2 * KILOBYTE
#define TIMESTAMP_SIZE    40
#define IP_ADDRESS_SIZE MAX_IP_STR_LEN + 1
#define LOGFILE_OPEN_TIME 30

#ifdef CYGWIN
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

pthread_mutex_t accesslog_mutex;

/* Initialize log module
 */
void init_log_module(void) {
	pthread_mutex_init(&accesslog_mutex, NULL);
}

/* Write a timestamp to a logfile.
 */
static void print_timestamp(char *str) {
	time_t t;
	struct tm *s;

	time(&t);
	s = localtime(&t);
	str[TIMESTAMP_SIZE - 1] = '\0';
	strftime(str, TIMESTAMP_SIZE - 1, "%a %d %b %Y %T %z|", s);
}

/* Keep escape characters out of the logfile
 */
static char *secure_string(char *str) {
	char *c = str;

	if (str != NULL) {
		while (*c != '\0') {
			if (*c == '\27') {
				*c = ' ';
			}
			c++;
		}
	}

	return str;
}

/*---< Main log functions >------------------------------------------*/

/* Log the Hiawatha process ID.
 */
void log_pid(t_config *config, pid_t pid, uid_t UNUSED(server_uid)) {
	FILE *fp;

	if ((fp = fopen(config->pidfile, "w")) == NULL) {
		fprintf(stderr, "Warning: can't write PID file %s.\n", config->pidfile);
		return;
	}

	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);

#ifndef CYGWIN
	if (chmod(config->pidfile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		fprintf(stderr, "Warning: can't chmod PID file %s. Make sure it's only writable for root!\n", config->pidfile);
	}
	if (server_uid == 0) {
		if (chown(config->pidfile, 0, 0) == -1) {
			fprintf(stderr, "Warning: can't chown PID file %s. Make sure it's owned by root!\n", config->pidfile);
		}
	}
#endif
}

/* Log a text.
 */
void log_string(char *logfile, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE];

	if (mesg == NULL) {
		return;
	} else if ((fp = fopen(logfile, "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	print_timestamp(str);
	fprintf(fp, "%s", str);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}

/* Log a system message.
 */
void log_system(t_session *session, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if (mesg == NULL) {
		return;
	} else if ((fp = fopen(session->config->system_logfile, "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	ip_to_str(str, &(session->ip_address), IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s", str);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}

/* Log an error for a specific file
 */
void log_file_error(t_session *session, char *file, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if ((file == NULL) || (mesg == NULL)) {
		return;
	} else if ((fp = fopen(session->host->error_logfile, "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	ip_to_str(str, &(session->ip_address), IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s%s|", str, file);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}

/* Log an error
 */
void log_error(t_session *session, char *mesg) {
	log_file_error(session, session->file_on_disk, mesg);
}

/* Log a HTTP request.
 */
void log_request(t_session *session) {
	char str[BUFFER_SIZE + 1], timestamp[TIMESTAMP_SIZE], ip_address[IP_ADDRESS_SIZE];
	char *user, *field, *uri, *vars, *path_info;
	t_headerfield *headerfield;
	int offset;
	time_t t;
	struct tm *s;

	if (ip_allowed(&(session->ip_address), session->config->logfile_mask) == deny) {
		return;
	}

	str[BUFFER_SIZE] = '\0';

#ifdef ENABLE_TOOLKIT
	if (session->request_uri == NULL) {
#endif
		uri = secure_string(session->uri);
		path_info = secure_string(session->path_info);
		vars = secure_string(session->vars);
#ifdef ENABLE_TOOLKIT
	} else {
		uri = secure_string(session->request_uri);
		path_info = NULL;
		vars = NULL;
	}
#endif

	if ((user = session->remote_user) != NULL) {
		user = secure_string(user);
	}

	if (session->config->log_format == hiawatha) {
		/* Hiawatha log format
		 */
		ip_to_str(str, &(session->ip_address), IP_ADDRESS_SIZE);
		strcat(str, "|");
		offset = strlen(str);
		print_timestamp(str + offset);
		offset += strlen(str + offset);

		if (user == NULL) {
			user = "";
		}

		snprintf(str + offset, BUFFER_SIZE - offset, "%d|%lld|%s|%s %s", session->return_code, (long long)session->bytes_sent, user, secure_string(session->method), uri);
		offset += strlen(str + offset);

		if ((offset < BUFFER_SIZE) && (path_info != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "/%s", path_info);
			offset += strlen(str + offset);
		}
		if ((offset < BUFFER_SIZE) && (vars != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "?%s", vars);
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			snprintf(str + offset, BUFFER_SIZE - offset, " %s", secure_string(session->http_version));
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			headerfield = session->headerfields;
			while (headerfield != NULL) {
				if ((strncasecmp("Cookie:", headerfield->data, 7) != 0) && (strncasecmp("Authorization:", headerfield->data, 14) != 0)) {
					snprintf(str + offset, BUFFER_SIZE - offset, "|%s", secure_string(headerfield->data));
					if ((offset += strlen(str + offset)) >= BUFFER_SIZE) {
						break;
					}
				}
				headerfield = headerfield->next;
			}
		}
	} else {
		/* Common Log Format
		 */
		ip_to_str(ip_address, &(session->ip_address), IP_ADDRESS_SIZE);

		if (user == NULL) {
			user = "-";
		}

		time(&t);
		s = localtime(&t);
		timestamp[TIMESTAMP_SIZE - 1] = '\0';
		strftime(timestamp, TIMESTAMP_SIZE - 1, "%d/%b/%Y:%T %z", s);

		snprintf(str, BUFFER_SIZE, "%s - %s [%s] \"%s %s", ip_address, user, timestamp, secure_string(session->method), uri);
		offset = strlen(str);
		if ((offset < BUFFER_SIZE) && (path_info != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "/%s", path_info);
			offset += strlen(str + offset);
		}
		if ((offset < BUFFER_SIZE) && (vars != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "?%s", vars);
			offset += strlen(str + offset);
		}
		if (offset < BUFFER_SIZE) {
			snprintf(str + offset, BUFFER_SIZE - offset, " %s\" %d %lld", secure_string(session->http_version), session->return_code, (long long)session->bytes_sent);
		}

		if (session->config->log_format == extended) {
			/* Extended Common Log Format
			 */
			offset += strlen(str + offset);
			if (offset < BUFFER_SIZE) {
				if ((field = get_headerfield("Referer:", session->headerfields)) != NULL) {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"%s\"", secure_string(field));
				} else {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"-\"");
				}
				offset += strlen(str + offset);
			}
			if (offset < BUFFER_SIZE) {
				if ((field = get_headerfield("User-Agent:", session->headerfields)) != NULL) {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"%s\"", secure_string(field));
				} else {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"-\"");
				}
			}
		}
	}

	pthread_mutex_lock(&accesslog_mutex);
	if (*(session->host->access_fp) == NULL) {
		*(session->host->access_fp) = fopen(session->host->access_logfile, "a");
	}
	if (*(session->host->access_fp) != NULL) {
		fprintf(*(session->host->access_fp), "%s"EOL, str);
		fflush(*(session->host->access_fp));
	}
	pthread_mutex_unlock(&accesslog_mutex);
}

/* Log garbage sent by a client.
 */
void log_garbage(t_session *session) {
	int i, spaces = 2;
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if ((session->config->garbage_logfile == NULL) || (session->request == NULL)) {
		return;
	}

	for (i = 0; i < session->bytes_in_buffer; i++) {
		if (session->request[i] == '\0') {
			if (spaces > 0) {
				session->request[i] = ' ';
				spaces--;
			} else {
				session->request[i] = '\r';
			}
		}
	}

	if ((fp = fopen(session->config->garbage_logfile, "a")) == NULL) {
		return;
	}

	ip_to_str(str, &(session->ip_address), IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s%s"EOL, str, session->request);
	fclose(fp);
}

/* Log exploit attempt
 */
void log_exploit_attempt(t_session *session, char *type, char *data) {
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE], *host, *uri, *unknown = "unknown";

	if ((session->config->exploit_logfile == NULL) || (type == NULL)) {
		return;
	} else if ((fp = fopen(session->config->exploit_logfile, "a")) == NULL) {
		return;
	}

	host = (session->host->hostname.size > 0) ? session->host->hostname.item[0] : unknown;
	uri = (session->uri != NULL) ? session->uri : unknown;

	ip_to_str(str, &(session->ip_address), IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	if (data == NULL) {
		fprintf(fp, "%s%s|%s|%s"EOL, str, host, uri, type);
	} else {
		fprintf(fp, "%s%s|%s|%s|%s"EOL, str, host, uri, type, data);
	}
	fclose(fp);
}

/* Log an unbanning.
 */
void log_unban(char *logfile, t_ip_addr *ip_address, unsigned long connect_attempts) {
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if ((logfile == NULL) || (ip_address == NULL)) {
		return;
	} else if ((fp = fopen(logfile, "a")) == NULL) {
		return;
	}

	ip_to_str(str, ip_address, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%sUnbanned (%ld connect attempts during ban)"EOL, str, connect_attempts);
	fclose(fp);
}

/* Log a CGI error.
 */
void log_cgi_error(t_session *session, char *mesg) {
	FILE *fp;
	char *c, str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];
	int len = 0;

	if (mesg == NULL) {
		return;
	}

	c = mesg;
	while (*c != '\0') {
		if (*c == '\n') {
			if (*(c + 1) == '\0') {
				*c = '\0';
			} else {
				*c = '|';
			}
		} else {
			len++;
		}
		c++;
	}

	if (len > 0) {
		if ((fp = fopen(session->host->error_logfile, "a")) != NULL) {
			ip_to_str(str, &(session->ip_address), IP_ADDRESS_SIZE);
			strcat(str, "|");
			print_timestamp(str + strlen(str));
			if (session->file_on_disk == NULL) {
				fprintf(fp, "%s-|%s"EOL, str, secure_string(mesg));
			} else {
				fprintf(fp, "%s%s|%s"EOL, str, session->file_on_disk, secure_string(mesg));
			}
			fclose(fp);
		}
	}
}

/* Close open access logfiles.
 */
void close_logfiles(t_host *host, time_t now) {
	pthread_mutex_lock(&accesslog_mutex);
	while (host != NULL) {
		if ((now >= host->access_time + LOGFILE_OPEN_TIME) || (now == 0)) {
			if (*(host->access_fp) != NULL) {
				fclose(*(host->access_fp));
				*(host->access_fp) = NULL;
			}
		}
		host = host->next;
	}
	pthread_mutex_unlock(&accesslog_mutex);
}

void close_logfiles_for_cgi_run(t_host *host) {
	while (host != NULL) {
		if (*(host->access_fp) != NULL) {
			fclose(*(host->access_fp));
		}
		host = host->next;
	}
}

#ifdef ENABLE_DEBUG
void log_debug(t_session *session, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if (mesg == NULL) {
		return;
	} else if ((fp = fopen(LOG_DIR"/access.log", "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	ip_to_str(str, &(session->ip_address), IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s%05d|", str, session->thread_id);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}
#endif

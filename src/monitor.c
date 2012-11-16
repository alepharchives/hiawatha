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

#ifdef ENABLE_MONITOR

#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <zlib.h>
#include "global.h"
#include "monitor.h"
#include "liblist.h"
#include "libip.h"

#define MAX_MONITOR_BUFFER_SIZE 50 * KILOBYTE
#define MAX_TIMESTAMP_SIZE      16
#define MAX_FILENAME_SIZE       35
#define FORCE_SYNC_BUFFER        4

static char *monitor_buffer = NULL;
static int monitor_buffer_size;
static pthread_mutex_t monitor_buffer_mutex;

static int stats_delay, force_sync_buffer;

static char *filename;
static int filename_offset;

/* Reset server record
 */
static void reset_server_stats(t_monitor_srv_stats *stats) {
	if (stats != NULL) {
		stats->simultaneous_connections = 0;
	}
}

/* Reset host record
 */
static void reset_host_stats(t_monitor_host_stats *stats) {
	if (stats != NULL) {
		stats->requests = 0;
		stats->bytes_sent = 0;
		stats->bans = 0;
		stats->exploit_attempts = 0;

		stats->result_forbidden = 0;
		stats->result_not_found = 0;
		stats->result_internal_error = 0;
	}
}

/* Replace TAB with SPACE
 */
static void secure_monitor_value(char *str) {
	if (str == NULL) {
		return;
	}
	while (*str != '\0') {
		if ((*str == '\r') || (*str == '\n') || (*str == '\t')) {
			*str = ' ';
		}
		str++;
	}
}

/* Write monitor buffer to disk
 */
static int sync_monitor_buffer(void) {
	int handle, bytes_written, total_written;
	gzFile gzhandle;

	if (monitor_buffer_size == 0) {
		return 0;
	}

	snprintf(filename + filename_offset, MAX_FILENAME_SIZE, "%ld.txt.gz", (long)time(NULL));
	if ((handle = open(filename, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP)) == -1) {
		return -1;
	}
	fchmod(handle, S_IRUSR | S_IWUSR);

	if ((gzhandle = gzdopen(handle, "w6")) == NULL) {
		close(handle);
		unlink(filename);
		return -1;
	}

	total_written = 0;
	while (total_written < monitor_buffer_size) {
		if ((bytes_written = gzwrite(gzhandle, monitor_buffer + total_written, monitor_buffer_size - total_written)) == -1) {
			if (gzclose(gzhandle) != Z_OK) {
				close(handle);
			}
			unlink(filename);
			return -1;
		}
		total_written += bytes_written;
	}

	if (gzclose(gzhandle) != Z_OK) {
		close(handle);
	}

	monitor_buffer_size = 0;

	return 0;
}

/* Make enough space in monitor buffer
 */
static bool enough_space_for_event(size_t event_size) {
	if (event_size > MAX_MONITOR_BUFFER_SIZE) {
		return false;
	}

	if (monitor_buffer_size + event_size > MAX_MONITOR_BUFFER_SIZE) {
		return sync_monitor_buffer() == 0;
	}

	return true;
}

/* Initialize monitor module
 */
int init_monitor_module(t_config *config) {
	t_host *host;

	if ((monitor_buffer = (char*)malloc(MAX_MONITOR_BUFFER_SIZE)) == NULL) {
		return -1;
	}
	monitor_buffer_size = 0;

	filename_offset = strlen(config->monitor_directory) + 1;
	if ((filename = (char*)malloc(filename_offset + MAX_FILENAME_SIZE + 1)) == NULL) {
		return -1;
	}
	memcpy(filename, config->monitor_directory, filename_offset);
	filename[filename_offset - 1] = '/';
	filename[filename_offset + MAX_FILENAME_SIZE] = '\0';

	host = config->first_host;
	while (host != NULL) {
		if ((host->monitor_stats = (t_monitor_host_stats*)malloc(sizeof(t_monitor_host_stats))) == NULL) {
			return -1;
		}

		reset_host_stats(host->monitor_stats);

		host = host->next;
	}

	reset_server_stats(&(config->monitor_stats));

	stats_delay = (int)config->monitor_stats_interval / TASK_RUNNER_INTERVAL;
	force_sync_buffer = FORCE_SYNC_BUFFER;

	pthread_mutex_init(&monitor_buffer_mutex, NULL);

	return 0;
}

/* Stop monitor module
 */
void shutdown_monitor_module(t_config *config) {
	stats_delay = 0;
	monitor_stats(config, time(NULL));
	sync_monitor_buffer();
}

static int add_string_to_buffer(char *str) {
	size_t size;

	if ((monitor_buffer == NULL) || (str == NULL)) {
		return -1;
	}
	size = strlen(str);

	pthread_mutex_lock(&monitor_buffer_mutex);

	if (enough_space_for_event(size) == false) {
		pthread_mutex_unlock(&monitor_buffer_mutex);
		return -1;
	}

	memcpy(monitor_buffer + monitor_buffer_size, str, size);
	monitor_buffer_size += size;

	pthread_mutex_unlock(&monitor_buffer_mutex);

	return 0;
}

/* Monitor deamon start
 */
int monitor_server_start(void) {
	char str[8 + MAX_TIMESTAMP_SIZE];

	snprintf(str, MAX_TIMESTAMP_SIZE + 8, "Start\t%ld\n", (long)time(NULL));

	return add_string_to_buffer(str);
}

/* Monitor deamon stop
 */
int monitor_server_stop(void) {
	char str[7 + MAX_TIMESTAMP_SIZE];

	snprintf(str, MAX_TIMESTAMP_SIZE + 7, "Stop\t%ld\n", (long)time(NULL));

	return add_string_to_buffer(str);
}

#ifdef ENABLE_LOADCHECK
/* Monitor high server load
 */
int monitor_high_server_load(double load) {
	char str[35 + MAX_TIMESTAMP_SIZE];

	snprintf(str, MAX_TIMESTAMP_SIZE + 35, "High server load (%0.2f)\t%ld\n", load, (long)time(NULL));

	return add_string_to_buffer(str);
}
#endif

/* Status request
 */
int monitor_stats(t_config *config, time_t now) {
	static int timer = 0;
	time_t timestamp_begin, timestamp_end;
	t_host *host;
	char *str = NULL;
	size_t str_len = 0, len;

	if (timer++ < stats_delay) {
		return 0;
	}
	timer = 0;

	timestamp_end = now;
	timestamp_begin = timestamp_end - stats_delay;

	/* Monitor host stat
	 */
	host = config->first_host;
	while (host != NULL) {
		if (host->monitor_host) {
			host = host->next;
			continue;
		}

		len = 2 * MAX_TIMESTAMP_SIZE + strlen(host->hostname.item[0]) + 7 * 15;

		if (len > str_len) {
			str_len = len + 100;
			sfree(str);
			if ((str = (char*)malloc(str_len)) == NULL) {
				return -1;
			}
		}

		snprintf(str, str_len, "host\t%ld\t%ld\t%s\t%d\t%ld\t%d\t%d\t%d\t%d\t%d\n",
			(long)timestamp_begin, (long)timestamp_end, host->hostname.item[0],
			host->monitor_stats->requests, (long)host->monitor_stats->bytes_sent, host->monitor_stats->bans, host->monitor_stats->exploit_attempts,
			host->monitor_stats->result_forbidden, host->monitor_stats->result_not_found, host->monitor_stats->result_internal_error);
		str[str_len - 1] = '\0';

		if (add_string_to_buffer(str) == -1) {
			free(str);
			return -1;
		}

		reset_host_stats(host->monitor_stats);

		host = host->next;
	}

	/* Monitor server stats
	 */
	len = 2 * MAX_TIMESTAMP_SIZE + 20;

	if (len > str_len) {
		str_len = len + 100;
		sfree(str);
		if ((str = (char*)malloc(str_len)) == NULL) {
			return -1;
		}

	}

	snprintf(str, str_len, "server\t%ld\t%ld\t%d\n",
		(long)timestamp_begin, (long)timestamp_end,
		config->monitor_stats.simultaneous_connections);
	str[str_len - 1] = '\0';

	if (add_string_to_buffer(str) == -1) {
		free(str);
		return -1;
	}

	reset_server_stats(&(config->monitor_stats));

	sfree(str);

	/* Force syncing of monitor buffer
	 */
	if (force_sync_buffer-- <= 0) {
		pthread_mutex_lock(&monitor_buffer_mutex);
		sync_monitor_buffer();
		pthread_mutex_unlock(&monitor_buffer_mutex);

		force_sync_buffer = FORCE_SYNC_BUFFER;
	}

	return 0;
}

/* Monitor request
 */
int monitor_request(t_session *session) {
	char *str, *user_agent, *referer;
	char ip_address[MAX_IP_STR_LEN + 1];
	size_t str_len;
	int result;

	if (session->request_uri == NULL) {
		return -1;
	}

	secure_monitor_value(session->request_uri);

	ip_to_str(ip_address, &(session->ip_address), MAX_IP_STR_LEN);
	ip_address[MAX_IP_STR_LEN] = '\0';

	if ((user_agent = get_headerfield("User-Agent:", session->headerfields)) == NULL) {
		user_agent = "-";
	} else {
		secure_monitor_value(user_agent);
	}

	if ((referer = get_headerfield("Referer:", session->headerfields)) == NULL) {
		referer = "-";
	} else {
		secure_monitor_value(referer);
	}

	str_len = 20 + MAX_TIMESTAMP_SIZE + strlen(session->host->hostname.item[0]) + strlen(session->request_uri) +
	             strlen(ip_address) + strlen(user_agent) + strlen(referer);
	if ((str = (char*)malloc(str_len)) == NULL) {
		return -1;
	}

	snprintf(str, str_len, "request\t%ld\t%d\t%s\t%s\t%s\t%s\t%s\n",
		(long)session->time, session->return_code, session->host->hostname.item[0], session->request_uri, ip_address, user_agent, referer);
	str[str_len - 1] = '\0';

	result = add_string_to_buffer(str);
	free(str);

	return result;
}

/* Stats monitor functions
 */
void monitor_counter_request(t_session *session) {
	if (session->host->monitor_stats == NULL) {
		return;
	}

	session->host->monitor_stats->bytes_sent += session->bytes_sent;
	session->host->monitor_stats->requests++;

	switch (session->return_code) {
		case 403:
			session->host->monitor_stats->result_forbidden++;
			break;
		case 404:
			session->host->monitor_stats->result_not_found++;
			break;
		case 500:
			session->host->monitor_stats->result_internal_error++;
			break;
	}
}

void monitor_counter_ban(t_session *session) {
	if (session->host->monitor_stats == NULL) {
		return;
	}

	session->host->monitor_stats->bans++;
}

void monitor_counter_exploit_attempt(t_session *session) {
	if (session->host->monitor_stats == NULL) {
		return;
	}

	session->host->monitor_stats->exploit_attempts++;
}

#endif

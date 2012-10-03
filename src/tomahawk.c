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

#ifdef ENABLE_TOMAHAWK

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "global.h"
#include "libstr.h"
#include "tomahawk.h"
#include "client.h"
#ifdef ENABLE_CACHE
#include "cache.h"
#endif
#include "polarssl/md5.h"

#define MAX_IDLE_TIME   60
#define MAX_CMD_SIZE   100
#define TIMESTAMP_SIZE  50

static t_admin *adminlist;
static int current_admin;
static char *prompt = "\033[01;34mhcc>\033[00m ";

static pthread_mutex_t tomahawk_mutex;

static char start_time[TIMESTAMP_SIZE];
extern char *version_string;

static volatile unsigned long counters[COUNTER_MAX];
static volatile unsigned long long transfer[TRANSFER_MAX];

void increment_counter(int counter) {
	counters[counter]++;
}

void increment_transfer(int counter, long bytes) {
	transfer[counter] += bytes;
}

static void clear_counters(void) {
	int i;

	for (i = 0; i < COUNTER_MAX; i++) {
		counters[i] = 0;
	}
	for (i = 0; i < TRANSFER_MAX; i++) {
		transfer[i] = 0;
	}
}

/* Initialize Tomahawk
 */
void init_tomahawk_module(void) {
	time_t t;
	struct tm *s;

    adminlist = NULL;
	current_admin = 0;
	pthread_mutex_init(&tomahawk_mutex, NULL);

	time(&t);
	s = localtime(&t);
	start_time[TIMESTAMP_SIZE - 1] = '\0';
	strftime(start_time, TIMESTAMP_SIZE - 1, "%a %d %b %Y %T %z", s);

	clear_counters();
}

/* An administrator has connected to Tomahawk
 */
int add_admin(int sock) {
	t_admin *new;

	if ((new = (t_admin*)malloc(sizeof(t_admin))) == NULL) {
		return -1;
	} else if ((new->fp = fdopen(sock, "r+")) == NULL) {
		return -1;
	}

	fprintf(new->fp, "\n\033[02;31mWelcome to Tomahawk, the Hiawatha command shell\033[00m\n");
	fprintf(new->fp, "Password: \0337\033[00;30;40m"); /* Save cursor position and change color to black */
	fflush(new->fp);

	new->next = adminlist;
	new->socket = sock;
	new->poll_data = NULL;
	new->authenticated = false;
	new->timer = MAX_IDLE_TIME;
	adminlist = new;

	return 0;
}

/* An administrator has left Tomahawk
 */
void remove_admin(int sock) {
	t_admin *deadone = NULL, *check;

	pthread_mutex_lock(&tomahawk_mutex);

	if (adminlist != NULL) {
		if (adminlist->socket == sock) {
			deadone = adminlist;
			adminlist = adminlist->next;
		} else {
			check = adminlist;
			while (check->next != NULL) {
				if (check->next->socket == sock) {
					deadone = check->next;
					check->next = deadone->next;
					break;
				}
				check = check->next;
			}
		}
	}

	pthread_mutex_unlock(&tomahawk_mutex);

	if (deadone != NULL) {
		fclose(deadone->fp);
		free(deadone);
	}
}

/* Disconnect al the administrators.
 */
void disconnect_admins(void) {
	t_admin *admin;

	pthread_mutex_lock(&tomahawk_mutex);

	while (adminlist != NULL) {
		admin = adminlist;
		adminlist = adminlist->next;

		close(admin->socket);
		free(admin);
	}

	pthread_mutex_unlock(&tomahawk_mutex);
}

/* Return the first admin record.
 */
t_admin *first_admin(void) {
	current_admin = 0;

	return adminlist;
}

/* Return the next admin record.
 */
t_admin *next_admin(void) {
	t_admin *admin;
	int next;

	pthread_mutex_lock(&tomahawk_mutex);

	admin = adminlist;
	next = current_admin;
	while ((next >= 0) && (admin != NULL)) {
		admin = admin->next;
		next--;
	}

	pthread_mutex_unlock(&tomahawk_mutex);

	if (admin != NULL) {
		current_admin++;
	}

	return admin;
}

/* Check administratos (only auto-logout timers for now).
 */
void check_admin_list(void) {
	t_admin *admin, *prev_admin = NULL, *next_admin;

	pthread_mutex_lock(&tomahawk_mutex);

	admin = adminlist;
	while (admin != NULL) {
		next_admin = admin->next;
		if (admin->timer == 0) {
			fprintf(admin->fp, "\033[00m(auto-logout)\n");
			fflush(admin->fp);
			close(admin->socket);
			if (prev_admin == NULL) {
				adminlist = next_admin;
			} else {
				prev_admin->next = next_admin;
			}
			free(admin);
		} else {
			admin->timer--;
			prev_admin = admin;
		}
		admin = next_admin;
	}

	pthread_mutex_unlock(&tomahawk_mutex);
}

/* Show help info.
 */
static void show_help(FILE *fp) {
	fprintf(fp,	"  ban <ip>[ <time>]: ban an IP (for <time> seconds)\n"
				"  clear screen     : clear the screen\n"
#ifdef ENABLE_CACHE
				"        cache      : remove all unlocked files from the cache\n"
#endif
				"        counters   : set all counters to zero\n"
				"  kick <id>        : kick client by its id (show clients)\n"
				"       <ip>        : kick client by its IP\n"
				"       all         : disconnect all clients\n"
				"  show bans        : show the ban list\n"
#ifdef ENABLE_CACHE
				"       cache       : show the file in the cache\n"
#endif
				"       clients     : show the connected clients\n"
				"       status      : show general information\n"
				"  quit/exit        : quit Tomahawk\n"
				"  unban <ip>       : unban an IP address\n"
				"        all        : unban all IP addresses\n");
}

static void show_status(FILE *fp) {
	fprintf(fp, "  %s\n", version_string);
	fprintf(fp, "  Start time        : %s\n\n", start_time);

#ifdef ENABLE_CACHE
	fprintf(fp, "  Size of cache     : %9.1f kB\n", ((float)size_of_cache()) / KILOBYTE);
#endif
	fprintf(fp, "  Number of clients : %7d\n", number_of_clients());
	fprintf(fp, "  Number of bans    : %7d\n\n", number_of_bans());

	fprintf(fp, "  Clients served    : %7lu\n", counters[COUNTER_CLIENT]);
	fprintf(fp, "  Files requested   : %7lu\n", counters[COUNTER_FILE]);
	fprintf(fp, "  CGIs requested    : %7lu\n", counters[COUNTER_CGI]);
#ifdef ENABLE_XSLT
	fprintf(fp, "  Indexes requested : %7lu\n", counters[COUNTER_INDEX]);
#endif
	fprintf(fp, "  Data received     : %9.1f MB\n", ((float)transfer[TRANSFER_RECEIVED]) / MEGABYTE);
	fprintf(fp, "  Data send         : %9.1f MB\n\n", ((float)transfer[TRANSFER_SEND]) / MEGABYTE);

	fprintf(fp, "  Clients banned    : %7lu\n", counters[COUNTER_BAN]);
	fprintf(fp, "  Connections denied: %7lu\n", counters[COUNTER_DENY]);
	fprintf(fp, "  Exploit attempts  : %7lu\n", counters[COUNTER_EXPLOIT]);
}

static int run_tomahawk(char *line, FILE *fp, t_config *config) {
	char *cmd, *param, *param2;
	t_ip_addr ip;
	int retval = 0, time, id, count;

	split_string(line, &cmd, &param, ' ');

	if (strcmp(cmd, "ban") == 0) {
		/* Ban
		 */
		if (param == NULL) {
			fprintf(fp, "  ban what?\n");
		} else {
			if (split_string(param, &param, &param2, ' ') == 0) {
				time = str2int(param2);
			} else {
				time = TIMER_OFF;
			}
			if (parse_ip(param, &ip) == -1) {
				fprintf(fp, "  invalid IP!\n");
			} else switch (count = ban_ip(&ip, time, config->kick_on_ban)) {
				case -1:
					fprintf(fp, "  error while banning!\n");
					break;
				case 0:
					fprintf(fp, "  IP rebanned.\n");
					break;
				default:
					fprintf(fp, "  %d IPs banned.", count);
					if (config->kick_on_ban) {
						fprintf(fp, " and kicked\n");
					} else {
						fprintf(fp, "\n");
					}
			}
		}
	} else if (strcmp(cmd, "clear") == 0) {
		/* Clear
		 */
		if (param == NULL) {
			fprintf(fp, "  clear what?\n");
#ifdef ENABLE_CACHE
		} else if (strcmp(param, "cache") == 0) {
			fprintf(fp, "  %d files removed from the cache.\n", clear_cache());
#endif
		} else if (strcmp(param, "screen") == 0) {
			fprintf(fp, "\033[2J\033[H");
		} else if (strcmp(param, "counters") == 0) {
			clear_counters();
		} else {
			fprintf(fp, "  clear it yourself!\n");
		}
	} else if (strcmp(cmd, "help") == 0) {
		/* Help
		 */
		show_help(fp);
	} else if (strcmp(cmd, "kick") == 0) {
		/* Kick
		 */
		if (param == NULL) {
			fprintf(fp, "  kick what?\n");
		} else if (strcmp(param, "all") == 0) {
			fprintf(fp, "   %d clients have been kicked.\n", disconnect_clients(config));
		} else if ((id = str2int(param)) != -1) {
			if (kick_client(id) == 1) {
				fprintf(fp, "  client has been kicked.\n");
			} else {
				fprintf(fp, "  client not found!\n");
			}
		} else if (parse_ip(param, &ip) != -1) {
			fprintf(fp, "  %d clients have been kicked.\n", kick_ip(&ip));
		} else if (strcmp(param, "yourself") == 0) {
			fprintf(fp, "  I can't. I'm a computer.\n");
		} else if (strcmp(param, "me") == 0) {
			fprintf(fp, "  you need help...\n");
		} else {
			fprintf(fp, "  %s kicked back. Ouch!\n", param);
		}
	} else if (strcmp(cmd, "show") == 0) {
		/* Show
		 */
		if (param == NULL) {
			fprintf(fp, "  show what?\n");
		} else if (strcmp(param, "bans") == 0) {
			print_ban_list(fp);
#ifdef ENABLE_CACHE
		} else if (strcmp(param, "cache") == 0) {
			print_cache_list(fp);
#endif
		} else if (strcmp(param, "clients") == 0) {
			print_client_list(fp);
		} else if (strcmp(param, "status") == 0) {
			show_status(fp);
		} else {
			fprintf(fp, "  can't show that!\n");
		}
	} else if (strcmp(cmd, "unban") == 0) {
		/* Unban
		 */
		if (param == NULL) {
			fprintf(fp, "  unban who?\n");
		} else if (strcmp(param, "all") == 0) {
			default_ipv4(&ip);
			count = unban_ip(&ip);
#ifdef ENABLE_IPV6
			default_ipv6(&ip);
			count += unban_ip(&ip);
#endif
			fprintf(fp, "  %d IPs have been unbanned.\n", count);
		} else if (parse_ip(param, &ip) == -1) {
			fprintf(fp, "  invalid IP!\n");
		} else if (unban_ip(&ip) == 1) {
			fprintf(fp, "  IP has been unbanned.\n");
		} else {
			fprintf(fp, "  IP not found!\n");
		}
	} else if ((strcmp(cmd, "quit") == 0) || (strcmp(cmd, "exit") == 0)) {
		/* Quit
		 */
		retval = cc_DISCONNECT;
	} else if (strcmp(cmd, "") != 0) {
		/* Unknown
		 */
		fprintf(fp, "  unknown command!\n");
	}

	return retval;
}

/* Handle a administrator tomahawk.
 */
int handle_admin(t_admin *admin, t_config *config) {
	int retval = cc_OKE;
	char line[MAX_CMD_SIZE + 1], *pwd, encrypted[33];
	unsigned char digest[16];

	if (fgets(line, MAX_CMD_SIZE, admin->fp) != NULL) {
		line[MAX_CMD_SIZE] = '\0';
		admin->timer = MAX_IDLE_TIME;
		if (strlen(line) >= MAX_CMD_SIZE - 1) {
			do {
				if (fgets(line, MAX_CMD_SIZE, admin->fp) == NULL) {
					return cc_DISCONNECT;
				}
			} while (strlen(line) >= MAX_CMD_SIZE - 1);
			if (admin->authenticated == false) {
				fprintf(admin->fp, "\033[00m");
				retval = cc_DISCONNECT;
			}
			fprintf(admin->fp, "  don't do that!\n");
		} else if (admin->authenticated) {
			retval = run_tomahawk(remove_spaces(line), admin->fp, config);
		} else {
			fprintf(admin->fp, "\0338\033[A\033[K\0338\n"); /* Restore cursor position and color and erase to end of line */

			pwd = remove_spaces(line);
			md5((unsigned char*)pwd, strlen(pwd), digest);
			md5_bin2hex(digest, encrypted);
			if ((admin->authenticated = (strcmp(encrypted, config->tomahawk_port->binding_id) == 0)) == false) {
				retval = cc_DISCONNECT;
				fprintf(admin->fp, "Password incorrect\n\n");
			} else {
				fprintf(admin->fp, "Welcome. Use 'help' for help. Auto-logout after %d seconds idle-time.\n\n", MAX_IDLE_TIME);
				fflush(admin->fp);
			}
		}
	} else {
		fprintf(admin->fp, "  read error!\n");
		retval = cc_DISCONNECT;
	}

	if (retval == 0) {
		fprintf(admin->fp, "%s", prompt);
		fflush(admin->fp);
	}

	return retval;
}

#endif

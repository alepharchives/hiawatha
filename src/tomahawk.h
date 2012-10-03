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

#ifndef _TOMAHAWK_H
#define _TOMAHAWK_H

#include <poll.h>
#include "config.h"

#ifdef ENABLE_TOMAHAWK

#include "serverconfig.h"

#define cc_OKE            0
#define cc_DISCONNECT     1

#define COUNTER_CLIENT    0
#define COUNTER_FILE      1
#define COUNTER_CGI       2
#define COUNTER_INDEX     3
#define COUNTER_BAN       4
#define COUNTER_DENY      5
#define COUNTER_EXPLOIT   6
#define COUNTER_MAX       7

#define TRANSFER_SEND     0
#define TRANSFER_RECEIVED 1
#define TRANSFER_MAX      2

typedef struct type_admin {
	int socket;
	struct pollfd *poll_data;
	FILE *fp;
	bool authenticated;
	int timer;

	struct type_admin *next;
} t_admin;

void increment_counter(int counter);
void increment_transfer(int counter, long bytes);

void init_tomahawk_module(void);
int  add_admin(int sock);
void remove_admin(int sock);
void check_admin_list(void);
t_admin *first_admin(void);
t_admin *next_admin(void);
int handle_admin(t_admin *admin, t_config *config);
void disconnect_admins(void);

#endif

#endif

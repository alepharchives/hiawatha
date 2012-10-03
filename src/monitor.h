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

#ifndef _MONITOR_H
#define _MONITOR_H

#include "config.h"

#ifdef ENABLE_MONITOR

#include <time.h>
#include "serverconfig.h"
#include "session.h"

int  init_monitor_module(t_config *config);
void shutdown_monitor_module(t_config *config);

int  monitor_server_start(void);
int  monitor_server_stop(void);
#ifdef ENABLE_LOADCHECK
int  monitor_high_server_load(double load);
#endif
int  monitor_stats(t_config *config, time_t now);
int  monitor_request(t_session *session);

void monitor_counter_request(t_session *session);
void monitor_counter_ban(t_session *session);
void monitor_counter_exploit_attempt(t_session *session);

#endif

#endif

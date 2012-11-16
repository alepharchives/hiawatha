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

#ifndef _LOG_H
#define _LOG_H

#include "global.h"
#include "libip.h"
#include "session.h"

void init_log_module(void);
void log_pid(t_config *config, pid_t pid, uid_t server_uid);
void log_string(char *logfile, char *mesg, ...);
void log_system(t_session *session, char *mesg, ...);
void log_file_error(t_session *session, char *file, char *mesg, ...);
void log_error(t_session *session, char *mesg);
void log_request(t_session *session);
void log_garbage(t_session *session);
void log_exploit_attempt(t_session *session, char *type, char *data);
void log_unban(char *logfile, t_ip_addr *ip_address, unsigned long connect_attempts);
void log_cgi_error(t_session *session, char *mesg);
void close_logfiles(t_host *host, time_t now);
void close_logfiles_for_cgi_run(t_host *host);
#ifdef ENABLE_DEBUG
void log_debug(t_session *session, char *mesg, ...);
#endif

#endif

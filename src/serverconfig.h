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

#ifndef _SERVERCONFIG_H
#define _SERVERCONFIG_H

#include <stdbool.h>
#include <pthread.h>
#include <poll.h>
#include <regex.h>
#include "global.h"
#include "libip.h"
#include "mimetype.h"
#ifdef ENABLE_TOOLKIT
#include "toolkit.h"
#endif
#ifdef ENABLE_RPROXY
#include "rproxy.h"
#endif
#include "libfs.h"
#include "liblist.h"
#include "userconfig.h"
#ifdef ENABLE_SSL
#include "libssl.h"
#endif

#define MAX_START_FILE_LENGTH 32

typedef enum { root, part } t_pathmatch;
typedef enum { no_auth, basic, digest } t_auth_method;
typedef enum { hiawatha, common, extended } t_log_format;
#ifdef CYGWIN
typedef enum { windows, cygwin } t_platform;
#endif

#ifdef ENABLE_MONITOR
typedef struct type_monitor_srv_stats {
	int simultaneous_connections;
} t_monitor_srv_stats;

typedef struct type_monitor_host_stats {
	int requests;
	off_t bytes_sent;
	int bans;
	int exploit_attempts;

	int result_forbidden;
	int result_not_found;
	int result_internal_error;
} t_monitor_host_stats;
#endif

typedef struct type_deny_body {
	regex_t pattern;
	struct type_deny_body *next;
} t_deny_body;

typedef struct type_cgi_handler {
	char          *handler;
	t_charlist    extension;
	struct type_cgi_handler *next;
} t_cgi_handler;

typedef struct type_connect_to {
	char          *unix_socket;
	int           port;
	t_ip_addr     ip_addr;
	bool          available;

	struct type_connect_to *next;
} t_connect_to;

typedef struct type_cgi_session {
	t_ip_addr     client_ip;
	t_connect_to  *connect_to;
	time_t        session_timeout;

	struct type_cgi_session *next;
} t_cgi_session;

typedef struct type_fcgi_server {
	char          *fcgi_id;
	t_connect_to  *connect_to;
	t_charlist    extension;
	int           session_timeout;
	char          *chroot;
	size_t        chroot_len;

	t_cgi_session *cgi_session_list[256];
	pthread_mutex_t cgi_session_mutex[256];

	struct type_fcgi_server *next;
} t_fcgi_server;

typedef struct type_throttle {
	char          *filetype;
	unsigned long upload_speed;

	struct type_throttle *next;
} t_throttle;

typedef struct type_binding {
	int           port;
	t_ip_addr     interface;
	char          *binding_id;
#ifdef ENABLE_SSL
	bool          use_ssl;
	char          *key_cert_file;
	char          *ca_cert_file;
	char          *ca_crl_file;
	rsa_context   *private_key;
	x509_cert     *certificate;
	x509_cert     *ca_certificate;
	x509_crl      *ca_crl;
#endif

	bool          enable_trace;
	bool          enable_alter;
	int           max_keepalive;
	long          max_request_size;
	long          max_upload_size;
	int           time_for_1st_request;
	int           time_for_request;

	int           socket;
	struct pollfd *poll_data;

	struct type_binding *next;
} t_binding;

typedef struct type_directory {
	char          *path;
	t_pathmatch   path_match;
	char          *wrap_cgi;
	t_groups      groups;
	char          *start_file;
	bool          execute_cgi;
	bool          execute_cgiset;
#ifdef ENABLE_XSLT
	char          *show_index;
	bool          show_index_set;
#endif
	bool          follow_symlinks;
	bool          follow_symlinks_set;
	bool          use_gz_file;
	bool          use_gz_file_set;
	t_auth_method auth_method;
	char          *passwordfile;
	char          *groupfile;
	t_charlist    required_group;
	t_accesslist  *access_list;
	t_accesslist  *alter_list;
	t_charlist    alter_group;
	mode_t        alter_fmode;
	t_charlist    image_referer;
	char          *imgref_replacement;
	t_keyvalue    *envir_str;
	int           time_for_cgi;
	char          *run_on_download;

	/* Uploadspeed control
	 */
	int           max_clients;
	int           nr_of_clients;
	long          upload_speed;
	long          session_speed;
	pthread_mutex_t client_mutex;

	struct type_directory *next;
} t_directory;

typedef struct type_host {
	char            *website_root;
	size_t          website_root_len;
	char            *start_file;
	t_error_handler *error_handlers;
	char            *access_logfile;
	FILE            *access_fileptr;
	FILE            **access_fp;
	time_t          access_time;
	char            *error_logfile;
	t_charlist      hostname;
	bool            user_websites;
	bool            execute_cgi;
	int             time_for_cgi;
	char            *no_extension_as;
#ifdef ENABLE_XSLT
	char            *show_index;
	bool            use_xslt;
#endif
	bool            allow_dot_files;
	bool            use_gz_file;
	char            *login_message;
	char            *passwordfile;
	t_auth_method   auth_method;
	char            *groupfile;
	t_charlist      required_binding;
	t_denybotlist   *deny_bot;
	t_charlist      required_group;
	t_charlist      alter_group;
	t_keyvalue      *custom_headers;
	char            *wrap_cgi;
	t_groups        groups;
	t_charlist      volatile_object;
	t_accesslist    *access_list;
	t_accesslist    *alter_list;
	mode_t          alter_fmode;
	char            *run_on_alter;
	t_charlist      image_referer;
	char            *imgref_replacement;
	t_keyvalue      *envir_str;
	t_keyvalue      *alias;
#ifdef ENABLE_TOOLKIT
	t_charlist      toolkit_rules;
#endif
#ifdef ENABLE_SSL
    bool            require_ssl;
	char            *key_cert_file;
	char            *ca_cert_file;
	char            *ca_crl_file;
	rsa_context     *private_key;
	x509_cert       *certificate;
	x509_cert       *ca_certificate;
	x509_crl        *ca_crl;
#endif
#ifdef ENABLE_RPROXY
	t_rproxy        *rproxy;
#endif
	bool            prevent_sqli;
	bool            prevent_xss;
	bool            prevent_csrf;
	bool            follow_symlinks;
	bool            enable_path_info;
	bool            trigger_on_cgi_status;
	bool            secure_url;
	t_charlist      fast_cgi;
	t_deny_body     *deny_body;
	bool            webdav_app;

#ifdef ENABLE_MONITOR
	t_monitor_host_stats *monitor_stats;
	bool            monitor_requests;
	bool            monitor_host;
#endif

	struct type_host *next;
} t_host;

typedef struct type_config {
	char          *mimetype_config;

	uid_t         server_uid;
	gid_t         server_gid;
	t_groups      groups;
	char          *server_string;
	t_binding     *binding;
	t_log_format  log_format;
	bool          wait_for_cgi;
	t_charlist    cgi_extension;
	int           total_connections;
	int           connections_per_ip;
	int           socket_send_timeout;
	bool          kill_timedout_cgi;
	char          *system_logfile;
	char          *garbage_logfile;
	char          *exploit_logfile;
	char          *pidfile;
	t_accesslist  *logfile_mask;
	char          *user_directory;
	bool          user_directory_set;
	t_iplist      *hide_proxy;
	t_accesslist  *request_limit_mask;
	int           max_url_length;

	t_mimetype    *mimetype;
	t_host        *first_host;
	t_directory   *directory;
	t_throttle    *throttle;
#ifdef ENABLE_TOOLKIT
	t_url_toolkit *url_toolkit;
#endif
	t_cgi_handler *cgi_handler;
	char          *cgi_wrapper;
	bool          wrap_user_cgi;
#ifdef CYGWIN
	t_platform    platform;
#endif

	int           ban_on_denied_body;
	int           ban_on_garbage;
	int           ban_on_max_per_ip;
	int           ban_on_flooding;
	int           ban_on_max_request_size;
	int           ban_on_sqli;
	int           ban_on_timeout;
	int           ban_on_wrong_password;
	int           ban_on_invalid_url;
	bool          kick_on_ban;
	bool          reban_during_ban;
	int           max_wrong_passwords;
	int           flooding_count;
	int           flooding_time;
	int           reconnect_delay;
	t_accesslist  *banlist_mask;
	t_fcgi_server *fcgi_server;

	char          *work_directory;
	char          *upload_directory;
	size_t        upload_directory_len;

#ifdef ENABLE_LOADCHECK
	double        max_server_load;
#endif

#ifdef ENABLE_CACHE
	off_t         cache_size;
	off_t         cache_max_filesize;
	off_t         cache_min_filesize;
#endif

#ifdef ENABLE_TOMAHAWK
	t_binding     *tomahawk_port;
#endif

#ifdef ENABLE_MONITOR
	bool          monitor_enabled;
	char          *monitor_directory;
	int           monitor_stats_interval;
	t_monitor_srv_stats monitor_stats;
#endif
#ifdef ENABLE_SSL
	int           min_ssl_version;
#endif
} t_config;

t_config *default_config(void);
int check_configuration(t_config *config);
int read_main_configfile(char *configfile, t_config *config, bool config_check);
int read_user_configfile(char *configfile, t_host *host, t_tempdata **tempdata);
t_host *get_hostrecord(t_host *host, char *hostname, t_binding *binding);
unsigned short get_throttlespeed(char *type, t_throttle *throttle);
void close_bindings(t_binding *binding);
#ifdef ENABLE_SSL
void fill_random_buffer(t_config *config, char *buffer, int size);
#endif

#endif

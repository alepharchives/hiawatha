/* Directory settings
 */
#define CONFIG_DIR  "/etc/hiawatha"
#define LOG_DIR     "/var/log/hiawatha"
#define PID_DIR     "/var/run"
#define SBIN_DIR    "/usr/sbin"
#define VERSION     "8.8"
#define WEBROOT_DIR "/var/www/hiawatha"
#define WORK_DIR    "/var/lib/hiawatha"

/* Settings
 */
#define _GNU_SOURCE 1
/* #undef CYGWIN */
/* #undef CIFS */

/* Hiawatha modules
 */
#define ENABLE_CACHE ON
/* #undef ENABLE_DEBUG */
#define ENABLE_IPV6 ON
#define ENABLE_LOADCHECK ON
#define ENABLE_MONITOR on
#define ENABLE_RPROXY ON
#define ENABLE_SSL ON
#define ENABLE_TOMAHAWK on
#define ENABLE_TOOLKIT ON
#define ENABLE_XSLT ON

/* Includes
 */
#define HAVE_CRYPT_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_NETINET_TCP_H 1
/* #undef HAVE_RPCSVC_CRYPT_H */

/* Functions
 */
#define HAVE_SETENV 1
#define HAVE_UNSETENV 1
#define HAVE_CLEARENV 1
#define HAVE_STRCASECMP 1
#define HAVE_STRNCASECMP 1
/* #undef HAVE_STRNSTR */
#define HAVE_STRCASESTR 1

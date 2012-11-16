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
#include <stdlib.h>
#include <string.h>
#include "alternative.h"
#include "envir.h"
#include "libstr.h"
#include "libip.h"
#include "session.h"

#define SSL_VAR_SIZE   512
#define MAX_HEADER_LEN 100

static int add_to_environment(t_fcgi_buffer *fcgi_buffer, char *key, char *value) {
	char buffer[8];
	int len;
	size_t key_len, value_len;

	if ((key == NULL) || (value == NULL)) {
		return 0;
	} else if (fcgi_buffer == NULL) {
		/* Normal CGI
		 */
		setenv(key, value, 1);
	} else {
		/* FastCGI
		 */
		key_len = strlen(key);
		value_len = strlen(value);

		if (value_len <= 127) {
			*buffer = (unsigned char)key_len;
			len = 1;
		} else {
			*(buffer) = (unsigned char)((key_len >> 24) | 0x80);
			*(buffer + 1) = (unsigned char)((key_len >> 16) & 0xff);
			*(buffer + 2) = (unsigned char)((key_len >> 8) & 0xff);
			*(buffer + 3) = (unsigned char)(key_len & 0xff);
			len = 4;
		}

		if (value_len <= 127) {
			*(buffer + len) = (unsigned char)value_len;
			len++;
		} else {
			*(buffer + len) = (unsigned char)((value_len >> 24) | 0x80);
			*(buffer + len + 1) = (unsigned char)((value_len >> 16) & 0xff);
			*(buffer + len + 2) = (unsigned char)((value_len >> 8) & 0xff);
			*(buffer + len + 3) = (unsigned char)(value_len & 0xff);
			len += 4;
		}

		if (send_fcgi_buffer(fcgi_buffer, buffer, len) == -1) {
			return -1;
		} else if (send_fcgi_buffer(fcgi_buffer, key, key_len) == -1) {
			return -1;
		} else if (send_fcgi_buffer(fcgi_buffer, value, value_len) == -1) {
			return -1;
		}
	}

	return 0;
}

static int add_to_environment_chroot(t_session *session, t_fcgi_buffer *fcgi_buffer, char *key, char *value) {
	size_t ofs = 0;
	char c;

	if ((key == NULL) || (value == NULL)) {
		return 0;
	} else if (session->fcgi_server != NULL) {
		if (strncmp(value, session->fcgi_server->chroot, session->fcgi_server->chroot_len) == 0) {
			c = value[session->fcgi_server->chroot_len];
			if ((c == '/') || (c == '\0')) {
				ofs = session->fcgi_server->chroot_len;
			}
		}
	}

	return add_to_environment(fcgi_buffer, key, value + ofs);
}

/* Copy a headerfield to an environment setting
 */
int headerfield_to_environment(t_session *session, t_fcgi_buffer *fcgi_buffer, char *key, char *envir) {
	char *value;

	if ((key == NULL) || (envir == NULL)) {
		return 0;
	} else if ((value = get_headerfield(key, session->headerfields)) != NULL) {
		return add_to_environment(fcgi_buffer, envir, value);
	} else {
		return 0;
	}
}

/* Set environment variables for CGI script.
 */
void set_environment(t_session *session, t_fcgi_buffer *fcgi_buffer) {
	char ip[MAX_IP_STR_LEN], len[20], value[10], *data, variable[MAX_HEADER_LEN], old;
	size_t len1, len2, path_info_len;
	bool has_path_info = false;
	t_headerfield *headerfields;
	t_keyvalue *envir;
#ifdef ENABLE_SSL
	char subject[SSL_VAR_SIZE], issuer[SSL_VAR_SIZE];
#endif
#ifdef CYGWIN
	char *root;
#endif

	add_to_environment(fcgi_buffer, "GATEWAY_INTERFACE", "CGI/1.1");
	add_to_environment(fcgi_buffer, "REQUEST_METHOD", session->method);
	add_to_environment(fcgi_buffer, "REQUEST_URI", session->request_uri);

	if (session->path_info != NULL) {
		path_info_len = strlen(session->path_info);
		if (path_info_len <= (unsigned int)session->uri_len) {
			if (memcmp(session->uri + session->uri_len - path_info_len, session->path_info, path_info_len) == 0) {
				has_path_info = true;
			}
		}
	}

	if (has_path_info) {
		old = *(session->uri + session->uri_len - path_info_len);
		*(session->uri + session->uri_len - path_info_len) = '\0';
		add_to_environment(fcgi_buffer, "SCRIPT_NAME", session->uri);
		*(session->uri + session->uri_len - path_info_len) = old;
	} else if (session->uri[session->uri_len - 1] == '/') {
		len1 = session->uri_len;
		len2 = strlen(session->host->start_file);

		if ((data = (char*)malloc(len1 + len2 + 1)) != NULL) {
			memcpy(data, session->uri, len1);
			memcpy(data + len1, session->host->start_file, len2);
			*(data + len1 + len2) = '\0';
			add_to_environment(fcgi_buffer, "SCRIPT_NAME", data);
			free(data);
		}
	} else {
		add_to_environment(fcgi_buffer, "SCRIPT_NAME", session->uri);
	}

	add_to_environment_chroot(session, fcgi_buffer, "SCRIPT_FILENAME", session->file_on_disk);
#ifdef CYGWIN
	if (session->config->platform == windows) {
		if ((root = strdup(session->host->website_root)) != NULL) {
			if ((data = cygwin_to_windows(root)) != NULL) {
				add_to_environment_chroot(session, fcgi_buffer, "DOCUMENT_ROOT", data);
			}
			free(root);
		}
	} else
#endif
		add_to_environment_chroot(session, fcgi_buffer, "DOCUMENT_ROOT", session->host->website_root);

	if (ip_to_str(ip, &(session->ip_address), MAX_IP_STR_LEN) != -1) {
		add_to_environment(fcgi_buffer, "REMOTE_ADDR", ip);
	}

	if (session->vars != NULL) {
		add_to_environment(fcgi_buffer, "QUERY_STRING", session->vars);
	}

	if (session->body != NULL) {
		len[19] = '\0';
		snprintf(len, 19, "%ld", session->content_length);
		add_to_environment(fcgi_buffer, "CONTENT_LENGTH", len);
		headerfield_to_environment(session, fcgi_buffer, "Content-Type:", "CONTENT_TYPE");
	}

	value[9] = '\0';
	snprintf(value, 9, "%d", session->binding->port);
	add_to_environment(fcgi_buffer, "SERVER_PORT", value);
	add_to_environment(fcgi_buffer, "SERVER_NAME", *(session->host->hostname.item));
	add_to_environment(fcgi_buffer, "SERVER_PROTOCOL", session->http_version);
	add_to_environment(fcgi_buffer, "SERVER_SOFTWARE", "Hiawatha v"VERSION);
	if (session->binding->binding_id != NULL) {
		add_to_environment(fcgi_buffer, "SERVER_BINDING", session->binding->binding_id);
	}
	if (ip_to_str(ip, &(session->binding->interface), MAX_IP_STR_LEN) != -1) {
		add_to_environment(fcgi_buffer, "SERVER_ADDR", ip);
	}
	add_to_environment(fcgi_buffer, "REDIRECT_STATUS", "200");

	if (session->remote_user != NULL) {
		if (session->http_auth == basic) {
			add_to_environment(fcgi_buffer, "AUTH_TYPE", "Basic");
		} else if (session->http_auth == digest) {
			add_to_environment(fcgi_buffer, "AUTH_TYPE", "Digest");
		}
		add_to_environment(fcgi_buffer, "REMOTE_USER", session->remote_user);
	}

	headerfield_to_environment(session, fcgi_buffer, "Accept:", "HTTP_ACCEPT");
	headerfield_to_environment(session, fcgi_buffer, "Accept-Charset:", "HTTP_ACCEPT_CHARSET");
	headerfield_to_environment(session, fcgi_buffer, "Accept-Encoding:", "HTTP_ACCEPT_ENCODING");
	headerfield_to_environment(session, fcgi_buffer, "Accept-Language:", "HTTP_ACCEPT_LANGUAGE");
	headerfield_to_environment(session, fcgi_buffer, "Authorization:", "HTTP_AUTHORIZATION");
	headerfield_to_environment(session, fcgi_buffer, "Client-IP:", "HTTP_CLIENT_IP");
	headerfield_to_environment(session, fcgi_buffer, "DNT:", "HTTP_DNT");
	headerfield_to_environment(session, fcgi_buffer, "Expect:", "HTTP_EXPECT");
	headerfield_to_environment(session, fcgi_buffer, "From:", "HTTP_FROM");
	headerfield_to_environment(session, fcgi_buffer, "Host:", "HTTP_HOST");
	headerfield_to_environment(session, fcgi_buffer, "If-Modified-Since:", "HTTP_IF_MODIFIED_SINCE");
	headerfield_to_environment(session, fcgi_buffer, "If-Unmodified-Since:", "HTTP_IF_UNMODIFIED_SINCE");
	headerfield_to_environment(session, fcgi_buffer, "Range:", "HTTP_RANGE");
	headerfield_to_environment(session, fcgi_buffer, "Referer:", "HTTP_REFERER");
	headerfield_to_environment(session, fcgi_buffer, "User-Agent:", "HTTP_USER_AGENT");
	headerfield_to_environment(session, fcgi_buffer, "Via:", "HTTP_VIA");

	/* Webdav headers
	 */
	if (session->host->webdav_app) {
		headerfield_to_environment(session, fcgi_buffer, "Depth:", "HTTP_DEPTH");
		headerfield_to_environment(session, fcgi_buffer, "Destination:", "HTTP_DESTINATION");
		headerfield_to_environment(session, fcgi_buffer, "If:", "HTTP_IF");
		headerfield_to_environment(session, fcgi_buffer, "Overwrite:", "HTTP_OVERWRITE");
	}

	/* Convert X-* HTTP headers to HTTP_* environment variables
	 */
	headerfields = session->headerfields;
	while (headerfields != NULL) {
		if (strncasecmp(headerfields->data, "X-", 2) == 0) {
			if (header_to_variable(headerfields->data, (char*)&variable, MAX_HEADER_LEN) != -1) {
				add_to_environment(fcgi_buffer, variable, headerfields->data + headerfields->value_offset);
			}
		}
		headerfields = headerfields->next;
	}

#ifdef ENABLE_SSL
	if (session->binding->use_ssl) {
		add_to_environment(fcgi_buffer, "HTTP_SCHEME", "https");
		add_to_environment(fcgi_buffer, "HTTPS", "on");
	} else {
#endif
		add_to_environment(fcgi_buffer, "HTTP_SCHEME", "http");
#ifdef ENABLE_SSL
		add_to_environment(fcgi_buffer, "HTTPS", "off");
	}
#endif

	if (session->path_info != NULL) {
		add_to_environment(fcgi_buffer, "PATH_INFO", session->path_info);
	}

	snprintf(value, 9, "%d", session->return_code);
	add_to_environment(fcgi_buffer, "HTTP_RETURN_CODE", value);
	if (session->error_code != -1) {
		snprintf(value, 9, "%d", session->error_code);
		add_to_environment(fcgi_buffer, "HTTP_GENERATED_ERROR", value);
	}

	if (session->cookie != NULL) {
		add_to_environment(fcgi_buffer, "HTTP_COOKIE", session->cookie);
	}

	envir = session->host->envir_str;
	while (envir != NULL) {
		if (strncmp(envir->key, "CGIWRAP_", 8) != 0) {
			add_to_environment(fcgi_buffer, envir->key, envir->value);
		}
		envir = envir->next;
	}

#ifdef ENABLE_SSL
	if (session->binding->use_ssl) {
		if (get_client_crt_info(&(session->ssl_context), subject, issuer, SSL_VAR_SIZE) == 0) {
			add_to_environment(fcgi_buffer, "SSL_CLIENT_SUBJECT", subject);
			add_to_environment(fcgi_buffer, "SSL_CLIENT_ISSUER", issuer);
		}
	}
#endif
}

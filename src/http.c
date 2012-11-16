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
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include "global.h"
#include "session.h"
#include "libstr.h"
#include "tomahawk.h"
#include "log.h"
#ifdef ENABLE_MONITOR
#include "monitor.h"
#endif

#define REQUEST_BUFFER_CHUNK     4 * KILOBYTE
#define NO_REQUEST_LIMIT_TIME  300
#define NO_REQUEST_LIMIT_SIZE   16 * MEGABYTE

extern char *hs_conlen;

/* Read the request from a client socket.
 */
int fetch_request(t_session *session) {
	char *new_reqbuf, *strstart, *strend;
	long max_request_size, bytes_read, header_length = -1, content_length = -1;
	int result = 200, write_bytes, poll_result;
	time_t deadline;
	struct pollfd poll_data;
	bool keep_reading = true, store_on_disk = false;
	int upload_handle = -1;

	if (session->request_limit == false) {
		deadline = session->time + NO_REQUEST_LIMIT_TIME;
		max_request_size = NO_REQUEST_LIMIT_SIZE;
	} else if (session->kept_alive == 0) {
		deadline = session->time + session->binding->time_for_1st_request;
		max_request_size = session->binding->max_request_size;
	} else {
		deadline = session->time + session->binding->time_for_request;
		max_request_size = session->binding->max_request_size;
	}

	do {
		/* Check if requestbuffer contains a complete request.
		 */
		if (session->request != NULL) {
			if (header_length == -1) {
				if ((strstart = strstr(session->request, "\r\n\r\n")) != NULL) {
					*(strstart + 2) = '\0';
					header_length = strstart + 4 - session->request;
					session->header_length = header_length;

					determine_request_method(session);
					store_on_disk = (session->request_method == PUT) && session->binding->enable_alter;

					if (store_on_disk) {
	 					if ((session->uploaded_file = (char*)malloc(session->config->upload_directory_len + 15)) != NULL) {
							strcpy(session->uploaded_file, session->config->upload_directory);
							strcpy(session->uploaded_file + session->config->upload_directory_len, "/upload_XXXXXX");
							if ((upload_handle = mkstemp(session->uploaded_file)) == -1) {
								free(session->uploaded_file);
								session->uploaded_file = NULL;
							}
						}
						if (session->uploaded_file == NULL) {
							log_error(session, "can't create temporary file for PUT request");
							result = 500;
							break;
						}

						session->uploaded_size = session->bytes_in_buffer - header_length;
						if (write_buffer(upload_handle, session->request + header_length, session->uploaded_size) == -1) {
							result = 500;
							break;
						}
						session->bytes_in_buffer = header_length;
					}

				}
			}
			if (header_length != -1) {
				if (content_length == -1) {
					if ((strstart = strcasestr(session->request, hs_conlen)) != NULL) {
						strstart += 16;
						if ((strend = strstr(strstart, "\r\n")) != NULL) {
							*strend = '\0';
							content_length = str2int(strstart);
							*strend = '\r';
							if ((content_length < 0) || (INT_MAX - content_length - 2 <= header_length)) {
								result = 500;
								break;
							}

							if (store_on_disk) {
								/* Write to file on disk
								 */
								session->content_length = 0;
								if (content_length > session->binding->max_upload_size) {
									result = 413;
									break;
								}

								session->buffer_size = header_length + REQUEST_BUFFER_CHUNK;
								if ((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
									session->request = new_reqbuf;
								} else {
									session->error_cause = ec_SOCKET_READ_ERROR;
									result = -1;
									break;
								}
							} else {
								/* Read into memory
								 */
								session->content_length = content_length;
								if (header_length + content_length > max_request_size) {
									session->error_cause = ec_MAX_REQUESTSIZE;
									result = -1;
									break;
								}

								if (header_length + content_length > session->buffer_size) {
									session->buffer_size = header_length + content_length;
									if ((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
										session->request = new_reqbuf;
									} else {
										session->error_cause = ec_SOCKET_READ_ERROR;
										result = -1;
										break;
									}
								}
							}
						}
					} else {
						session->content_length = 0;
						if (store_on_disk) {
							result = 411;
						}
						break;
					}
				}

				if (content_length > -1) {
					if (store_on_disk) {
						if (session->uploaded_size == content_length) {
							/* Received a complete PUT request */
							break;
						}
					} else {
						if (session->bytes_in_buffer >= header_length + content_length) {
							/* Received a complete request */
							break;
						}
					}
				}
			}
		}

#ifdef ENABLE_SSL
		poll_result = session->binding->use_ssl ? ssl_pending(&(session->ssl_context)) : 0;

		if (poll_result == 0) {
#endif
			poll_data.fd = session->client_socket;
			poll_data.events = POLL_EVENT_BITS;
			poll_result = poll(&poll_data, 1, 1000);
#ifdef ENABLE_SSL
		}
#endif

		switch (poll_result) {
			case -1:
				if (errno != EINTR) {
					session->error_cause = ec_SOCKET_READ_ERROR;
					result = -1;
					keep_reading = false;
				}
				break;
			case 0:
				if (session->force_quit) {
					session->error_cause = ec_FORCE_QUIT;
					result = -1;
					keep_reading = false;
				} else if (time(NULL) > deadline) {
					session->error_cause = ec_TIMEOUT;
					result = -1;
					keep_reading = false;
				}
				break;
			default:
				if ((content_length == -1) && ((session->buffer_size - session->bytes_in_buffer) < 256)) {
					session->buffer_size += REQUEST_BUFFER_CHUNK;
					if ((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
						session->request = new_reqbuf;
					} else {
						session->error_cause = ec_SOCKET_READ_ERROR;
						result = -1;
						keep_reading = false;
						break;
					}
				}

				/* Read from socket.
				 */
#ifdef ENABLE_SSL
				if (session->binding->use_ssl) {
					bytes_read = ssl_receive(&(session->ssl_context), session->request + session->bytes_in_buffer,
									session->buffer_size - session->bytes_in_buffer);
				} else
#endif
					bytes_read = recv(session->client_socket, session->request + session->bytes_in_buffer,
									session->buffer_size - session->bytes_in_buffer, 0);

				switch (bytes_read) {
					case -1:
						if (errno != EINTR) {
							session->error_cause = ec_SOCKET_READ_ERROR;
							result = -1;
							keep_reading = false;
						}
						break;
					case 0:
						session->error_cause = ec_CLIENT_DISCONNECTED;
						result = -1;
						keep_reading = false;
						break;
					default:
						if (store_on_disk) {
							/* Write to file on disk
							 */
							write_bytes = bytes_read;
							if (session->uploaded_size + bytes_read > content_length) {
								write_bytes -= ((session->uploaded_size + bytes_read) - content_length);
							}
							if (write_buffer(upload_handle, session->request + header_length, write_bytes) == -1) {
								result = 500;
								keep_reading = false;
								break;
							}
							if ((session->uploaded_size += write_bytes) > session->binding->max_upload_size) {
								keep_reading = false;
								result = 413;
								break;
							}
							if (write_bytes < bytes_read) {
								memmove(session->request + header_length, session->request + header_length + write_bytes, bytes_read - write_bytes);
								session->bytes_in_buffer += bytes_read - write_bytes;
								keep_reading = false;
							}
						} else {
							/* Read into memory
							 */
							session->bytes_in_buffer += bytes_read;
							*(session->request + session->bytes_in_buffer) = '\0';

							if (session->bytes_in_buffer > max_request_size) {
								keep_reading = false;
								session->error_cause = ec_MAX_REQUESTSIZE;
								result = -1;
								break;
							}
						}
				}
		}
	} while (keep_reading);

	if (upload_handle != -1) {
		fsync(upload_handle);
		close(upload_handle);
	}

#ifdef ENABLE_TOMAHAWK
	increment_transfer(TRANSFER_RECEIVED, header_length + content_length);
#endif

	return result;
}

/* Convert the requestbuffer to a session record.
 */
int parse_request(t_session *session, int total_bytes) {
	int retval = 200;
	char *request_end, *str_end, *conn;

	request_end = session->request + total_bytes;

	/* Request method
	 */
	session->method = str_end = session->request;
	while ((*str_end != ' ') && (str_end != request_end)) {
		str_end++;
	}
	if (str_end == request_end) {
		return 400;
	}
	*str_end = '\0';
	session->uri = ++str_end;

	/* URI
	 */
	while ((*str_end != ' ') && (str_end != request_end)) {
		str_end++;
	}
	if (str_end == request_end) {
		return 400;
	}
	*(str_end++) = '\0';
	session->uri_len = strlen(session->uri);
	if ((session->config->max_url_length > 0) && (session->uri_len > session->config->max_url_length)) {
		return 414;
	}

	if (strncmp(session->uri, "http://", 7) == 0) {
		return 400;
	} else if ((session->request_uri = strdup(session->uri)) == NULL) {
		return -1;
	}

	/* Protocol version
	 */
	if (min_strlen(str_end, 10) == false) {
		return 400;
	} else if (memcmp(str_end, "HTTP/", 5) != 0) {
		return 400;
	}

	session->http_version = str_end;
	str_end += 7;

	if ((*(str_end - 1) != '.') || (*(str_end + 1) != '\r') || (*(str_end + 2) != '\n')) {
		return 400;
	} else if (*(str_end - 2) != '1') {
		return 505;
	}
	*(str_end + 1) = '\0';

	/* Body and other request headerlines
	 */
	if (session->content_length > 0) {
		session->body = session->request + session->header_length;
	}
	session->headerfields = parse_headerfields(str_end + 3);
	session->hostname = strlower(get_headerfield("Host:", session->headerfields));
	session->cookie = get_headerfield("Cookie:", session->headerfields);

	if ((conn = get_headerfield("Connection:", session->headerfields)) != NULL) {
		conn = strlower(remove_spaces(conn));
	}
	session->keep_alive = false;

	switch (*str_end) {
		case '0':
			if ((conn != NULL) && (session->kept_alive < session->binding->max_keepalive)) {
				if (strcasecmp(conn, "keep-alive") == 0) {
					session->keep_alive = true;
				}
			}
			break;
		case '1':
			if (session->hostname == NULL) {
				retval = 400;
			} else if (session->kept_alive < session->binding->max_keepalive) {
				session->keep_alive = true;
				if (conn != NULL) {
					if (strcmp(conn, "close") == 0) {
						session->keep_alive = false;
					}
				}
			}
			break;
		default:
			retval = 505;
			break;
	}
	if (session->keep_alive) {
		session->kept_alive++;
	}

	return retval;
}

/* Convert the request uri to a filename.
 */
int uri_to_path(t_session *session) {
	size_t length, alias_length = 0;
	char *strstart, *strend;
	t_keyvalue *alias;
	int retval;

	/* Requested file in userdirectory?
	 */
	if (session->host->user_websites && (session->uri_len >= 3)) {
		if (*(session->uri + 1) == '~') {
			strstart = session->uri + 1;
			if ((strend = strchr(strstart, '/')) == NULL) {
				return 301;
			} else if ((length = strend - strstart) > 1) {
				if ((session->local_user = (char*)malloc(length + 1)) == NULL) {
					return 500;
				}

				memcpy(session->local_user, strstart, length);
				*(session->local_user + length) = '\0';

				if ((retval = get_homedir(session, session->local_user + 1)) != 200) {
					return retval;
				}
				session->host->error_handlers = NULL;
			} else {
				/* uri is '/~/...' */
				return 404;
			}
		}
	}

	/* Search for an alias.
	 */
	alias = session->host->alias;
	while (alias != NULL) {
		alias_length = strlen(alias->key);
		if (strncmp(session->uri, alias->key, alias_length) == 0) {
			if ((*(session->uri + alias_length) == '/') || (*(session->uri + alias_length) == '\0')) {
				session->alias_used = true;
				break;
			}
		}
		alias = alias->next;
	}

	/* Allocate memory
	 */
	if (alias == NULL) {
		length = session->host->website_root_len;
	} else {
		length = strlen(alias->value);
	}
	length += session->uri_len + MAX_START_FILE_LENGTH;
	if ((session->file_on_disk = (char*)malloc(length + 4)) == NULL) { /* + 3 for '.gz' (gzip encoding) */
		return 500;
	}

	/* Copy stuff
	 */
	if (alias == NULL) {
		length = session->host->website_root_len;
		memcpy(session->file_on_disk, session->host->website_root, length);
		strstart = session->uri;
		if (session->local_user != NULL) {
			strstart += strlen(session->local_user) + 1;
		}
	} else {
		length = strlen(alias->value);
		memcpy(session->file_on_disk, alias->value, length);
		strstart = session->uri + alias_length;

	}
	strcpy(session->file_on_disk + length, strstart);

	return 200;
}

int get_path_info(t_session *session) {
	t_fsbool is_dir;
	char *slash;

	if (session->alias_used) {
		return 200;
	}

	if (session->host->website_root_len >= strlen(session->file_on_disk)) {
		return 500;
	}

	slash = session->file_on_disk + session->host->website_root_len + 1;
	while (*slash != '\0') {
		if (*slash == '/') {
			*slash = '\0';
			is_dir = is_directory(session->file_on_disk);
			*slash = '/';

			switch (is_dir) {
				case error:
					return 500;
				case not_found:
					return 404;
				case no_access:
					return 403;
				case no:
					if ((session->path_info = strdup(slash)) == NULL) {
						return -1;
					}
					*slash = '\0';
					return 200;
				case yes:
					break;
			}
		}
		slash++;
	}

	return 200;
}

/* Validate URL
 */
bool validate_url(t_session *session) {
	if (valid_uri(session->uri, session->host->allow_dot_files)) {
		if (session->host->secure_url == false) {
			return true;
		} else if (strstr(session->request_uri, "%00") == NULL) {
			return true;
		} else {
			session->return_code = 403;
		}
	} else {
		session->return_code = (session->request_method == PUT) ? 403 : 404;
	}

	log_exploit_attempt(session, "invalid URL", NULL);
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled) {
		monitor_counter_exploit_attempt(session);
	}
#endif

	session->error_cause = ec_INVALID_URL;

	return false;
}

/* Return an error message.
 */
const char *http_error(int code) {
	int i;
	static const struct {
		int code;
		const char *message;
	} error[] = {
		/* Informational
		 */
		{100, "Continue"},
		{101, "Switching Protocols"},
		{102, "Processing"},
		{103, "Checkpoint"},

		/* Success
		 */
		{200, "OK"},
		{201, "Created"},
		{202, "Accepted"},
		{203, "Non-Authoritative Information"},
		{204, "No Content"},
		{205, "Reset Content"},
		{206, "Partial Content"},
		{207, "Multi-Status"},
		{208, "Already Reported"},

		/* Redirection
		 */
		{300, "Multiple Choices"},
		{301, "Moved Permanently"},
		{302, "Found"},
		{303, "See Other"},
		{304, "Not Modified"},
		{305, "Use Proxy"},
		{307, "Temporary Redirect"},
		{308, "Resume Incomplete"},

		/* Client error
		 */
		{400, "Bad Request"},
		{401, "Unauthorized"},
		{402, "Payment Required"},
		{403, "Forbidden"},
		{404, "Not Found"},
		{405, "Method Not Allowed"},
		{406, "Not Acceptable"},
		{407, "Proxy Authentication Required"},
		{408, "Request Timeout"},
		{409, "Conflict"},
		{410, "Gone"},
		{411, "Length Required"},
		{412, "Precondition Failed"},
		{413, "Request Entity Too Large"},
		{414, "Request-URI Too Long"},
		{415, "Unsupported Media Type"},
		{416, "Requested Range Not Satisfiable"},
		{417, "Expectation Failed"},
		{418, "I'm a teapot"},
		{422, "Unprocessable Entity"},
		{423, "Locked"},
		{424, "Failed Dependency"},
		{425, "Unordered Collection"},
		{426, "Upgrade Required"},
		{428, "Precondition Required"},
		{429, "Too Many Requests"},
		{431, "Request Header Fields Too Large"},

		/* Server error
		 */
		{500, "Internal Server Error"},
		{501, "Not Implemented"},
		{502, "Bad Gateway"},
		{503, "Service Unavailable"},
		{504, "Gateway Timeout"},
		{505, "HTTP Version Not Supported"},
		{506, "Variant Also Negotiates"},
		{507, "Insufficient Storage"},
		{508, "Loop Detected"},
		{509, "Bandwidth Limit Exceeded"},
		{510, "Not Extended"},
		{511, "Network Authentication Required"},
		{0,   NULL}
	};

	for (i=0; error[i].code != 0; i++) {
		if (error[i].code == code) {
			return error[i].message;
		}
	}

	return NULL;
}

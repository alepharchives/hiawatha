#ifndef _HTTP_H
#define _HTTP_H

#include "session.h"

int fetch_request(t_session *session);
int parse_request(t_session *session, int total_bytes);
int uri_to_path(t_session *session);
int get_path_info(t_session *session);
bool validate_url(t_session *session);
const char *http_error(int code);

#endif

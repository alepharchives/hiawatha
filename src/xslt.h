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

#ifndef _XSLT_H
#define _XSLT_H

#include "config.h"

#ifdef ENABLE_XSLT

#include <stdbool.h>
#include "session.h"

void init_xslt_module();
bool can_transform_with_xslt(t_session *session);
int transform_xml(t_session *session);
int show_index(t_session *session);

#endif

#endif

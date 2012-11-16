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
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include "libstr.h"
#include "libip.h"

int default_ipv4(t_ip_addr *ip_addr) {
	/* set to 0.0.0.0
	 */
	if (ip_addr == NULL) {
		return -1;
	}

	memset(ip_addr->value, '\0', IPv4_LEN);
	ip_addr->family = AF_INET;
	ip_addr->size = IPv4_LEN;

	return 0;
}

#ifdef ENABLE_IPV6
int default_ipv6(t_ip_addr *ip_addr) {
	/* set to ::
	 */
	if (ip_addr == NULL) {
		return -1;
	}

	memset(ip_addr->value, '\0', IPv6_LEN);
	ip_addr->family = AF_INET6;
	ip_addr->size = IPv6_LEN;

	return 0;
}
#endif

int set_to_localhost(t_ip_addr *ip_addr) {
	t_ipv4 *ipv4;

	/* Set to 127.0.0.1
	 */
	if (ip_addr == NULL) {
		return -1;
	}

	ipv4 = (t_ipv4*)&(ip_addr->value);
	*ipv4 = htonl(0x7F000001);
	ip_addr->family = AF_INET;
	ip_addr->size = IPv4_LEN;

	return 0;
}

int parse_ip(char *str, t_ip_addr *ip_addr) {
	if ((str == NULL) || (ip_addr == NULL)) {
		return -1;
	}

	if (inet_pton(AF_INET, str, ip_addr->value) > 0) {
		ip_addr->family = AF_INET;
		ip_addr->size = IPv4_LEN;
#ifdef ENABLE_IPV6
	} else if (inet_pton(AF_INET6, str, ip_addr->value) > 0) {
		ip_addr->family = AF_INET6;
		ip_addr->size = IPv6_LEN;
#endif
	} else {
		ip_addr->family = AF_UNSPEC;
		ip_addr->size = 0;

		return -1;
	}

	return ip_addr->family;
}

unsigned char index_by_ip(t_ip_addr *ip) {
	unsigned char index = 0;
	int i;

	if (ip != NULL) {
		for (i = 0; i < ip->size; i++) {
			index += ip->value[i];
		}
	}

	return index;
}

int copy_ip(t_ip_addr *dest, t_ip_addr *src) {
	if ((dest == NULL) || (src == NULL)) {
		return -1;
	} else if ((unsigned int)src->size > MAX_IP_LEN) {
		return -1;
	}

	dest->family = src->family;
	memcpy(dest->value, src->value, src->size);
	dest->size = src->size;

	return 0;
}

bool same_ip(t_ip_addr *ip1, t_ip_addr *ip2) {
	if ((ip1 != NULL) && (ip2 != NULL)) {
		if ((ip1->family == ip2->family) && (ip1->size == ip2->size)) {
			return (memcmp(ip1->value, ip2->value, ip1->size) == 0);
		}
	}

	return false;
}

int apply_netmask(t_ip_addr *ip, int mask) {
	int byte;

	if (ip == NULL) {
		return -1;
	} else if (ip->family == AF_INET) {
		byte = IPv4_LEN - 1;
		mask = (8 * IPv4_LEN) - mask;
#ifdef ENABLE_IPV6
	} else if (ip->family == AF_INET6) {
		byte = IPv6_LEN - 1;
		mask = (8 * IPv6_LEN) - mask;
#endif
	} else {
		return -1;
	}

	while ((byte >= 0) && (mask > 0)) {
		if (mask >= 8) {
			ip->value[byte] = 0;
		} else {
			ip->value[byte] = (ip->value[byte] >> mask) << mask;
		}

		byte--;
		mask -= 8;
	}

	return 0;
}

bool ip_in_subnet(t_ip_addr *ip, t_ip_addr *subnet, int mask) {
	t_ip_addr test_ip;

	if ((ip == NULL) || (subnet == NULL)) {
		return false;
	} else if (ip->family != subnet->family) {
		return false;
	}

	/* Apply mask to client IP
	 */
	copy_ip(&test_ip, ip);
	if (apply_netmask(&test_ip, mask) == -1) {
		return false;
	}

	return same_ip(&test_ip, subnet);
}

int parse_ip_port(char *line, t_ip_addr *ip, int *port) {
	char *s_ip, *s_port, sep = '?';

	if ((line == NULL) || (ip == NULL) || (port == NULL)) {
		return -1;
	}

#ifdef ENABLE_IPV6
	if (split_string(line, &s_ip, &s_port, ']') == 0) {
		if ((*s_ip != '[') || (*s_port != ':')) {
			return -1;
		}
		s_ip = remove_spaces(s_ip + 1);
		s_port = remove_spaces(s_port + 1);
	} else
#endif
	{
		s_port = line + strlen(line);
		do {
			if (s_port <= line) {
				return -1;
			}
			s_port--;
		} while ((*s_port != ':') && (*s_port != '.'));
		sep = *s_port;
		*s_port = '\0';
		s_ip = remove_spaces(line);
		s_port = remove_spaces(s_port + 1);
	}

	if (parse_ip(s_ip, ip) == -1) {
		return -1;
	} else if ((*port = str2int(s_port)) <= 0) {
		return -1;
	}

	if (sep != '?') {
		if ((ip->family == AF_INET) && (sep != ':')) {
			return -1;
		}
#ifdef ENABLE_IPV6
		if ((ip->family == AF_INET6) && (sep != '.')) {
			return -1;
		}
#endif
	}

	return 0;
}

/* Write an IP address to a logfile.
 */
int ip_to_str(char *str, t_ip_addr *ip, int max_len) {
	if (inet_ntop(ip->family, &(ip->value), str, max_len) == NULL) {
		strcpy(str, "?.?.?.?");

		return -1;
	}

	return 0;
}

/* Convert hostname to an IP address
 */
int hostname_to_ip(char *hostname, t_ip_addr *ip) {
	struct hostent *hostinfo;

	if ((hostinfo = gethostbyname(hostname)) == NULL) {
		return -1;
	}

	memcpy(&ip->value, hostinfo->h_addr, hostinfo->h_length);
	ip->family = hostinfo->h_addrtype;
	ip->size = hostinfo->h_length;

	return 0;
}

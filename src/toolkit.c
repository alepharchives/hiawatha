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

#ifdef ENABLE_TOOLKIT

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include "toolkit.h"
#include "libstr.h"
#include "libfs.h"
#include "alternative.h"

#define REGEXEC_NMATCH 10
#define MAX_SUB_DEPTH  10
#define MAX_MATCH_LOOP 20

t_url_toolkit *find_toolkit(char *toolkit_id, t_url_toolkit *url_toolkit) {
	if (toolkit_id == NULL) {
		return NULL;
	}

	while (url_toolkit != NULL) {
		if (strcmp(url_toolkit->toolkit_id, toolkit_id) == 0) {
			return url_toolkit;
		}
		url_toolkit = url_toolkit->next;
	}

	return NULL;
}

static int replace(char *src, int ofs, int len, char *rep, char **dst) {
	int len_rep;

	if ((src == NULL) || (rep == NULL) || (dst == NULL)) {
		return -1;
	}

	len_rep = strlen(rep);
	if ((*dst = (char*)malloc(strlen(src) - len + len_rep + 1)) == NULL) {
		return -1;
	}

	memcpy(*dst, src, ofs);
	memcpy(*dst + ofs, rep, len_rep);
	strcpy(*dst + ofs + len_rep, src + ofs + len);

	return 0;
}

bool toolkit_setting(char *key, char *value, t_url_toolkit *toolkit) {
	t_toolkit_rule *new_rule, *rule;
	char *rest;
	int loop, time;

	if ((key == NULL) || (value == NULL) || (toolkit == NULL)) {
		return false;
	}

	if (strcmp(key, "toolkitid") == 0) {
		return (toolkit->toolkit_id = strdup(value)) != NULL;
	}

	if ((new_rule = (t_toolkit_rule*)malloc(sizeof(t_toolkit_rule))) == NULL) {
		return false;
	} else if (toolkit->toolkit_rule == NULL) {
		toolkit->toolkit_rule = new_rule;
	} else {
		rule = toolkit->toolkit_rule;
		while (rule->next != NULL) {
			rule = rule->next;
		}
		rule->next = new_rule;
	}

	new_rule->condition = tc_none;
	new_rule->operation = to_none;
	new_rule->flow = tf_continue;
	new_rule->conditional_flow = tf_continue;
	new_rule->match_loop = 1;
	new_rule->parameter = NULL;
	new_rule->value = 0;
	new_rule->next = NULL;

	if (strcmp(key, "match") == 0) {
		/* Match
		 */
		new_rule->condition = tc_match;
		if (split_string(value, &value, &rest, ' ') == -1) {
			return false;
		} else if (regcomp(&(new_rule->pattern), value, REG_EXTENDED) != 0) {
			return false;
		}
		split_string(rest, &value, &rest, ' ');

		if (strcasecmp(value, "ban") == 0) {
			/* Match Ban
			 */
			new_rule->operation = to_ban;
			if ((new_rule->value = str2int(rest)) == false) {
				return false;
			}
		} else if (strcasecmp(value, "call") == 0) {
			/* Match Call
			 */
			new_rule->operation = to_sub;
			if (rest == NULL) {
				return false;
			} else if ((new_rule->parameter = strdup(rest)) == NULL) {
				return false;
			}
		} else if (strcasecmp(value, "denyaccess") == 0) {
			/* Match DenyAccess
			 */
			new_rule->operation = to_denyaccess;
			new_rule->flow = tf_exit;
		} else if (strcasecmp(value, "exit") == 0) {
			/* Match Exit
			 */
			new_rule->flow = tf_exit;
		} else if (strcasecmp(value, "expire") == 0) {
			/* Match Expire
			 */
			new_rule->operation = to_expire;
			if (split_string(rest, &value, &rest, ' ') == -1) {
				return false;
			}
			if ((new_rule->value = str2int(value)) == -1) {
				return false;
			}

			time = new_rule->value;

			split_string(rest, &value, &rest, ' ');
			if (strcasecmp(value, "minutes") == 0) {
				new_rule->value *= MINUTE;
			} else if (strcasecmp(value, "hours") == 0) {
				new_rule->value *= HOUR;
			} else if (strcasecmp(value, "days") == 0) {
				new_rule->value *= DAY;
			} else if (strcasecmp(value, "weeks") == 0) {
				new_rule->value *= 7 * DAY;
			} else if (strcasecmp(value, "months") == 0) {
				new_rule->value *= 30.5 * DAY;
			} else if (strcasecmp(value, "seconds") != 0) {
				return false;
			}

			if (new_rule->value < time) {
				return false;
			}

			if (rest != NULL) {
				if (strcasecmp(rest, "exit") == 0) {
					new_rule->flow = tf_exit;
				} else if (strcasecmp(rest, "return") == 0) {
					new_rule->flow = tf_return;
				} else {
					return false;
				}
			}
		} else if (strcasecmp(value, "goto") == 0) {
			/* Match Goto
			 */
			new_rule->operation = to_sub;
			new_rule->flow = tf_exit;
			if (rest == NULL) {
				return false;
			} else if ((new_rule->parameter = strdup(rest)) == NULL) {
				return false;
			}
		} else if (strcasecmp(value, "redirect") == 0) {
			/* Match Redirect
			 */
			new_rule->operation = to_redirect;
			new_rule->flow = tf_exit;
			if (rest == NULL) {
				return false;
			} else if ((new_rule->parameter = strdup(rest)) == NULL) {
				return false;
			}
		} else if (strcasecmp(value, "return") == 0) {
			/* Match Return
			 */
			new_rule->flow = tf_return;
		} else if (strcasecmp(value, "rewrite") == 0) {
			/* Match Rewrite
			 */
			new_rule->operation = to_rewrite;
			new_rule->flow = tf_exit;

			split_string(rest, &value, &rest, ' ');
			if (value == NULL) {
				return false;
			} else if ((new_rule->parameter = strdup(value)) == NULL) {
				return false;
			}

			if (rest != NULL) {
				split_string(rest, &value, &rest, ' ');
				if ((loop = str2int(value)) > 0) {
					if (loop > MAX_MATCH_LOOP) {
						return false;
					}
					new_rule->match_loop = loop;
					if ((value = rest) == NULL) {
						return true;
					}
				} else if (rest != NULL) {
					return false;
				}

				if (strcasecmp(value, "continue") == 0) {
					new_rule->flow = tf_continue;
				} else if (strcasecmp(value, "return") == 0) {
					new_rule->flow = tf_return;
				} else {
					return false;
				}
			}
		} else if (strcasecmp(value, "skip") == 0) {
			/* Match Skip
			 */
			new_rule->operation = to_skip;
			if ((new_rule->value = str2int(rest)) < 1) {
				return false;
			}
		} else if (strcasecmp(value, "usefastcgi") == 0) {
			/* Match UseFastCGI
			 */
			new_rule->operation = to_fastcgi;
			new_rule->flow = tf_exit;
			if (rest == NULL) {
				return false;
			} else if ((new_rule->parameter = strdup(rest)) == NULL) {
				return false;
			}
		} else {
			return false;
		}
	} else if (strcmp(key, "call") == 0) {
		/* Call
		 */
		new_rule->operation = to_sub;

		if ((new_rule->parameter = strdup(value)) == NULL) {
			return false;
		}
	} else if (strcmp(key, "oldbrowser") == 0) {
		/* Old browser
		 */
		new_rule->condition = tc_oldbrowser;
		new_rule->operation = to_replace;
		new_rule->flow = tf_exit;

		if (valid_uri(value, false) == false) {
			return false;
		} else if ((new_rule->parameter = strdup(value)) == NULL) {
			return false;
		}
	} else if (strcmp(key, "skip") == 0) {
		/* Skip
		 */
		new_rule->operation = to_skip;

		if ((new_rule->value = str2int(value)) < 1) {
			return false;
		}
	} else if (strcmp(key, "requesturi") == 0) {
		/* RequestURI
		 */
		new_rule->condition = tc_requesturi;

		if (split_string(value, &value, &rest, ' ') == -1) {
			return false;
		}

		if (strcasecmp(value, "exists") == 0) {
			new_rule->value = IU_EXISTS;
		} else if (strcasecmp(value, "isfile") == 0) {
			new_rule->value = IU_ISFILE;
		} else if (strcasecmp(value, "isdir") == 0) {
			new_rule->value = IU_ISDIR;
		} else {
			return false;
		}

		if (strcasecmp(rest, "return") == 0) {
			new_rule->conditional_flow = tf_return;
		} else if (strcasecmp(rest, "exit") == 0) {
			new_rule->conditional_flow = tf_exit;
		} else {
			return false;
		}
#ifdef ENABLE_SSL
	} else if (strcmp(key, "usessl") == 0) {
		/* UseSSL
		 */
		new_rule->condition = tc_usessl;
		split_string(value, &value, &rest, ' ');

		if (strcasecmp(value, "call") == 0) {
			/* UseSSL Call
			 */
			new_rule->operation = to_sub;
			if (rest == NULL) {
				return false;
			} else if ((new_rule->parameter = strdup(rest)) == NULL) {
				return false;
			}
		} else if (strcasecmp(value, "exit") == 0) {
			/* UseSSL Exit
			 */
			new_rule->flow = tf_exit;
		} else if (strcasecmp(value, "goto") == 0) {
			/* UseSSL Goto
			 */
			new_rule->operation = to_sub;
			new_rule->flow = tf_exit;
			if (rest == NULL) {
				return false;
			} else if ((new_rule->parameter = strdup(rest)) == NULL) {
				return false;
			}
		} else if (strcasecmp(value, "return") == 0) {
			/* UseSSL Return
			 */
			new_rule->flow = tf_return;
		} else if (strcasecmp(value, "skip") == 0) {
			/* UseSSL Skip
			 */
			new_rule->operation = to_skip;
			if ((new_rule->value = str2int(rest)) < 1) {
				return false;
			}
		} else {
			return false;
		}
#endif
	} else {
		/* Unknown condition
		 */
		return false;
	}

	return true;
}

bool toolkit_rules_oke(t_url_toolkit *url_toolkit) {
	t_url_toolkit *toolkit;
	t_toolkit_rule *rule;

	toolkit = url_toolkit;
	while (toolkit != NULL) {
		if (toolkit->toolkit_id == NULL) {
			fprintf(stderr, "A ToolkitID is missing in an UrlToolkit section.\n");
			return false;
		}

		rule = toolkit->toolkit_rule;
		while (rule != NULL) {
			if (rule->operation == to_sub) {
				if (rule->parameter == NULL) {
					fprintf(stderr, "Missing parameter in toolkit rule '%s'.\n", toolkit->toolkit_id);
					return false;
				} else if (find_toolkit(rule->parameter, url_toolkit) == NULL) {
					fprintf(stderr, "Unknown ToolkitID in Goto/Call in toolkit rule '%s'.\n", toolkit->toolkit_id);
					return false;
				}
			}
			rule = rule->next;
		}
		toolkit = toolkit->next;
	}

	return true;
}

static int do_rewrite(char *url, regex_t *regexp, regmatch_t *pmatch, char *rep, char **new_url, int loop) {
	int ofs, len, i, n;
	char *repl, *c, *sub, *tmp;
	bool first_run = true;

	if ((url == NULL) || (regexp == NULL) || (rep == NULL) || (new_url == NULL)) {
		return -1;
	}

	*new_url = NULL;
	while (loop-- > 0) {
		if (first_run) {
			first_run = false;
		} else if (regexec(regexp, url, REGEXEC_NMATCH, pmatch, 0) == REG_NOMATCH) {
			break;
		}

		if ((ofs = pmatch[0].rm_so) == -1) {
			return -1;
		}

		if ((repl = strdup(rep)) == NULL) {
			return -1;
		}

		/* Replace '$x' in replacement string with substring.
		 */
		c = repl;
		while (*c != '\0') {
			if (*c == '$') {
				if ((*(c+1) >= '0') && (*(c+1) <= '9')) {
					i = *(c+1) - 48;
					if (pmatch[i].rm_so != -1) {
						len = pmatch[i].rm_eo - pmatch[i].rm_so;
						if ((sub = strdup(url + pmatch[i].rm_so)) == NULL) {
							free(repl);
							return -1;
						}
						sub[len] = '\0';
					} else {
						if ((sub = strdup("")) == NULL) {
							free(repl);
							return -1;
						}
					}
					n = c - repl;

					if (replace(repl, n, 2, sub, &tmp) == -1) {
						free(repl);
						return -1;
					}

					free(repl);
					repl = tmp;
					c = repl + n + strlen(sub) - 1;
					free(sub);
				}
			}
			c++;
		}

		/* Replace pattern with replacement string.
		 */
		len = pmatch[0].rm_eo - ofs;
		if (replace(url, ofs, len, repl, new_url) == -1) {
			free(repl);
			return -1;
		}
		url = *new_url;

		free(repl);
	}

	return 0;
}

void init_toolkit_options(t_toolkit_options *options, char *website_root, t_url_toolkit *toolkit,
#ifdef ENABLE_SSL
	                      bool use_ssl,
#endif
						  bool allow_dot_files, t_headerfield *headerfields) {
	options->sub_depth = 0;
	options->new_url = NULL;
	options->website_root = website_root;
	options->fastcgi_server = NULL;
	options->ban = 0;
	options->expire = -1;
	options->url_toolkit = toolkit;
#ifdef ENABLE_SSL
	options->use_ssl = use_ssl;
#endif
	options->allow_dot_files = allow_dot_files;
	options->headerfields = headerfields;
}

int use_toolkit(char *url, char *toolkit_id, t_toolkit_options *options) {
	t_url_toolkit *toolkit;
	t_toolkit_rule *rule;
	bool condition_met, replaced = false;
	int result, skip = 0;
	char *file, *qmark;
	regmatch_t pmatch[REGEXEC_NMATCH];
	char *user_agent;
	struct stat fileinfo;

	if (options == NULL) {
		return UT_ERROR;
	}

	options->new_url = NULL;

	if ((toolkit = find_toolkit(toolkit_id, options->url_toolkit)) == NULL) {
		return UT_ERROR;
	}

	rule = toolkit->toolkit_rule;
	while (rule != NULL) {
		condition_met = false;

		/* Skip lines
		 */
		if (skip > 0) {
			skip--;
			rule = rule->next;
			continue;
		}

		/* Condition
		 */
		switch (rule->condition) {
			case tc_none:
				/* None
				 */
				condition_met = true;
				break;
			case tc_match:
				/* Match
				 */
				if (regexec(&(rule->pattern), url, REGEXEC_NMATCH, pmatch, 0) == 0) {
					condition_met = true;
				}
				break;
			case tc_requesturi:
				/* Request URI
				 */
				if (valid_uri(url, false) == false) {
					break;
				}
				if ((file = make_path(options->website_root, url)) == NULL) {
					return UT_ERROR;
				}

				if ((qmark = strchr(file, '?')) != NULL) {
					*qmark = '\0';
				}
				url_decode(file);

				if (stat(file, &fileinfo) != -1) {
					switch (rule->value) {
						case IU_EXISTS:
							if (S_ISDIR(fileinfo.st_mode) || S_ISREG(fileinfo.st_mode)) {
								rule->flow = rule->conditional_flow;
								condition_met = true;
							}
							break;
						case IU_ISFILE:
							if (S_ISREG(fileinfo.st_mode)) {
								rule->flow = rule->conditional_flow;
								condition_met = true;
							}
							break;
						case IU_ISDIR:
							if (S_ISDIR(fileinfo.st_mode)) {
								rule->flow = rule->conditional_flow;
								condition_met = true;
							}
							break;
					}
				}

				free(file);
				break;
#ifdef ENABLE_SSL
			case tc_usessl:
				/* Client connections uses SSL?
				 */
				condition_met = options->use_ssl;
				break;
#endif
			case tc_oldbrowser:
				/* Old browser
				 */
				if ((user_agent = get_headerfield("User-Agent:", options->headerfields)) != NULL) {
					if (strstr(user_agent, "MSIE 7") != NULL) {
						condition_met = true;
					} else if (strstr(user_agent, "MSIE 6") != NULL) {
						condition_met = true;
					}
				}
				break;
		}

		/* Condition not met
		 */
		if (condition_met == false) {
			rule = rule->next;
			continue;
		}

		/* Operation
		 */
		switch (rule->operation) {
			case to_none:
				/* None
				 */
				break;
			case to_rewrite:
				/* Rewrite
				 */
				if (do_rewrite(url, &(rule->pattern), pmatch, rule->parameter, &(options->new_url), rule->match_loop) == -1) {
					if (options->new_url != NULL) {
						free(options->new_url);
						options->new_url = NULL;
					}
					return UT_ERROR;
				}
				if (options->new_url != NULL) {
					if (replaced) {
						free(url);
					}
					url = options->new_url;
					replaced = true;
				} else if (replaced) {
					options->new_url = url;
				}
				break;
			case to_sub:
				/* Subroutine
				 */
				if (++(options->sub_depth) > MAX_SUB_DEPTH) {
					return UT_ERROR;
				}

				if ((result = use_toolkit(url, rule->parameter, options)) == UT_ERROR) {
					if (options->new_url != NULL) {
						free(options->new_url);
						options->new_url = NULL;
					}
					return UT_ERROR;
				}
				options->sub_depth--;

				if (options->new_url != NULL) {
					if (replaced) {
						free(url);
					}
					url = options->new_url;
					replaced = true;
				} else if (replaced) {
					options->new_url = url;
				}

				if (result != UT_RETURN) {
					return result;
				}
				break;
			case to_expire:
				/* Send Expire HTTP header
				 */
				options->expire = rule->value;
				break;
			case to_skip:
				/* Skip
				 */
				skip = rule->value;
				break;
			case to_denyaccess:
				/* Deny access
				 */
				return UT_DENY_ACCESS;
			case to_redirect:
				/* Redirect client
				 */
				if (do_rewrite(url, &(rule->pattern), pmatch, rule->parameter, &(options->new_url), rule->match_loop) == -1) {
					if (options->new_url != NULL) {
						free(options->new_url);
						options->new_url = NULL;
					}
					return UT_ERROR;
				}
				if (options->new_url != NULL) {
					if (replaced) {
						free(url);
					}
					return UT_REDIRECT;
				} else if (replaced) {
					options->new_url = url;
				}
				break;
			case to_fastcgi:
				/* Use FastCGI server
				 */
				options->fastcgi_server = rule->parameter;
				break;
			case to_ban:
				/* Ban client
				 */
				options->ban = rule->value;
				break;
			case to_replace:
				/* Replace URL
				 */
				if (replaced) {
					free(url);
				}
				if ((options->new_url = strdup(rule->parameter)) == NULL) {
					return UT_ERROR;
				}
				break;
		}

		/* Flow
		 */
		switch (rule->flow) {
			case tf_continue:
				/* Continue
				 */
				break;
			case tf_exit:
				/* Exit
				 */
				return UT_EXIT;
			case tf_return:
				/* Return
				 */
				return UT_RETURN;
		}

		rule = rule->next;
	}

	return UT_RETURN;
}

#endif

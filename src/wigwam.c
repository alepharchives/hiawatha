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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_RPCSVC_CRYPT_H
#include <rpcsvc/crypt.h>
#endif
#include "global.h"
#include "alternative.h"
#include "libstr.h"
#include "libfs.h"
#include "libip.h"
#ifdef ENABLE_TOOLKIT
#include "toolkit.h"
#endif
#include "polarssl/md5.h"

#define MAX_INPUT_SIZE KILOBYTE
#define MAX_PATH 1024

typedef struct type_line {
	char *key, *value, *file;
	int linenr;
	struct type_line *next;
} t_line;

bool quiet = false;

int read_file(char *config_file, t_line **config, t_line **aliases, bool handle_include);

void mem_error() {
	fprintf(stderr, "Fatal error while allocating memory.\n");
	exit(EXIT_FAILURE);
}

t_line *last_result(t_line *config) {
	if (config != NULL) {
		while (config->next != NULL) {
			config = config->next;
		}
	}

	return config;
}

void add_result(t_line **config, char *key, char *value, char *file, int linenr) {
	t_line *new;

	if (*config == NULL) {
		if ((new = *config = (t_line*)malloc(sizeof(t_line))) == NULL) {
			mem_error();
		}
	} else {
		new = last_result(*config);
		if ((new->next = (t_line*)malloc(sizeof(t_line))) == NULL) {
			mem_error();
		}
		new = new->next;
	}
	new->next = NULL;

	new->key = key;
	new->value = value;
	new->file = file;
	new->linenr = linenr;
}

t_line *search_key(t_line *config, char *key) {
	t_line *result = NULL;

	while (config != NULL) {
		if (strcasecmp(config->key, key) == 0) {
			if (config->value == NULL) {
				printf("'%s' on line %d in '"CONFIG_DIR"/%s' requires a parameter.\n", config->key, config->linenr, config->file);
				exit(EXIT_FAILURE);
			} else {
				add_result(&result, config->key, config->value, config->file, config->linenr);
			}
		}
		config = config->next;
	}

	return result;
}

t_line *in_result(char *value, t_line *result) {
	while (result != NULL) {
		if (strcmp(result->value, value) == 0) {
			return result;
		}
		result = result->next;
	}

	return NULL;
}

void dispose_result(t_line *config, bool free_content) {
	t_line *prev;

	while (config != NULL) {
		prev = config;
		config = config->next;

		if (free_content) {
			free(prev->key);
		}
		free(prev);
	}
}

int read_directory(char *dir, t_line **config, t_line **aliases) {
	t_filelist *filelist, *file;
	char *path;
	int retval = 0;

	if ((filelist = read_filelist(dir)) == NULL) {
		return -1;
	}
	file = filelist = sort_filelist(filelist);

	while (file != NULL) {
		if (strcmp(file->name, "..") != 0) {
			if ((path = make_path(dir, file->name)) != NULL) {
				if (file->is_dir) {
					retval = read_directory(path, config, aliases);
					free(path);
				} else {
					retval = read_file(path, config, aliases, false);
				}

				if (retval == -1) {
					break;
				}
			} else {
				retval = -1;
				break;
			}
		}
		file = file->next;
	}
	remove_filelist(filelist);

	return retval;
}

static int fgets_multi(char *line, int size, FILE *fp) {
	int lines;
	char *pos;

	if ((line == NULL) || (size <= 1)) {
		return -1;
	} else if (fgets(line, size, fp) != NULL) {
		if ((pos = strstr(line, " \\\n")) == NULL) {
			pos = strstr(line, " \\\r");
		}

		if (pos == NULL) {
			lines = 0;
		} else if ((lines = fgets_multi(pos, size - (pos - line), fp)) == -1) {
			return -1;
		}
		return 1 + lines;
	} else {
		return 0;
	}
}


int read_file(char *config_file, t_line **config, t_line **aliases, bool handle_include) {
	FILE *fp;
	char line[MAX_INPUT_SIZE + 1], *data, *value;
	bool is_alias;
	int lines_read, linenr = 0, retval = 0;

	if (quiet == false) {
		printf("Reading %s\n", config_file);
	}

	if (config_file == NULL) {
		return -1;
	} else if ((fp = fopen(config_file, "r")) == NULL) {
		perror(config_file);
		return -1;
	}

	line[MAX_INPUT_SIZE] = '\0';
	while ((lines_read = fgets_multi(line, MAX_INPUT_SIZE, fp)) != 0) {
		if ((lines_read == -1) || (strlen(line) > MAX_INPUT_SIZE)) {
			fprintf(stderr, "Line %d in %s is too long.\n", linenr, config_file);
			return -1;
		}

		linenr += lines_read;
		data = uncomment(line);
		if ((data[0] == '#') || (data[0] == '\0')) {
			continue;
		}

		if (handle_include && (strncasecmp(data, "include ", 8) == 0)) {
			switch (is_directory(data + 8)) {
				case no:
					retval = read_file(strdup(data + 8), config, aliases, false);
					break;
				case yes:
					retval = read_directory(data + 8, config, aliases);
					break;
				default:
					retval = -1;
			}
		} else {
			if (strncmp(data, "set ", 4) == 0) {
				is_alias = true;
				data += 4;
			} else {
				is_alias = false;
			}

			if ((data = strdup(data)) == NULL) {
				mem_error();
			}
			split_configline(data, &data, &value);
			if (is_alias) {
				add_result(aliases, data, value, config_file, linenr);
			} else {
				add_result(config, strlower(data), value, config_file, linenr);
			}
		}

		if (retval == -1) {
			break;
		}
	}
	fclose(fp);

	return retval;
}

int read_config_file(char *config_file, t_line **config) {
	t_line *aliases = NULL, *alias, *line;
	char *new_value;
	int retval;

	if (config_file == NULL) {
		return -1;
	} else if ((retval = read_file(config_file, config, &aliases, true)) == -1) {
		return -1;
	}

	/* Replace the aliasses
	 */
	line = *config;
	while (line != NULL) {
		alias = aliases;
		while (alias != NULL) {
			if (line->value != NULL) {
				if (str_replace(line->value, alias->key, alias->value, &new_value) > 0) {
					line->value = new_value;
				}
			}
			alias = alias->next;
		}
		line = line->next;
	}
	dispose_result(aliases, true);

	return retval;
}

bool is_ip_address(char *str) {
	t_ip_addr ip_addr;

	return parse_ip(str, &ip_addr) != -1;
}

int find_duplicates(t_line *config, char *key, char *config_dir) {
	t_line *haystack, *needles, *needle;
	int errors = 0;

	haystack = needles = search_key(config, key);
	while (needles != NULL) {
		if ((needle = in_result(needles->value, needles->next)) != NULL) {
			printf("Duplicate %s found on line %d in '%s/%s'.\n", key, needle->linenr, config_dir, needle->file);
			errors++;
		}
		needles = needles->next;
	}
	dispose_result(haystack, false);

	return errors;
}

int check_main_config(char *config_dir) {
	int errors = 0;
	t_line *config = NULL, *haystack, *needles, *needle;
	char *item, *rest, *info;
	bool inside_section, has_dot;

	if (quiet == false) {
		printf("Using %s\n", config_dir);
	}

	if (chdir(config_dir) == -1) {
		perror(config_dir);
		return 1;
	}

	/* Read the configuration file
	 */
	config = NULL;
	if (read_config_file(strdup("hiawatha.conf"), &config) != 0) {
		return 1;
	}

	/* Find duplicate ids
	 */
	//errors += find_duplicates(config, "BindingId", config_dir);
	errors += find_duplicates(config, "FastCGIid", config_dir);
	errors += find_duplicates(config, "ToolkitId", config_dir);

	/* Duplicate hostnames check
	 */
	haystack = NULL;
	needles = needle = search_key(config, "hostname");
	while (needle != NULL) {
		if ((rest = strdup(needle->value)) == NULL) {
			mem_error();
		}
		while (rest != NULL) {
			split_string(rest, &item, &rest, ',');
			if (in_result(item, haystack) == false) {
				if ((info = strdup(item)) == NULL) {
					mem_error();
				}
				add_result(&haystack, info, info, needle->file, needle->linenr);
			} else {
				printf("Warning: duplicate hostname '%s' found on line %d in '%s/%s'.\n", item, needle->linenr, config_dir, needle->file);
				//errors++;
			}
		}
		free(rest);
		needle = needle->next;
	}
	dispose_result(needles, false);
	dispose_result(haystack, true);

	/* Binding Id check
	 */
	haystack = search_key(config, "bindingid");
	needles = needle = search_key(config, "requiredbinding");
	while (needle != NULL) {
		if ((rest = strdup(needle->value)) == NULL) {
			mem_error();
		}
		while (rest != NULL) {
			split_string(rest, &item, &rest, ',');
			if (in_result(item, haystack) == NULL) {
				printf("Unknown Binding ID '%s' in VirtualHost on line %d in '%s/%s'.\n", item, needle->linenr, config_dir, needle->file);
				errors++;
			}
		}
		free(rest);
		needle = needle->next;
	}
	dispose_result(needles, false);
	dispose_result(haystack, false);

	/* FastCGI Id check
	 */
	haystack = search_key(config, "fastcgiid");
	needles = needle = search_key(config, "usefastcgi");
	while (needle != NULL) {
		if ((rest = strdup(needle->value)) == NULL) {
			mem_error();
		}
		while (rest != NULL) {
			split_string(rest, &item, &rest, ',');
			if (in_result(item, haystack) == NULL) {
				printf("Unknown FastCGI server ID '%s' in VirtualHost on line %d in '%s/%s'.\n", needle->value, needle->linenr, config_dir, needle->file);
				errors++;
			}
		}
		free(rest);
		needle = needle->next;
	}
	dispose_result(needles, false);

	needle = config;
	while (needle != NULL) {
		if (strcmp(needle->key, "match") == 0) {
			if ((item = strcasestr(needle->value, " usefastcgi ")) != NULL) {
				item += 12;
				while ((*item == ' ') && (*item != '\0')) {
					item++;
				}
				if (*item != '\0') {
					if (in_result(item, haystack) == NULL) {
						printf("Unknown FastCGI server ID '%s' in UrlToolkit on line %d in '%s/%s'.\n", item, needle->linenr, config_dir, needle->file);
						errors++;
					}
				}
			}
		}
		needle = needle->next;
	}

	dispose_result(haystack, false);

	/* Toolkit ID check
	 */
	haystack = search_key(config, "toolkitid");
	needles = needle = search_key(config, "usetoolkit");
	while (needle != NULL) {
		if ((rest = strdup(needle->value)) == NULL) {
			mem_error();
		}
		while (rest != NULL) {
			split_string(rest, &item, &rest, ',');
			if (in_result(item, haystack) == NULL) {
				printf("Unknown UrlToolkit ID '%s' in VirtualHost on line %d in '%s/%s'.\n", item, needle->linenr, config_dir, needle->file);
				errors++;
			}
		}
		free(rest);
		needle = needle->next;
	}
	dispose_result(needles, false);
	dispose_result(haystack, false);

	/* Extension check
	 */
	haystack = NULL;
	needles = needle = search_key(config, "cgiextension");
	while (needle != NULL) {
		if ((rest = strdup(needle->value)) == NULL) {
			mem_error();
		}
		while (rest != NULL) {
			split_string(rest, &item, &rest, ',');
			if (in_result(item, haystack) == NULL) {
				add_result(&haystack, needle->key, item, needle->file, needle->linenr);
			} else {
				printf("Duplicate extension (%s) found in CGIextension.\n", item);
				errors++;
			}
		}
		needle = needle->next;
	}
	dispose_result(needles, false);

	needles = needle = search_key(config, "cgihandler");
	while (needle != NULL) {
#ifdef CYGWIN
		if ((rest = strstr(needle->value, ":\\")) != NULL) {
			rest += 2;
		} else
#endif
			if ((rest = strdup(needle->value)) == NULL) {
				mem_error();
			}
		split_string(rest, &info, &rest, ':');
#ifdef CYGWIN
		info = needle->value;
#endif
		while (rest != NULL) {
			split_string(rest, &item, &rest, ',');
			if (in_result(item, haystack) == NULL) {
				add_result(&haystack, needle->key, item, needle->file, needle->linenr);
			} else {
				printf("Duplicate extension (%s) found in CGIhandler %s.\n", item, info);
				errors++;
			}
		}
		needle = needle->next;
	}
	dispose_result(needles, false);

	dispose_result(haystack, false);

	/* Default-website hostname check (non-fatal)
	 */
	inside_section = false;
	haystack = config;
	while (haystack != NULL) {
		if (strncmp(haystack->key, "virtualhost", 11) == 0) {
			inside_section = true;
		} else if (strcmp(haystack->key, "}") == 0) {
			inside_section = false;
		} else if (inside_section == false) {
			if (strcmp(haystack->key, "hostname") == 0) {
				if (is_ip_address(haystack->value) == false) {
					printf("Warning: it is wise to use your IP address as the hostname of the default website (line %d in '%s/%s') and give it a blank webpage. By doing so, automated webscanners won't find your possible vulnerable website.\n", haystack->linenr, config_dir, haystack->file);
				}
				break;
			}
		}

		haystack = haystack->next;
	}

	/* Check for dots in extensios
	 */
	haystack = config;
	while (haystack != NULL) {
		if ((strcmp(haystack->key, "cgiextension") == 0) || (strcmp(haystack->key, "extension") == 0)) {
			has_dot = (strchr(haystack->value, '.') != NULL);
		} else if (strcmp(haystack->key, "cgihandler") == 0) {
#ifdef CYGWIN
			if ((info = strstr(haystack->value, ":\\")) != NULL) {
				info += 2;
			} else
#endif
				info = haystack->value;
			if ((rest = strchr(info, ':')) != NULL) {
				has_dot = (strchr(rest, '.') != NULL);
			} else {
				has_dot = false;
			}
		} else {
			has_dot = false;
		}

		if (has_dot) {
			printf("Extensions should not contain a dot (line %d in '%s/%s')\n", haystack->linenr, config_dir, haystack->file);
			errors++;
		}

		haystack = haystack->next;
	}

	dispose_result(config, true);

	return errors;
}

#ifdef ENABLE_TOOLKIT
void check_url_toolkit(char *config_dir, char **toolkit_id) {
	t_line *config = NULL;
	char input[MAX_INPUT_SIZE + 1], **id, *url, current_dir[MAX_PATH];
	t_url_toolkit *url_toolkit, *toolkit = NULL, *new_toolkit;
	t_toolkit_options options;
	bool in_rule_section = false;
	int result = 0;

	if (quiet == false) {
		printf("Using %s\n", config_dir);
	}

	if (getcwd(current_dir, MAX_PATH) == NULL) {
		return;
	} else if (chdir(config_dir) == -1) {
		perror(config_dir);
		return;
	}

	/* Read the configuration file
	 */
	config = NULL;
	if (read_config_file(strdup("hiawatha.conf"), &config) != 0) {
		return;
	}

	if (chdir(current_dir) == -1) {
		perror(current_dir);
		return;
	}

	/* Parse the URL toolkit rules
	 */
	url_toolkit = NULL;
	while (config != NULL) {
		if (in_rule_section) {
			if ((strcmp(config->key, "}") == 0) && (strcmp(config->value, "") == 0)) {
				in_rule_section = false;
			} else if (toolkit_setting(config->key, config->value, toolkit) == false) {
				fprintf(stderr, "UrlToolkit error in %s on line %d.\n", config->file, config->linenr);
				return;
			}
		} else if ((strcmp(config->key, "urltoolkit") == 0) && (strcmp(config->value, "{") == 0)) {
			if ((new_toolkit = (t_url_toolkit*)malloc(sizeof(t_url_toolkit))) == NULL) {
				perror("malloc()");
				return;
			}
			if (url_toolkit == NULL) {
				url_toolkit = toolkit = new_toolkit;
			} else {
				toolkit->next = new_toolkit;
				toolkit = toolkit->next;
			}
			toolkit->toolkit_id = NULL;
			toolkit->toolkit_rule = NULL;
			toolkit->next = NULL;

			in_rule_section = true;
		}
		config = config->next;
	}

	if (url_toolkit == NULL) {
		printf("No URL toolkit rules found.\n");
		return;
	}

	if (toolkit_rules_oke(url_toolkit) == false) {
		return;
	}

	if (*toolkit_id == NULL) {
		printf("No errors found in URL toolkit rules.\n");
		return;
	}

	id = toolkit_id;
	do {
		if (find_toolkit(*id, url_toolkit) == false) {
			printf("ToolkitID '%s' not found.\n", *id);
			return;
		}
		id++;
	} while (*id != NULL);

	/* Start testing
	 */
	input[MAX_INPUT_SIZE] = '\0';
	printf("\n===[ URL toolkit tester\n");
	printf("Use empty input to leave the program.\n\nurl: ");
	while (fgets(input, MAX_INPUT_SIZE, stdin) != NULL) {
		url = remove_spaces(input);

		if (strcmp(url, "") == 0) {
			printf("bye!\n\n");
			break;
		}

		if (*input != '/') {
			printf("Bad URL: missing leading slash.\n");
		}

#ifdef ENABLE_SSL
		init_toolkit_options(&options, ".", url_toolkit, false, false, NULL);
#else
		init_toolkit_options(&options, ".", url_toolkit, false, NULL);
#endif

		id = toolkit_id;
		while (*id != NULL) {
			if ((result = use_toolkit(url, *id, &options)) == UT_ERROR) {
				perror("use_toolkit()");
			}
			if (options.new_url != NULL) {
				url = options.new_url;
			}
			if (result == UT_REDIRECT) {
				break;
			}
			if (result == UT_DENY_ACCESS) {
				url = "(403 Forbidden)";
				break;
			}
			if (options.fastcgi_server != NULL) {
				break;
			}
			id++;
		}

		if (options.fastcgi_server != NULL) {
			printf("Using FastCGI server: %s\n", options.fastcgi_server);
		}
		if (options.new_url != NULL) {
			if (result == UT_REDIRECT) {
				printf("Request is redirected.\n");
			} else if (options.new_url[0] != '/') {
				printf("Warning: your new URL is missing a leading slash!\n");
			}
			printf("new: %s\n\n", options.new_url);
			free(options.new_url);
		} else {
			printf("old: %s\n\n", url);
		}

		printf("url: ");
	}
}
#endif

void read_password(char *buffer, int size) {
	struct termios tty;
	int pos = 0;
	char c;

	printf("Enter password: ");

	if (tcgetattr(STDOUT_FILENO, &tty) == -1) {
		printf("Terminal error.\n");
		return;
	}
	tty.c_lflag &= ~ECHO;
	if (tcsetattr(STDOUT_FILENO, TCSADRAIN, &tty) == -1) {
		printf("Terminal error.\n");
		return;
	}

	while (((c = getc(stdin)) != '\n') && (pos < size - 1)) {
		buffer[pos++] = c;
	}
	buffer[pos] = '\0';

	tty.c_lflag |= ECHO;
	if (tcsetattr(STDOUT_FILENO, TCSADRAIN, &tty) == -1) {
		printf("Terminal error.\n");
		return;
	}

	printf("\n");
}

void create_basic_password(char *username) {
	char password[100], salt[3], *encrypted;
	char *salt_digits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
	int len;

	srand((unsigned)time(NULL));
	len = strlen(salt_digits);

	read_password(password, 100);
	salt[0] = salt_digits[rand() % len];
	salt[1] = salt_digits[rand() % len];
	salt[2] = '\0';
	encrypted = crypt(password, salt);

	printf("%s:%s\n", username, encrypted);
}

void create_digest_password(char *username, char *realm) {
	char password[100], *data, encrypted[33];
	unsigned char digest[16];

	read_password(password, 100);

	if ((data = (void*)malloc(strlen(username) + strlen(realm) + strlen(password) + 4)) == NULL) {
		return;
	}

	sprintf(data, "%s:%s:%s", username, realm, password);
	md5((unsigned char*)data, strlen(data), digest);
	md5_bin2hex(digest, encrypted);

	free(data);

	printf("%s:%s:%s\n", username, realm, encrypted);
}

void show_help(char *wigwam) {
	printf("Usage: %s [options]\n", wigwam);
	printf("Options: -b <username>: create password file entry for basic HTTP authentication.\n");
	printf("         -c <path>: path to where the configration files are located.\n");
	printf("         -d <username> <realm>: create password file entry for digest HTTP authentication.\n");
	printf("         -h: show this information and exit.\n");
	printf("         -q: don't print the test results.\n");
#ifdef ENABLE_TOOLKIT
	printf("         -t [<toolkit_id> ...]: test URL toolkit rule(s).\n");
#endif
	printf("         -v: show version and exit.\n");
}

int main(int argc, char *argv[]) {
	int i, errors_found = 0;
	char *config_dir = CONFIG_DIR;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-b") == 0) {
			if (++i < argc) {
				create_basic_password(argv[i]);
				return EXIT_SUCCESS;
			} else {
				fprintf(stderr, "Specify a username.\n");
				return EXIT_FAILURE;
			}
		} else if (strcmp(argv[i], "-c") == 0) {
			if (++i < argc) {
				config_dir = argv[i];
			} else {
				fprintf(stderr, "Specify a directory.\n");
				return EXIT_FAILURE;
			}
		} else if (strcmp(argv[i], "-d") == 0) {
			if (++i < argc - 1) {
				create_digest_password(argv[i], argv[i + 1]);
				return EXIT_SUCCESS;
			} else {
				fprintf(stderr, "Specify a username and a realm.\n");
				return EXIT_FAILURE;
			}
        } else if (strcmp(argv[i], "-h") == 0) {
			show_help(argv[0]);
			return EXIT_SUCCESS;
#ifdef ENABLE_TOOLKIT
		} else if (strcmp(argv[i], "-t") == 0) {
			check_url_toolkit(config_dir, argv + i + 1);
			return EXIT_SUCCESS;
#endif
		} else if (strcmp(argv[i], "-q") == 0) {
			quiet = true;
		} else if (strcmp(argv[i], "-v") == 0) {
			printf("Wigwam v"VERSION"\n");
			return EXIT_SUCCESS;
		} else {
			fprintf(stderr, "Unknown option. Use '-h' for help.\n");
			return EXIT_FAILURE;
		}
	}

	errors_found += check_main_config(config_dir);

	if ((quiet == false) && (errors_found == 0))  {
		printf("No non-fatal errors found in the Hiawatha configuration.\n");
	}

	if (errors_found > 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

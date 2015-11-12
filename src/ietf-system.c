/*
 * Copyright (C) 2015 Sartura, Ltd.
 *
 * Author: Zvonimir Fras <zvonimir.fras@sartura.hr>
 * Author: Luka Perkov <luka.perkov@sartura.hr>
 *
 * freenetconfd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with freenetconfd. If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <linux/reboot.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <uci.h>

#include "freenetconfd/freenetconfd.h"
#include "freenetconfd/datastore.h"
#include "freenetconfd/plugin.h"
#include "freenetconfd/netconf.h"
#include "firmware_upgrade.h"

int rpc_set_current_datetime(struct rpc_data *data);
int rpc_system_restart(struct rpc_data *data);
int rpc_system_shutdown(struct rpc_data *data);

__unused struct module *init();
__unused void destroy();

struct module m;
char *ns = "urn:ietf:params:xml:ns:yang:ietf-system";

datastore_t root = DATASTORE_ROOT_DEFAULT;

/**
 * get_word_from_string() - helper function to handle extracting elements from line lists
 *
 * allocates memory, so you need to free it later.
 *
 * read_to will be set to the position where the word ends to ease you searching for
 * next word. You can pass NULL if you don't need that info.
 *
 * Returns: pointer to a \0 terminated word or NULL if at the end of string
 */
static char *get_word_from_string(char *str, char **read_to);
static int owrt_char_is_true(const char *value);

static char *get_uci(const char *path);
static int set_uci(const char *cmd, const char *value);
static int delete_uci(const char *to_delete);
static int add_list_uci(const char *list, const char *value);

static char *get_hostname(datastore_t *self);
static int set_hostname(datastore_t *self, char *value);
static char *get_location(datastore_t *self);
static int set_location(datastore_t *self, char *value);
static char *get_contact(datastore_t *self);
static int set_contact(datastore_t *self, char *value);
static char *get_system_ntp_enabled(datastore_t *self);
static int set_system_ntp_enabled(datastore_t *self, char *value);
static char *get_system_clock_timezone_name(datastore_t *self);
static int set_system_clock_timezone_name(datastore_t *self, char *value);
static char *get_system_clock_timezone_utc_offset(datastore_t *self);
static int set_system_clock_timezone_utc_offset(datastore_t *self, char *value);
static int set_system_ntp_server_name(datastore_t *self, char *value);
static char *get_current_datetime(datastore_t *self);
static char *get_boot_datetime(datastore_t *self);
static void update_system_ntp(datastore_t *self);
static int del_system_ntp_server(datastore_t *self, void *data);
static void update_system_dns_resolver(datastore_t *self);
static int set_system_dns_resolver_server_name(datastore_t *self, char *value);
static int del_system_dns_resolver_server(datastore_t *self, void *data);
static int del_system_dns_resolver_search(datastore_t *self, void *data);
static int set_system_dns_resolver_search(datastore_t *self, char *value);
static void update_system_state_platform(datastore_t *self);

static datastore_t *create_system_clock_child(datastore_t *self, char *name,
											  char *value, char *ns, char *target_name, int target_position);
static datastore_t *create_system_ntp_server_child(datastore_t *self, char *name,
												   char *value, char *ns, char *target_name, int target_position);
static datastore_t *create_system_ntp_child(datastore_t *self, char *name,
											char *value, char *ns, char *target_name, int target_position);
static datastore_t *create_system_dns_resolver_server_child(datastore_t *self, char *name,
															char *value, char *ns, char *target_name, int target_position);
static datastore_t *create_system_dns_resolver_child(datastore_t *self, char *name,
													 char *value, char *ns, char *target_name, int target_position);
static datastore_t *create_system_child(datastore_t *self, char *name,
										char *value, char *ns, char *target_name, int target_position);

static int create_store();

int create_store()
{
	// ietf-system
	datastore_t *system = ds_add_child_create(&root, "system", NULL, ns, NULL, 0);

	create_system_child(system, "contact", NULL, NULL, NULL, 0); // string
	create_system_child(system, "hostname", NULL, NULL, NULL, 0); // string
	create_system_child(system, "location", NULL, NULL, NULL, 0); // string

	datastore_t *system_clock = create_system_child(system, "clock", NULL, NULL, NULL, 0); // string
	// we're making timezone-name a default case for timezone choice since we can't check that on the fly
	create_system_clock_child(system_clock, "timezone-name", NULL, NULL, NULL, 0);

	datastore_t *system_ntp = create_system_child(system, "ntp", NULL, NULL, NULL, 0); // string
	create_system_ntp_child(system_ntp, "enabled", NULL, NULL, NULL, 0);
	system_ntp->update(system_ntp);

	datastore_t *system_dns_resolver = create_system_child(system, "dns-resolver", NULL, NULL, NULL, 0); // string
	system_dns_resolver->update(system_dns_resolver);


	// ietf-system-state
	datastore_t *system_state = ds_add_child_create(&root, "system-state", NULL, ns, NULL, 0);
	ds_set_is_config(system_state, 0, 0);

	datastore_t *platform = ds_add_child_create(system_state, "platform", NULL, ns, NULL, 0);
	platform->update = update_system_state_platform;

	ds_add_child_create(platform, "os-name", NULL, ns, NULL, 0);
	ds_add_child_create(platform, "os-release", NULL, ns, NULL, 0);
	ds_add_child_create(platform, "os-version", NULL, ns, NULL, 0);
	ds_add_child_create(platform, "machine", NULL, ns, NULL, 0);

	datastore_t *clock_state = ds_add_child_create(system_state, "clock", NULL, ns, NULL, 0);

	datastore_t *current_datetime = ds_add_child_create(clock_state, "current-datetime", "now", ns, NULL, 0);
	current_datetime->get = get_current_datetime;

	datastore_t *boot_datetime = ds_add_child_create(clock_state, "boot-datetime", "before", ns, NULL, 0);
	boot_datetime->get = get_boot_datetime;

	// firmware upgrade
	system_state->create_child = create_section_node;
	init_firmware_upgrade(system_state, ns);
	return 0;
}

datastore_t *create_system_child(datastore_t *self, char *name,
										char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(name, "contact"))
	{
		child->get = get_contact;
		child->set = set_contact;
	}
	else if (!strcmp(name, "hostname"))
	{
		child->get = get_hostname;
		child->set = set_hostname;
	}
	else if (!strcmp(name, "location"))
	{
		child->get = get_location;
		child->set = set_location;
	}
	else if (!strcmp(name, "clock"))
	{
		child->create_child = create_system_clock_child;
	}
	else if (!strcmp(name, "ntp"))
	{
		child->create_child = create_system_ntp_child;
		child->update = update_system_ntp;
	}
	else if (!strcmp(name, "dns-resolver"))
	{
		child->create_child = create_system_dns_resolver_child;
		child->update = update_system_dns_resolver;
	}

	return child;
}

datastore_t *create_system_clock_child(datastore_t *self, char *name,
                                       char *value, char *ns, char *target_name, int target_position)
{
	ds_purge_choice_group(self, 1);

	datastore_t *child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "timezone-name"))
	{
		child->choice_group = 1;
		child->get = get_system_clock_timezone_name;
		child->set = set_system_clock_timezone_name;
	}
	else if (!strcmp(name, "timezone-utc-offset"))
	{
		child->choice_group = 1;
		child->get = get_system_clock_timezone_utc_offset;
		child->set = set_system_clock_timezone_utc_offset;
	}

	return child;
}

datastore_t *create_system_ntp_child(datastore_t *self, char *name,
											char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(name, "enabled"))
	{
		child->get = get_system_ntp_enabled;
		child->set = set_system_ntp_enabled;
	}
	else if (!strcmp(name, "server"))
	{
		child->is_list = 1;
		child->create_child = create_system_ntp_server_child;
		child->del = del_system_ntp_server;
	}

	return child;
}

datastore_t *create_system_ntp_server_child(datastore_t *self, char *name,
												   char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(name, "name"))
	{
		child->is_key = 1;
		child->set = set_system_ntp_server_name;
	}
	else
	{
		// "udp" "association_type" "iburst" "prefer" are not supported by the deviation.
		ds_free(child, 0);
		child = NULL;
	}

	return child;
}


char *get_contact(datastore_t *self)
{
	return get_uci("system.@system[0].contact");
}

int set_contact(datastore_t *self, char *value)
{
	char cmd[] = "system.@system[0].contact=";
	return set_uci(cmd, value);
}

char *get_hostname(datastore_t *self)
{
	char *retVal = get_uci("system.@system[0].hostname");
	return retVal;
}

int set_hostname(datastore_t *self, char *value)
{
	char cmd[] = "system.@system[0].hostname=";
	return set_uci(cmd, value);
}

char *get_location(datastore_t *self)
{
	return get_uci("system.@system[0].location");
}

int set_location(datastore_t *self, char *value)
{
	char cmd[] = "system.@system[0].location=";
	return set_uci(cmd, value);
}

char *get_system_ntp_enabled(datastore_t *self)
{
	return get_uci("system.ntp.enable_server");
}

int set_system_ntp_enabled(datastore_t *self, char *value)
{
	char cmd[] = "system.ntp.enable_server=";
	return set_uci(cmd, value);
}

char *get_system_clock_timezone_name(datastore_t *self)
{
	char *tz = get_uci("system.@system[0].timezone");
	char *rc = NULL;

	if (!strcmp(tz, "UTC"))
		rc = strdup("Africa/Abidjan");
	else if (!strcmp(tz, "CET-1CEST,M3.5.0,M10.5.0/3"))
		rc = strdup("Europe/Zagreb");

	free(tz);

	return rc;
}

int set_system_clock_timezone_name(datastore_t *self, char *value)
{
	char cmd[] = "system.@system[0].timezone=";
	return set_uci(cmd, value);
}

char *get_system_clock_timezone_utc_offset(datastore_t *self)
{
	char *tz = get_uci("system.@system[0].timezone");
	char *rc = NULL;

	if (!strcmp(tz, "UTC"))
		rc = strdup("0");
	else if (!strcmp(tz, "CET-1CEST,M3.5.0,M10.5.0/3"))
		rc = strdup("60");

	free(tz);

	return rc;
}

int set_system_clock_timezone_utc_offset(datastore_t *self, char *value)
{
	char cmd[] = "system.@system[0].timezone=";
	return set_uci(cmd, value);
}

int set_system_ntp_server_name(datastore_t *self, char *value)
{
	return add_list_uci("system.ntp.server", value);
}

static char* time_to_string(const struct tm *timeptr)
{
	static char result[26];
	sprintf(result, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d\n",
		1900 + timeptr->tm_year,
		timeptr->tm_mon,
		timeptr->tm_mday,
		timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec
		);
	return result;
}

char *get_current_datetime(datastore_t *self)
{
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	return strdup(time_to_string(timeinfo));
}

char *get_boot_datetime(datastore_t *self)
{
	time_t rawtime;
	struct sysinfo info;
	struct tm *timeinfo;

	time(&rawtime);
	sysinfo(&info);

	rawtime -= info.uptime;
	timeinfo = localtime(&rawtime);

	return strdup(time_to_string(timeinfo));
}

void update_system_ntp(datastore_t *self)
{
	// update server list
	// delete current list
	datastore_t *server;
	while ((server = ds_find_child(self, "server", NULL)) != NULL)
	{
		ds_free(server, 0);
	}

	// get with uci and recreate list
	struct uci_context *c;
	struct uci_ptr p;
	char *a = strdup("system.ntp.server");

	c = uci_alloc_context();
	if (uci_lookup_ptr(c, &p, a, true) != UCI_OK)
	{
		uci_perror(c, "XXX");
		return;
	}

	struct uci_element *e;

	if (p.o && p.o->type == UCI_TYPE_LIST)
	{
		uci_foreach_element(&p.o->v.list, e)
		{
			if (e->name)
			{
				server = self->create_child(self, "server", NULL, ns, NULL, 0);
				server->create_child(server, "name", e->name, ns, NULL, 0);
			}
		}
	}

	uci_free_context(c);
	free(a);
}

int del_system_ntp_server(datastore_t *self, void *data)
{
	struct uci_context *context;
	struct uci_ptr ptr;
	char *cmd = strdup("system.ntp.server");

	context = uci_alloc_context();
	if (uci_lookup_ptr(context, &ptr, cmd, true) != UCI_OK)
	{
		uci_perror(context, "XXX");
		return 1;
	}

	// delete list from uci
	delete_uci("system.ntp.server");

	struct uci_element *e;

	if (ptr.o && ptr.o->type == UCI_TYPE_LIST)
	{
		uci_foreach_element(&ptr.o->v.list, e)
		{
			if (e->name)
			{
				// if it's not the server we have to delete, add it
				if (strcmp(e->name, self->child->value))
					add_list_uci("system.ntp.server", e->name);
			}
		}
	}

	uci_set(context, &ptr);

	uci_save(context, ptr.p);
	uci_commit(context, &ptr.p, true);

	uci_free_context(context);
	free(cmd);

	return 0;
}

char *get_word_from_string(char *str, char **read_to)
{
	char *element;
	char *word_beginning = str;

	// skip leading spaces if any
	while(!((element = strchr(word_beginning, ' ')) - word_beginning))
		word_beginning++;

	// no word or last word found
	if (!element)
	{
		// last word
		if (*word_beginning)
		{
			if (read_to)
				*read_to = word_beginning + strlen(word_beginning);

			return strdup(word_beginning);
		}

		// no word
		return NULL;
	}

	int word_size = element - word_beginning;
	char *rc = malloc(word_size + 1);

	if (!rc)
	{
		DEBUG("Not enough memory!\n");
		return NULL;
	}

	memcpy(rc, word_beginning, word_size);
	rc[word_size] = '\0'; // terminate the string

	if (read_to)
		*read_to = word_beginning + word_size;

	return rc;
}

void update_system_dns_resolver(datastore_t *self)
{
	// OpenWRT has multiple places to set and get dns information
	// We're using /etc/resolv.conf

	FILE *fp = fopen("/etc/resolv.conf", "r");

	if (!fp)
	{
		DEBUG("Cannot opet /etc/resolv.conf, check the rights.\n");
		return;
	}

	// delete children, we'll recreate them
	datastore_t *child;
	for (child = self->child; child; )
	{
		datastore_t *tmp = child;
		child = child->next;
		ds_free(tmp, 0);
	}

	// read line by line
	char *line = malloc(1024);
	ssize_t read;
	size_t len = 1024;
	while ((read = getline(&line, &len, fp)) != -1)
	{
		if (line[read-1] == '\n')
			line[read-1] = '\0';

		if (!strncmp(line, "search", 6))
		{
			// read list and add one by one
			char *element;
			char *str = line + 7; // skip "search"
			while ((element = get_word_from_string(str, &str)))
			{
				self->create_child(self, "search", element, ns, NULL, 0);
				free(element);
			}
		}
		else if (!strncmp(line, "nameserver", 10))
		{
			datastore_t *server = self->create_child(self, "server", NULL, ns, NULL, 0);
			server->create_child(server, "name", line + 11, ns, NULL, 0);
		}
	}

	free(line);
	fclose(fp);
}

int set_system_dns_resolver_server_name(datastore_t *self, char *value)
{
	FILE *resolv_file = fopen("/etc/resolv.conf", "r");

	if (!resolv_file)
	{
		DEBUG("Cannot opet /etc/resolv.conf, check the rights.\n");
		return -1;
	}

	FILE *resolv_tmp_file = fopen("/tmp/resolv.conf.freenetconfd", "w");

	if (!resolv_tmp_file)
	{
		fclose(resolv_file);
		DEBUG("Cannot opet /tmp/resolv.conf.freenetconfd, check the rights.\n");
		return -1;
	}

	// read line by line
	char *line = malloc(1024);
	ssize_t read;
	size_t len = 1024;
	int should_create = 1;
	while ((read = getline(&line, &len, resolv_file)) != -1)
	{
		if (line[read-1] == '\n')
			line[read-1] = '\0';

		if (!strncmp(line, "nameserver", 10))
		{
			char *name = get_word_from_string(line+10, NULL);

			if (!name)
			{
				fprintf(resolv_tmp_file, "%s\n", line);
				continue;
			}

			// if rename
			if (!strcmp(name, self->value))
			{
				fprintf(resolv_tmp_file, "nameserver %s\n", value);
				should_create = 0;
				continue;
			}
		}

		fprintf(resolv_tmp_file, "%s\n", line);
	}

	if (should_create)
	{
		fprintf(resolv_tmp_file, "nameserver %s\n", value);
	}

	free(line);

	fclose(resolv_file);
	fclose(resolv_tmp_file);

	rename("/tmp/resolv.conf.freenetconfd", "/etc/resolv.conf");

	return 0;
}

int del_system_dns_resolver_server(datastore_t *self, void *data)
{
	FILE *resolv_file = fopen("/etc/resolv.conf", "r");

	if (!resolv_file)
	{
		DEBUG("Cannot opet /etc/resolv.conf, check the rights.\n");
		return -1;
	}

	FILE *resolv_tmp_file = fopen("/tmp/resolv.conf.freenetconfd", "w");

	if (!resolv_tmp_file)
	{
		fclose(resolv_file);
		DEBUG("Cannot opet /tmp/resolv.conf.freenetconfd, check the rights.\n");
		return -1;
	}

	// read line by line
	char *line = malloc(1024);
	ssize_t read;
	size_t len = 1024;
	while ((read = getline(&line, &len, resolv_file)) != -1)
	{
		if (line[read-1] == '\n')
			line[read-1] = '\0';

		if (!strncmp(line, "nameserver", 10))
		{
			char *name = get_word_from_string(line+10, NULL);

			if (!name)
			{
				fprintf(resolv_tmp_file, "%s\n", line);
				continue;
			}

			// skip the one we're deleting
			if (!strcmp(name, self->child->value))
				continue;
		}

		fprintf(resolv_tmp_file, "%s\n", line);
	}

	free(line);

	fclose(resolv_file);
	fclose(resolv_tmp_file);

	rename("/tmp/resolv.conf.freenetconfd", "/etc/resolv.conf");

	return 0;
}

datastore_t *create_system_dns_resolver_server_child(datastore_t *self, char *name,
															char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(name, "name"))
	{
		child->is_key = 1;
		child->set = set_system_dns_resolver_server_name;
	}

	return child;
}

int del_system_dns_resolver_search(datastore_t *self, void *data)
{
	// read line by line, write to other file if it's not deleted, switch files
	FILE *resolv_file = fopen("/etc/resolv.conf", "r");

	if (!resolv_file)
	{
		DEBUG("Cannot opet /etc/resolv.conf, check the rights.\n");
		return -1;
	}

	FILE *resolv_tmp_file = fopen("/tmp/resolv.conf.freenetconfd", "w");

	if (!resolv_tmp_file)
	{
		fclose(resolv_file);
		DEBUG("Cannot opet /tmp/resolv.conf.freenetconfd, check the rights.\n");
		return -1;
	}

	// read line by line
	char *line = malloc(1024);
	ssize_t read;
	size_t len = 1024;
	while ((read = getline(&line, &len, resolv_file)) != -1)
	{
		if (line[read-1] == '\n')
			line[read-1] = '\0';

		if (!strncmp(line, "search", 6))
		{
			fprintf(resolv_tmp_file, "search ");

			// read list and add one by one except the deleted one
			char *element;
			char *str = line + 7; // skip "search"
			for ( ;(element = get_word_from_string(str, &str)); free(element))
			{
				if (!strcmp(element, self->value))
					continue;

				fprintf(resolv_tmp_file, "%s", element);
			}

			fprintf(resolv_tmp_file, "\n"); // end the line
		}
		else
		{
			fprintf(resolv_tmp_file, "%s\n", line);
		}
	}

	free(line);

	fclose(resolv_file);
	fclose(resolv_tmp_file);

	rename("/tmp/resolv.conf.freenetconfd", "/etc/resolv.conf");

	return 0;
}

int set_system_dns_resolver_search(datastore_t *self, char *value)
{
	FILE *resolv_file = fopen("/etc/resolv.conf", "r");

	if (!resolv_file)
	{
		DEBUG("Cannot opet /etc/resolv.conf, check the rights.\n");
		return -1;
	}

	FILE *resolv_tmp_file = fopen("/tmp/resolv.conf.freenetconfd", "w");

	if (!resolv_tmp_file)
	{
		fclose(resolv_file);
		DEBUG("Cannot opet /tmp/resolv.conf.freenetconfd, check the rights.\n");
		return -1;
	}

	// read line by line
	char *line = malloc(1024);
	ssize_t read;
	size_t len = 1024;
	while ((read = getline(&line, &len, resolv_file)) != -1)
	{
		if (line[read-1] == '\n')
			line[read-1] = '\0';

		if (!strncmp(line, "search", 6))
		{
			fprintf(resolv_tmp_file, "%s %s\n", line, value);
		}
		else
		{
			fprintf(resolv_tmp_file, "%s\n", line);
		}
	}

	free(line);

	fclose(resolv_file);
	fclose(resolv_tmp_file);

	rename("/tmp/resolv.conf.freenetconfd", "/etc/resolv.conf");

	return 0;
}

datastore_t *create_system_dns_resolver_child(datastore_t *self, char *name,
													 char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(name, "search"))
	{
		child->is_list = 1;
		child->del = del_system_dns_resolver_search;
		child->set = set_system_dns_resolver_search;
	}
	else if (!strcmp(name, "server"))
	{
		child->is_list = 1;
		child->create_child = create_system_dns_resolver_server_child;
		child->del = del_system_dns_resolver_server;
	}

	return child;
}

void update_system_state_platform(datastore_t *self)
{
	struct utsname name;
	uname(&name);

	datastore_t *os_name = ds_find_child(self, "os-name", NULL);
	if (os_name)
		ds_set_value(os_name, strdup(name.sysname));

	datastore_t *os_release = ds_find_child(self, "os-release", NULL);
	if (os_release)
		ds_set_value(os_release, strdup(name.release));

	datastore_t *os_version = ds_find_child(self, "os-version", NULL);
	if (os_version)
		ds_set_value(os_version, strdup(name.version));

	datastore_t *machine = ds_find_child(self, "machine", NULL);
	if (machine)
		ds_set_value(machine, strdup(name.machine));
}

int owrt_char_is_true(const char *value)
{
	return !strcmp(value, "true") || !strcmp(value, "on") || !strcmp(value, "yes") || !strcmp(value, "1");
}

char *get_uci(const char *path)
{
	struct uci_ptr ptr;
	struct uci_context *context = uci_alloc_context();

	if (!context)
		return NULL;

	char *buf = NULL;
	printf("%s\n", path);

	char *path_dup = strdup(path);
	if (uci_lookup_ptr(context, &ptr, path_dup, true) != UCI_OK)
	{
		free(path_dup);
		uci_free_context(context);
		DEBUG("uci error\n");
		return NULL;
	}

	if (ptr.o)
		buf = strdup(ptr.o->v.string);

	uci_free_context(context);
	free(path_dup);

	return buf;
}

int set_uci(const char *cmd, const char *value)
{
	struct uci_ptr ptr;
	struct uci_context *context = uci_alloc_context();
	if (!context)
		return -1;

	char *full_cmd;

	full_cmd = malloc(strlen(value) + strlen(cmd) + 1);

	strcpy(full_cmd, cmd);
	strcat(full_cmd, value);

	memset(&ptr, 0, sizeof(ptr));

	if (uci_lookup_ptr(context, &ptr, full_cmd, true) != UCI_OK)
	{
		DEBUG("set_uci(\"%s\") failed\n", full_cmd);
		return -1;
	}

	uci_set(context, &ptr);

	uci_save(context, ptr.p);
	uci_commit(context, &ptr.p, true);

	uci_free_context(context);
	free(full_cmd);

	return 0;
}

int delete_uci(const char *to_delete)
{
	struct uci_ptr ptr;
	struct uci_context *context = uci_alloc_context();
	if (!context)
		return -1;

	memset(&ptr, 0, sizeof(ptr));

	char *cmd = strdup(to_delete);
	if (uci_lookup_ptr(context, &ptr, cmd, true) != UCI_OK)
	{
		DEBUG("delete_uci(\"%s\") failed\n", cmd);
		return -1;
	}

	uci_delete(context, &ptr);

	uci_save(context, ptr.p);
	uci_commit(context, &ptr.p, true);

	uci_free_context(context);
	free(cmd);

	return 0;
}

int add_list_uci(const char *list, const char *value)
{
	DEBUG("adding %s\t%s\n", list, value);
	struct uci_ptr ptr;
	struct uci_context *context = uci_alloc_context();
	if (!context)
		return -1;

	memset(&ptr, 0, sizeof(ptr));

	char *cmd = strdup(list);
	if (uci_lookup_ptr(context, &ptr, cmd, true) != UCI_OK)
	{
		DEBUG("delete_uci(\"%s\") failed\n", cmd);
		return -1;
	}

	ptr.value = value;
	uci_add_list(context, &ptr);

	uci_save(context, ptr.p);
// following line is commented out because it causes memory leak even on minimal example
// 	uci_commit(context, &ptr.p, true);

	uci_free_context(context);
	free(cmd);

	return 0;
}

// RPC
int rpc_set_current_datetime(struct rpc_data *data)
{
	datastore_t *ntp_enabled = ds_find_child(ds_find_child(ds_find_child(&root,
							   "system", NULL), "ntp", NULL), "enabled", NULL);

	char *ntp_enabled_value;
	if (ntp_enabled->get)
		ntp_enabled_value = ntp_enabled->get(ntp_enabled);
	else
		ntp_enabled_value = ntp_enabled->value;

	if (owrt_char_is_true(ntp_enabled_value))
	{
		// fail with error-tag 'operation-failed' and error-app-tag value of 'ntp-active'
		data->error = netconf_rpc_error("NTP active!",
									   RPC_ERROR_TAG_OPERATION_FAILED, RPC_ERROR_TYPE_APPLICATION, RPC_ERROR_SEVERITY_ERROR, "ntp-active");
		return RPC_ERROR;
	}

	// get always allocates, so we need to free value
	if (ntp_enabled->get)
		free(ntp_enabled_value);

	char cmd[BUFSIZ];
	char *date = roxml_get_content(roxml_get_chld(data->in, "current-datetime", 0), NULL, 0, NULL);

	snprintf(cmd, BUFSIZ, "date -s %s", date);

	if (system(cmd) == -1)
		return RPC_ERROR;

	DEBUG("rpc\n");

	roxml_add_node(data->out, 0, ROXML_ELM_NODE, "data", NULL);

	return RPC_DATA;
}

int rpc_system_restart(struct rpc_data *data)
{
	pid_t reboot_pid;

	if (0 == (reboot_pid = fork()))
	{
		execlp("/sbin/reboot", "/sbin/reboot", NULL);
		exit(1);
	}

	if (reboot_pid < 0)
		return RPC_ERROR;

	int reboot_status;
	waitpid(reboot_pid, &reboot_status, 0);

	if ( !WIFEXITED(reboot_status) || WEXITSTATUS(reboot_status) != 0)
		return RPC_ERROR;

	return RPC_DATA;
}

int rpc_system_shutdown(struct rpc_data *data)
{
	pid_t shutdown_pid;

	if ( 0 == (shutdown_pid = fork()) )
	{
		sync();
		reboot(LINUX_REBOOT_CMD_HALT);
		exit(1); /* never reached if reboot cmd succeeds */
	}

	if (shutdown_pid < 0)
		return RPC_ERROR;

	int shutdown_status;
	waitpid(shutdown_pid, &shutdown_status, 0);

	if ( !WIFEXITED(shutdown_status) || WEXITSTATUS(shutdown_status) != 0)
		return RPC_ERROR;

	return RPC_DATA;
}

struct rpc_method rpc[] =
{
	{"set-current-datetime", rpc_set_current_datetime},
	{"system-restart", rpc_system_restart},
	{"system-shutdown", rpc_system_shutdown},
	{"firmware-download", rpc_firmware_download},
	{"firmware-commit", rpc_firmware_commit},
	{"set-bootorder", rpc_set_bootorder},
};

__unused struct module *init()
{
	create_store();

	curl_init();
	m.rpcs = rpc;
	m.rpc_count = (sizeof(rpc) / sizeof(*(rpc))); // to be filled directly by code generator
	m.ns = ns;
	m.datastore = &root;

	return &m;
}

__unused void destroy()
{
	curl_cleanup();
	ds_free(root.child, 1);
	root.child = NULL;
}


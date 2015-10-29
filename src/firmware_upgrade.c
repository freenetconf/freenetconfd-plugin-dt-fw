/*
 * Copyright (C) 2015 Deutsche Telekom AG.
 *
 * Author: Mislav Novakovic <mislav.novakovic@sartura.hr>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <freenetconfd/freenetconfd.h>
#include <freenetconfd/datastore.h>
#include <freenetconfd/plugin.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include <openssl/ssl.h>
#include <curl/curl.h>

#include "firmware_upgrade.h"

static int set_node(datastore_t *self, char *value);
static char *get_node(datastore_t *self);
static int del_node(struct datastore *self, void *data);
static datastore_t *create_slot_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position);
static datastore_t *create_job_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position);
static int set_config_node(datastore_t *self, char *value);
static char *get_config_node(datastore_t *self);
static int del_config_node(struct datastore *self, void *data);
static char *uci_get(const char *str);
static int uci_set_value(const char *str);
static int uci_del(const char *str);

datastore_t *system_state;
char *ns;
int32_t job_id = 0;

struct server_data {
	char *address;
	char *password;
	char *certificate;
	char *ssh_key;
};

struct curl_data {
	struct server_data *server;
	const char *filename;
	int filesize;
	int downloaded;
	datastore_t *progress;
	FILE *stream;
};

void curl_cleanup()
{
	curl_global_cleanup();
}

void curl_init()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
}

static void init_config_file(char *filename)
{
	struct stat buffer;

	if (0 != stat (filename, &buffer)) {
		FILE *fh = fopen(filename, "w");
		fclose(fh);
	}
}

static size_t throw_away(void *ptr, size_t size, size_t nmemb, void *data)
{
	(void)ptr;
	(void)data;
	return (size_t)(size * nmemb);
}

static size_t firmware_fwrite(void *buffer, size_t size, size_t nmemb, void *stream)
{
	struct curl_data *data = (struct curl_data *)stream;
	if(data && !data->stream) {
		data->stream = fopen(data->filename, "wb");
		if(!data->stream)
			return -1;
	}

	data->downloaded = data->downloaded + (size * nmemb);
	int percent = (int)(100 * ((double) data->downloaded / (double) data->filesize));
	if (0 == percent % 10) {
		char str[20];
		sprintf(str, "%d", percent);
		ds_set_value(data->progress, str);
	}

	return fwrite(buffer, size, nmemb, data->stream);
}

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
{
	X509_STORE *store;
	X509 *cert=NULL;
	BIO *bio;
	char *mypem = NULL;

	struct curl_data *data = (struct curl_data *)parm;
	mypem = (char *) data->server->certificate;

	bio = BIO_new_mem_buf(mypem, -1);

	PEM_read_bio_X509(bio, &cert, 0, NULL);
	if (NULL == cert)
		DEBUG("PEM_read_bio_X509 failed...\n");

	store=SSL_CTX_get_cert_store((SSL_CTX *) sslctx);

	if (0 == X509_STORE_add_cert(store, cert))
		DEBUG("error adding certificate\n");

	X509_free(cert);
	BIO_free(bio);

	return CURLE_OK ;
}

static int curl_get(struct curl_data data, double *filesize)
{
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();
	if(curl) {
		if (data.server->password) {
			char *tmp =strchr(data.server->address, '/');
			char *start = (tmp + 1);
			if (!tmp)
				return 0;
			char *stop = strchr(data.server->address, '@');
			if (!stop)
				return 0;
			int len = stop - start;
			char username[len +1];
			snprintf(username, len, "%s", (start + 1));
			char auth[len + strlen(data.server->password) + 1];
			snprintf(auth, (len + strlen(data.server->password) + 2), "%s:%s", username, data.server->password);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_URL, data.server->address);
			curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
			if (filesize) {
				curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
				curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
				curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
				curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
			} else {
				curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_fwrite);
				curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
			}
			curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
			res = curl_easy_perform(curl);

			if(CURLE_OK != res)
				DEBUG("Curl error\n");
			else if (filesize)
				res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, filesize);

			curl_easy_cleanup(curl);
		} else if (data.server->certificate) {
			curl_easy_setopt(curl, CURLOPT_URL, data.server->address);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
			curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
			curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
			curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,"PEM");
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
			curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &data);
			// 2L -> it has to have the same name in the certificate as is in the URL you operate against.
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);

			if (filesize) {
				curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
				curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
				curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
			} else {
				curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_fwrite);
				curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
				//curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, firmware_fwrite);
				//curl_easy_setopt(curl, CURLOPT_HEADERDATA, stderr);
			}
			res = curl_easy_perform(curl);

			if(CURLE_OK != res)
				DEBUG("Curl error\n");
			else if (filesize)
				res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, filesize);

			curl_easy_cleanup(curl);
		} else if (data.server->ssh_key) {
			//Prior to 7.39.0, curl was not computing the public key and it had to be provided manually
			curl_easy_setopt(curl, CURLOPT_URL, data.server->address);
			curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 0);
			curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PUBLICKEY);
			curl_easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, "/home/mislav/.ssh/cacert.pem");
			curl_easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, "");
			curl_easy_setopt(curl, CURLOPT_DIRLISTONLY, 1);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_fwrite);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
			res = curl_easy_perform(curl);

			curl_easy_cleanup(curl);

			if(CURLE_OK != res)
				DEBUG("Curl error\n");
		}
	}

	if(data.stream)
		fclose(data.stream); /* close the local file */

	return res;
}

static int firmware_commit(char *job_id)
{
	datastore_t *node, *tmp;

	if (!job_id || 0 == strlen(job_id))
		return 1;

	node = ds_find_child(system_state, "firmware-job", NULL);
	if (!node)
		return 1;

	do {
		if (!strcmp(node->name, "firmware-job")) {
			tmp = ds_find_child(node, "job-id", NULL);
			if (tmp && !strcmp(tmp->value, job_id)) {
				break;
			}
		}
		node = node->next;
	} while (node);

	if (!node)
		return 1;

	node = ds_find_child(node, "install-target", NULL);
	if (!node)
		return 1;

	pid_t pid=fork();
	if (pid==0) {
		DEBUG("sysupgrade %s\n", node->value);
		execl("/sbin/sysupgrade", "sysupgrade", node->value, (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return 0;
}

static int get_job_id(struct server_data *server, char *name, int timeframe, int retry_count, int retry_interval, int retry_interval_increment)
{
	datastore_t *slot_name = NULL, *status_con = NULL, *status = NULL, *progress = NULL;
	struct curl_data data = {server, NULL, NULL, 0, NULL, NULL};
	datastore_t *tmp = system_state->child;
	datastore_t *firmware_slot = NULL;
	int total_retry_interval = retry_interval;
	time_t start, end, end_timeframe;
	double elapsed;
	double filesize = 0.0;
	int ret = 0;

	ret = curl_get(data, &filesize);
	if (ret)
		return 0;

	do {
		if (!strcmp(tmp->name, "firmware-slot")) {
			slot_name = ds_find_child(tmp, "name", NULL);
			if (slot_name && !strcmp(slot_name->value, name)) {
				firmware_slot = tmp;
				break;
			}
		}
		tmp = tmp->next;
	} while (tmp);

	if (!firmware_slot)
		return 0;

	datastore_t *slot_path = ds_find_child(tmp, "path", NULL);
	if (!slot_path)
		return 0;
	datastore_t *node = system_state->create_child(system_state, "firmware-job", NULL, ns, NULL, 0);
	char str_job_id[20];
	sprintf(str_job_id, "%d", ++job_id);
	node->create_child(node, "job-id", str_job_id, NULL, NULL, 0);
	node->create_child(node, "install-target", slot_name->value, NULL, NULL, 0);
	status_con = node->create_child(node, "status", NULL, NULL, NULL, 0);

	status = status_con->create_child(status_con, "status", "planned", NULL, NULL, 0);
	start = time(NULL);
	ds_set_value(status, "in-progress");
	progress = node->create_child(status_con, "progress", "0", NULL, NULL, 0);

	while (true) {
		retry_count--;
		end = time(NULL);
		elapsed = ((double) (end-start)) / (double) CLOCKS_PER_SEC *1000;

		char *tmp = NULL;
		if (slot_path->value && *slot_path->value && slot_path->value[strlen(slot_path->value) - 1] == '/')
			tmp = "/firmware_";
		else
			tmp = "/firmware_";
		char fw_file[strlen(slot_path->value) + strlen(tmp) +strlen(str_job_id) + 1];
		sprintf(fw_file, "%s%s%s", slot_path->value, tmp, str_job_id);
		data.filename = fw_file;
		data.filesize = (int) filesize;
		data.progress = progress;
		ret = curl_get(data, NULL);

		if (0 == ret)
			break;

		if (!retry_count)
			break;

		if (timeframe && (elapsed > timeframe))
			break;

		total_retry_interval *= (1 + (int) (retry_interval_increment / 100));
		usleep(total_retry_interval * 1000000);
	}

	ds_free(progress, 0);
	if (ret) {
		ds_set_value(status, "dl-failed");
		return 0;
	} else {
		ds_set_value(status, "done");
		return job_id;
	}
}

int init_firmware_upgrade(datastore_t *in_node, char *in_ns)
{
	datastore_t *node = NULL;
	struct uci_context *uci;
	struct uci_package *firm_slot = NULL;
	struct uci_element *e, *el;
	struct uci_section *s;
	struct uci_option *o;

	ns = in_ns;
	system_state = in_node;

	init_config_file("/etc/config/opencpe_firmware_mgmt");

	uci = uci_alloc_context();
	if (!uci)
		return -1;

	if (uci_load(uci, "/etc/config/opencpe_firmware_mgmt", &firm_slot) != UCI_OK) {
		uci_free_context(uci);
		return -1;
	}
	uci_foreach_element(&firm_slot->sections, e) {
		s = uci_to_section(e);

		if (strcmp(s->type, "firmware-slot"))
			continue;

		node = system_state->create_child(system_state, s->type, NULL, ns, NULL, 0);

		uci_foreach_element(&s->options, el) {
			o = uci_to_option(el);
			node->create_child(node, o->e.name, o->v.string, NULL, NULL, 0);
		}
	}

	uci_unload(uci, firm_slot);
	uci_free_context(uci);

	return 0;
}

datastore_t *create_section_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;

	if (!strcmp(name, "firmware-slot")) {
		child = ds_add_child_create(self, name, value, NULL, NULL, 0);
		child->del = del_config_node;
		child->create_child = create_slot_node;
		child->is_list = 1;
	} else if (!strcmp(name, "firmware-job")) {
		child = ds_add_child_create(self, name, value, NULL, NULL, 0);
		child->create_child = create_job_node;
		child->is_list = 1;
	} else {
		child = ds_add_child_create(self, name, value, ns, target_name, target_position);
	}

	return child;
}

static datastore_t *create_job_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;

	if (!strcmp(self->name, "status") && strcmp(name, "status") && strcmp(name, "status-msg") && strcmp(name, "progress"))
		return NULL;

	if (!strcmp(self->name, "firmware-job") && strcmp(name, "job-id") && strcmp(name, "install-target") && strcmp(name, "status"))
		return NULL;

	if (!strcmp(name, "status") && !strcmp(self->name, "status"))
		if (strcmp(value, "planned") && strcmp(value, "in-progress") && strcmp(value, "dl-failed") && strcmp(value, "verification-failed") && strcmp(value, "done"))
			return NULL;

	child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(self->name, "firmware-job") && !strcmp(name, "status"))
		child->create_child = create_job_node;
	return child;
}

static datastore_t *create_slot_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "name"))
		child->is_key = 1;

	if (!strcmp(name, "name") || !strcmp(name, "version") || !strcmp(name, "active") || !strcmp(name, "path")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	}

	return child;
}


static int set_node(datastore_t *self, char *value)
{
	datastore_t *node = ds_find_sibling(self->parent->child, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *config = "opencpe_firmware_mgmt";
	char *element = self->name;

	int len = strlen(config) + strlen(option) + strlen(element) + strlen(value) + 5;
	char uci[len];

	snprintf(uci, len, "%s.%s.%s=%s", config, option, element, value);

	if (!strcmp(self->name, "name")) {
		set_config_node(self->parent, value);
		return uci_set_value(&uci[0]);
	} else {
		return uci_set_value(&uci[0]);
	}
}

static char *get_node(datastore_t *self)
{
	char *config = "opencpe_firmware_mgmt";
	datastore_t *node = ds_find_sibling(self->parent->child, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	char *result = NULL;

	int len = strlen(config) + strlen(option) + strlen(element) + 3;
	char uci[len];

	snprintf(uci, len, "%s.%s.%s", config, option, element);
	result = uci_get(&uci[0]);
	if (result) {
		char *buffer = strdup(result);
		free(result);
		return buffer;
	} else {
		result = "";
		char *buffer = strdup(result);
		free(result);
		return buffer;
	}
}

static int del_node(struct datastore *self, void *data)
{
	char *config = "opencpe_firmware_mgmt";
	datastore_t *node = ds_find_sibling(self->parent->child, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;

	int len = strlen(config) + strlen(option) + strlen(element) + 3;
	char uci[len];

	snprintf(uci, len, "%s.%s.%s", config, option, element);

	if (!strcmp(self->name, "name"))
		return del_config_node(self, data);
	else
		return uci_del(&uci[0]);
}

static int set_config_node(datastore_t *self, char *value)
{
	struct uci_context *ctx;
	struct uci_package *pack = NULL;
	struct uci_ptr ptr = { 0 };
	struct uci_context *context = uci_alloc_context();
	char *config_file = "/etc/config/opencpe_firmware_mgmt";
	int ret;

	if (!context)
		return NULL;

	int len = strlen(config_file) + strlen(self->name) + strlen(value) + 3;
	char uci[len];
	snprintf(uci, len, "%s.%s=%s", config_file, value, self->name);

	uci_free_context(context);
	return uci_set_value(&uci[0]);
}

static char *get_config_node(datastore_t *self)
{
	char *config = "opencpe_firmware_mgmt";
	datastore_t *node = ds_find_sibling(self->child, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;

	char *buffer = strdup(option);

	return buffer;
}

static int del_config_node(struct datastore *self, void *data)
{
	char *config = "opencpe_firmware_mgmt";
	datastore_t *node = ds_find_sibling(self->child, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;

	int len = strlen(config) + strlen(option) + 3;
	char uci[len];

	snprintf(uci, len, "%s.%s", config, option);

	return uci_del(&uci[0]);
}

static char *uci_get(const char *str)
{
	char *value = NULL;
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	struct uci_context *context = uci_alloc_context();
	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	if (!context)
		return NULL;

	if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
		goto out;
	}

	if (UCI_TYPE_SECTION == result.target && result.s) {
		value = strdup(result.o->v.string);
		if (!value)
			printf("Error memory.\n");
		uci_free_context(context);
		return value;
	}

	if (!result.o)
		goto out;

	if (result.o->v.string) {
		value = strdup(result.o->v.string);
		if (!value) {
			printf("Error memory.\n");
			goto out;
		}
	}

out:
	uci_free_context(context);
	if (!value)
		value = strdup("");
	return value;
}

static int uci_set_value(const char *str)
{
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	struct uci_context *context = uci_alloc_context();
	int ret = 0;

	if (!context)
		return NULL;

	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	ret = uci_lookup_ptr(context, &result, (char *) str_copy, true);
	if (UCI_OK != ret) {
		goto out;
	}

	ret = uci_set(context, &result);
	if (UCI_OK != ret) {
		printf("UCI set error.\n");
		goto out;
	}

	ret = uci_save(context, result.p);
	if (UCI_OK != ret) {
		printf("UCI save error.\n");
		goto out;
	}

	ret = uci_commit(context, &result.p, 1);
	if (UCI_OK != ret) {
		printf("UCI commit error.\n");
		goto out;
	}

out:
	ret = 0;
	uci_free_context(context);
	return ret;
}

static int uci_del(const char *str)
{
	int ret = 0;
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	struct uci_context *context = uci_alloc_context();
	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	if (!context)
		goto out;

	if (!context)
		goto out;

	ret = uci_lookup_ptr(context, &result, (char *) str_copy, true);
	if (UCI_OK != ret) {
		goto out;
	}

	ret = uci_delete(context, &result);
	if (UCI_OK != ret) {
		printf("UCI delete error.\n");
		goto out;
	}

	ret = uci_save(context, result.p);
	if (UCI_OK != ret) {
		printf("UCI save error.\n");
		goto out;
	}

	ret = uci_commit(context, &result.p, false);
	if (UCI_OK != ret) {
		printf("UCI commit error.\n");
		goto out;
	}

out:
	ret = 0;
	uci_free_context(context);
	return ret;
}

int rpc_firmware_download (struct rpc_data *data)
{
	char *operation_name = NULL;
	int rc = 0, nb = 0, i = 0;
	node_t **nodes, *n;
	char *password = NULL, *certificate = NULL, *ssh_key = NULL;
	char *address = NULL;
	char *install_target = NULL;
	int32_t timeframe = 0;
	uint8_t retry_count = 3;
	uint32_t retry_interval = 300;
	uint8_t retry_interval_increment = 20;
	int32_t job_id = 0;

	node_t *operation = data->in;
	operation_name = roxml_get_name(operation, NULL, 0);

	if ((nodes = roxml_xpath(data->in, "//firmware-download", &nb)))
	{
		nb = roxml_get_chld_nb(nodes[0]);

		/* empty filter */
		if (!nb)
			return RPC_ERROR;

		while (--nb >= 0)
		{
			n = roxml_get_chld(nodes[0], NULL, nb);
			char *module = roxml_get_name(n, NULL, 0);
			char *ns = roxml_get_content(roxml_get_ns(n), NULL, 0, NULL);
			char *cur_value = roxml_get_content(n, NULL, 0, NULL);

			if (strcmp(module,"address") == 0)
				address = cur_value;
			else if (strcmp(module,"password") == 0)
				password = cur_value;
			else if (strcmp(module,"certificate") == 0)
				certificate = cur_value;
			else if (strcmp(module,"ssh-key") == 0)
				ssh_key = cur_value;
			else if (strcmp(module,"address") == 0)
				address = cur_value;
			else if (strcmp(module,"install-target") == 0)
				install_target = cur_value;
			else if (strcmp(module,"timeframe") == 0)
				timeframe = atoi(cur_value);
			else if (strcmp(module,"retry-count") == 0)
				retry_count = atoi(cur_value);
			else if (strcmp(module,"retry-interval") == 0)
				retry_interval = atoi(cur_value);
			else if (strcmp(module,"retry-interval-increment") == 0)
				retry_interval_increment = atoi(cur_value);
			else
				goto error;
		}
		if (password)
			i++;
		if (certificate)
			i++;
		if (ssh_key)
			i++;
		if (i != 1)
			goto error;

		if (!address || !install_target)
			goto error;
	}

	struct server_data server = {address, password, certificate, ssh_key};
	job_id = get_job_id(&server, install_target, timeframe, retry_count, retry_interval, retry_interval_increment);
	if (!job_id)
		goto error;

	char str[20];
	sprintf(str, "%d", job_id);
	node_t *n_data = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "data", NULL);
	roxml_add_node(n_data, 0, ROXML_ELM_NODE, "job-id", str);
	nodes = roxml_xpath(data->out, "//job-id", &nb);

	char *value = roxml_get_content(nodes[0], NULL, 0, NULL);

	roxml_add_node(nodes[0], 1, ROXML_ATTR_NODE, "xmlns", ns);

	return RPC_DATA;
error:
	return RPC_ERROR;
}

int rpc_firmware_commit (struct rpc_data *data)
{
	char *operation_name = NULL;
	int nb = 0;
	node_t **nodes, *n;
	char *job_id = NULL;

	node_t *operation = data->in;
	operation_name = roxml_get_name(operation, NULL, 0);

	if ((nodes = roxml_xpath(data->in, "//firmware-commit", &nb)))
	{
		nb = roxml_get_chld_nb(nodes[0]);

		/* empty filter */
		if (!nb)
			return RPC_DATA;

		while (--nb >= 0)
		{
			n = roxml_get_chld(nodes[0], NULL, nb);
			char *module = roxml_get_name(n, NULL, 0);
			char *ns = roxml_get_content(roxml_get_ns(n), NULL, 0, NULL);
			char *cur_value = roxml_get_content(n, NULL, 0, NULL);

			if (strcmp(module,"job-id") == 0) {
				job_id = cur_value;
			}
		}
	}

	if (!job_id)
		goto error;

	if (firmware_commit(job_id))
		goto error;

	return RPC_DATA;
error:
	return RPC_ERROR;
}

int rpc_set_bootorder(struct rpc_data *data)
{
	char *operation_name = NULL;
	int rc = 0, nb = 0;
	node_t **nodes, *n;
	char *name = NULL;

	node_t *operation = data->in;
	operation_name = roxml_get_name(operation, NULL, 0);

	if ((nodes = roxml_xpath(data->in, "//set-bootorder", &nb)))
	{
		nb = roxml_get_chld_nb(nodes[0]);

		/* empty filter */
		if (!nb)
			return RPC_DATA;

		while (--nb >= 0)
		{
			n = roxml_get_chld(nodes[0], NULL, nb);
			char *module = roxml_get_name(n, NULL, 0);
			char *ns = roxml_get_content(roxml_get_ns(n), NULL, 0, NULL);
			char *cur_value = roxml_get_content(n, NULL, 0, NULL);

			if (strcmp(module,"name") == 0) {
				name = cur_value;;
			}
		}
		//TODO implement this!
	}
	return RPC_DATA;
error:
	return RPC_ERROR;
}

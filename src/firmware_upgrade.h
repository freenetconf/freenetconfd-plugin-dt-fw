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

#ifndef __FIRMWARE_UPGRADE_H__
#define __FIRMWARE_UPGRADE_H__

#include "freenetconfd/datastore.h"

datastore_t *create_section_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position);
int init_firmware_upgrade(datastore_t *system_state, char *in_ns);
int rpc_firmware_commit (struct rpc_data *data);
int rpc_firmware_download (struct rpc_data *data);
int rpc_set_bootorder(struct rpc_data *data);
void curl_cleanup();
void curl_init();

#endif /* __FIRMWARE_UPGRADE_H__ */

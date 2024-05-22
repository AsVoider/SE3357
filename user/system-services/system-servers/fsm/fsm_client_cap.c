/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <malloc.h>
#include <string.h>
#include "fsm_client_cap.h"
#include <errno.h>

struct list_head fsm_client_cap_table;

/* Return mount_id */
int fsm_set_client_cap(badge_t client_badge, cap_t cap)
{
        /* Lab 5 TODO Begin */
        struct fsm_client_cap_node *iter;
        bool findCap = false;
        int ret = 0;
        pthread_mutex_lock(&fsm_client_cap_table_lock);
        for_each_in_list(iter, struct fsm_client_cap_node, node, &fsm_client_cap_table) {
                if (iter->client_badge == client_badge) {
                        findCap = true;
                        ret = iter->cap_num;
                        iter->cap_table[iter->cap_num] = cap;
                        iter->cap_num++;
                        break;
                }
        }
        if (!findCap) {
                struct fsm_client_cap_node *fc;
                fc = (struct fsm_client_cap_node *)malloc(sizeof(*fc));
                fc->cap_num = 1;
                fc->cap_table[0] = cap;
                fc->client_badge = client_badge;
                list_add(&fc->node, &fsm_client_cap_table);
                ret = 0;
        }
        pthread_mutex_unlock(&fsm_client_cap_table_lock);
        /* Lab 5 TODO End */
        return ret;
}

/* Return mount_id if record exists, otherwise -1 */
int fsm_get_client_cap(badge_t client_badge, cap_t cap)
{
        /* Lab 5 TODO Begin */
        int ret = -1;
        pthread_mutex_lock(&fsm_client_cap_table_lock);
        struct fsm_client_cap_node *iter;
        for_each_in_list(iter, struct fsm_client_cap_node, node, &fsm_client_cap_table) {
                if (iter->client_badge == client_badge) {
                        for (int i = 0; i < iter->cap_num; i++) {
                                if (cap == iter->cap_table[i]) {
                                        ret = i;
                                }
                        }
                }
        }
        pthread_mutex_unlock(&fsm_client_cap_table_lock);
        /* Lab 5 TODO End */
        return ret;
}

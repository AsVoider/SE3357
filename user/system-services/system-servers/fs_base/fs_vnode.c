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

#include <chcore-internal/fs_debug.h>
#include <chcore/syscall.h>
#include <stdio.h>
#include <stdlib.h>

#include "fs_vnode.h"
#include "fs_page_cache.h"

static bool less_vnode(const struct rb_node *lhs, const struct rb_node *rhs)
{
        struct fs_vnode *l = rb_entry(lhs, struct fs_vnode, node);
        struct fs_vnode *r = rb_entry(rhs, struct fs_vnode, node);

        return l->vnode_id < r->vnode_id;
}

static int cmp_key_node(const void *key, const struct rb_node *node)
{
        struct fs_vnode *sear = rb_entry(node, struct fs_vnode, node);
        ino_t t_k = *((ino_t *)key);
        // printf("key is %ld, node key is %ld", t_k, sear->vnode_id);
        if (t_k < sear->vnode_id)
                return -1;
        if (t_k > sear->vnode_id)
                return 1;
        return 0;
}

void free_entry(int entry_idx)
{
        free(server_entrys[entry_idx]->path);
        free(server_entrys[entry_idx]);
        server_entrys[entry_idx] = NULL;
}

int alloc_entry(void)
{
        int i;

        for (i = 0; i < MAX_SERVER_ENTRY_NUM; i++) {
                if (server_entrys[i] == NULL) {
                        server_entrys[i] = (struct server_entry *)malloc(
                                sizeof(struct server_entry));
                        if (server_entrys[i] == NULL)
                                return -1;
                        pthread_mutex_init(&server_entrys[i]->lock, NULL);
                        fs_debug_trace_fswrapper("entry_id=%d\n", i);
                        return i;
                }
        }
        return -1;
}

void assign_entry(struct server_entry *entry, u64 flags, off_t offset, int refcnt, void *path,
                  struct fs_vnode *vnode)
{
        fs_debug_trace_fswrapper(
                "flags=0x%lo, offset=0x%ld, path=%s, vnode_id=%ld\n",
                flags,
                offset,
                (char *)path,
                vnode->vnode_id);
        entry->flags = flags;
        entry->offset = offset;
        entry->path = path;
        entry->vnode = vnode;
        entry->refcnt = refcnt;
}

void fs_vnode_init(void)
{
        fs_vnode_list = malloc(sizeof(*fs_vnode_list));
        if (fs_vnode_list == NULL) {
                printf("[fs_base] no enough memory to initialize, exiting...\n");
                exit(-1);
        }
        init_rb_root(fs_vnode_list);
}

/* alloc fs_vnode & initalize its states */
struct fs_vnode *alloc_fs_vnode(ino_t id, enum fs_vnode_type type, off_t size,
                                void *private)
{
        /* Lab 5 TODO Begin */
        // printf("init start\n");
        struct fs_vnode *ret = (struct fs_vnode *)malloc(sizeof(*ret));

        ret->vnode_id = id;
        ret->type = type;
        ret->size = size;
        ret->private = private;

        ret->refcnt = 1;
        ret->pmo_cap = -1;

        // init_rb_root(&ret->node);
        pthread_rwlock_init(&ret->rwlock, NULL);
        if (using_page_cache) {
                struct page_cache_entity_of_inode* cache = new_page_cache_entity_of_inode(id, private);
                if (cache != NULL) {
                        ret->page_cache = cache;
                }
        }
        // printf("init success\n");
        return ret;

        /* Lab 5 TODO End */
}

void push_fs_vnode(struct fs_vnode *n)
{
        // printf("inserting\n");
        rb_insert(fs_vnode_list, &n->node, less_vnode);
}

void pop_free_fs_vnode(struct fs_vnode *n)
{
        rb_erase(fs_vnode_list, &n->node);
        if (n->pmo_cap > 0) {
                usys_revoke_cap(n->pmo_cap, false);
        }
        free(n);
}

struct fs_vnode *get_fs_vnode_by_id(ino_t vnode_id)
{
        /* Lab 5 TODO Begin */
        // printf("here id is %ld\n", vnode_id);
        struct fs_vnode *ret = NULL;
        // printf("root node is %ld\n", (unsigned long)(fs_vnode_list->root_node));
        struct rb_node *rbnode = rb_search(fs_vnode_list, (void *)&vnode_id, cmp_key_node);
        // printf("find vnode is %ld\n", (unsigned long)rbnode);
        if (rbnode == NULL) {
                return NULL;
        }
        ret = rb_entry(rbnode, struct fs_vnode, node);
        return ret;
        /* Lab 5 TODO End */
}

/* increase refcnt for vnode */
int inc_ref_fs_vnode(void *n)
{
        /* Lab 5 TODO Begin */
        if (n == NULL) {
                printf("receive Null Node");
                return 0;
        }
        struct fs_vnode *vnode = (struct fs_vnode *)n;
        pthread_rwlock_wrlock(&vnode->rwlock);
        vnode->refcnt++;
        pthread_rwlock_unlock(&vnode->rwlock);
        /* Lab 5 TODO End */
        return 0;
}

/* decrease vnode ref count and close file when refcnt is 0 */
int dec_ref_fs_vnode(void *node)
{
        /* Lab 5 TODO Begin */

        if (node == NULL) {
                printf("receive Null Node in dec");
                return 0;
        }

        struct fs_vnode *vnode = (struct fs_vnode *)node;
        pthread_rwlock_wrlock(&vnode->rwlock);
        vnode->refcnt--;
        if (vnode->refcnt == 0) {
                // printf("poping\n");
                pop_free_fs_vnode(vnode);
        }
        pthread_rwlock_unlock(&vnode->rwlock);
        // UNUSED(node);
        
        /* Lab 5 TODO End */

        return 0;
}
/*
 * Copyright (c) 2018 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <libconfig.h>
#include <crystal.h>

#include "config.h"

/* Minutes to wait between new crawler round */
#define CRAWLER_INTERVAL            30

/* Maximum number of concurrent crawler instances */
#define MAX_CRAWLERS                5

/* Number of seconds to wait for new nodes before a crawler times out and exits */
#define CRAWLER_TIMEOUT             30

/* Default maximum number of nodes the nodes list can store */
#define INITIAL_NODES_LIST_SIZE     4096

/* Seconds to wait between getnodes requests */
#define REQUEST_INTERVAL            1

/* Max number of nodes to send getnodes requests to per GETNODES_REQUEST_INTERVAL */
#define REQUESTS_PER_INTERVAL       4

/* Number of random node requests to make for each node we send a request to */
#define RANDOM_REQUESTS             32

static void config_destructor(void *p)
{
    crawler_config *config = (crawler_config *)p;

    if (!config)
        return;

    if (config->log_file)
        free(config->log_file);

    if (config->data_dir)
        free(config->data_dir);

    if (config->database)
        free(config->database);

    if (config->bootstraps) {
        int i;

        for (i = 0; i < config->bootstraps_size; i++) {
            bootstrap_node *node = config->bootstraps + i;
            if (node->ipv4)
                free((void *)node->ipv4);

            if (node->ipv6)
                free((void *)node->ipv6);

            if (node->key)
                free((void *)node->key);
        }

        free(config->bootstraps);
    }
}

static void qualified_path(const char *path, const char *ref, char *qualified)
{
    if (*path == '/') {
        strcpy(qualified, path);
    } else if (*path == '~') {
        sprintf(qualified, "%s%s", getenv("HOME"), path+1);
    } else {
        if (ref) {
            const char *p = strrchr(ref, '/');
            if (!p) p = ref;

            if (p - ref > 0) {
                strncpy(qualified, ref, p - ref);
                qualified[p - ref] = 0;
            } else
                *qualified = 0;
        } else {
            getcwd(qualified, PATH_MAX);
        }

        if (*qualified)
            strcat(qualified, "/");

        strcat(qualified, path);
    }
}

crawler_config *load_config(const char *config_file)
{
    crawler_config *config;
    config_t cfg;
    config_setting_t *setting;
    const char *stropt;
    int intopt;
    int entries;
    int i;
    int rc;

    config_init(&cfg);

    rc = config_read_file(&cfg, config_file);
    if (!rc) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return NULL;
    }

    config = (crawler_config *)rc_zalloc(sizeof(crawler_config), config_destructor);
    if (!config) {
        fprintf(stderr, "Load configuration failed, out of memory.\n");
        config_destroy(&cfg);
        return NULL;
    }

    config->interval = CRAWLER_INTERVAL;
    config_lookup_int(&cfg, "interval", (int *)&config->interval);
    config->interval = config->interval * 60;

    config->timeout = CRAWLER_TIMEOUT;
    config_lookup_int(&cfg, "timeout", (int *)&config->timeout);

    config->max_crawlers = MAX_CRAWLERS;
    config_lookup_int(&cfg, "max_crawlers", (int *)&config->max_crawlers);

    config->initial_nodes_list_size = INITIAL_NODES_LIST_SIZE;
    config->request_interval = REQUEST_INTERVAL;
    config->requests_per_interval = REQUESTS_PER_INTERVAL;
    config->random_requests = RANDOM_REQUESTS;

    rc = config_lookup_string(&cfg, "data_dir", &stropt);
    if (!rc || !*stropt) {
        fprintf(stderr, "Missing data dir option.\n");
        config_destroy(&cfg);
        deref(config);
        return NULL;
    } else {
        char path[PATH_MAX];
        qualified_path(stropt, config_file, path);
        config->data_dir = strdup(path);
    }

    config->log_level = VLOG_INFO;
    config_lookup_int(&cfg, "log_level", &config->log_level);

    rc = config_lookup_string(&cfg, "log_file", &stropt);
    if (rc && *stropt) {
        char path[PATH_MAX];
        qualified_path(stropt, config_file, path);
        config->log_file = strdup(path);
    }

    rc = config_lookup_string(&cfg, "ip2location_database", &stropt);
    if (rc && *stropt) {
        char path[PATH_MAX];
        qualified_path(stropt, config_file, path);
        config->database = strdup(path);
    }

    setting = config_lookup(&cfg, "bootstraps");
    if (!setting) {
        fprintf(stderr, "Missing bootstraps section.\n");
        config_destroy(&cfg);
        deref(config);
        return NULL;
    }

    entries = config_setting_length(setting);
    if (entries <= 0) {
        fprintf(stderr, "Empty bootstraps option.\n");
        config_destroy(&cfg);
        deref(config);
        return NULL;
    }

    config->bootstraps_size = entries;
    config->bootstraps = (bootstrap_node *)calloc(entries, sizeof(bootstrap_node));
    if (!config->bootstraps) {
        fprintf(stderr, "Out of memory.\n");
        config_destroy(&cfg);
        deref(config);
        return NULL;
    }

    for (i = 0; i < entries; i++) {
        bootstrap_node *node;

        node = config->bootstraps + i;

        config_setting_t *bs = config_setting_get_elem(setting, i);

        rc = config_setting_lookup_string(bs, "ipv4", &stropt);
        if (rc && *stropt)
            node->ipv4 = (const char *)strdup(stropt);
        else
            node->ipv4 = NULL;

        rc = config_setting_lookup_string(bs, "ipv6", &stropt);
        if (rc && *stropt)
            node->ipv6 = (const char *)strdup(stropt);
        else
            node->ipv6 = NULL;

        node->port = 33445;
        rc = config_setting_lookup_int(bs, "port", &intopt);
        if (rc && intopt)
            node->port = (unsigned short)intopt;

        rc = config_setting_lookup_string(bs, "public_key", &stropt);
        if (rc && *stropt)
            node->key = (const char *)strdup(stropt);
        else
            node->key = NULL;
    }

    config_destroy(&cfg);
    return config;
}


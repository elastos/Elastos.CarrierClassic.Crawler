/*  main.c
 *
 *
 *  Copyright (C) 2016 toxcrawler All Rights Reserved.
 *
 *  This file is part of toxcrawler.
 *
 *  toxcrawler is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  toxcrawler is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with toxcrawler.  If not, see <http://www.gnu.org/licenses/>.
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>

#include <rc_mem.h>
#include <base58.h>
#include <vlog.h>

#include <tox/tox.h>
#include "toxcore/DHT.h"
#include "toxcore/Messenger.h"

#include "config.h"
#include "util.h"

static crawler_config *config;
static int interrupted = 0;
static uint32_t running_crawlers = 0;
static time_t last_crawler_stamp;
static uint32_t last_index = 0;

typedef struct Crawler {
    Tox         *tox;
    DHT         *dht;
    Node_format *nodes_list;
    uint32_t     num_nodes;
    uint32_t     nodes_list_size;
    uint32_t     send_ptr;    /* index of the oldest node that we haven't sent a getnodes request to */
    time_t       last_new_node;   /* Last time we found an unknown node */
    time_t       last_getnodes_request;

    pthread_t    tid;
    time_t       stamp;
    uint32_t     round;
    uint32_t     index;
} Crawler;

/* Use these to lock and unlock the global threads struct */
#define LOCK   pthread_mutex_lock(&threads.lock)
#define UNLOCK pthread_mutex_unlock(&threads.lock)

struct Threads {
    uint16_t  num_active;
    time_t    last_created;
    pthread_mutex_t lock;
} threads;

static inline time_t now(void)
{
    return time(NULL);
}

static inline bool timedout(time_t timestamp, time_t timeout)
{
    return timestamp + timeout <= now();
}

/* Attempts to bootstrap to every listed bootstrap node */
static void crawler_bootstrap(Crawler *cwl)
{
    for (int i = 0; i < config->bootstraps_size; ++i) {
        TOX_ERR_BOOTSTRAP err;
        bootstrap_node *bs_node = config->bootstraps + i;

        uint8_t bin_key[TOX_PUBLIC_KEY_SIZE];
        if (base58_decode(bs_node->key, strlen(bs_node->key),
                bin_key, sizeof(bin_key)) == sizeof(bin_key))
            continue;

        if (bs_node->ipv4) {
            tox_bootstrap(cwl->tox, bs_node->ipv4, bs_node->port, bin_key, &err);
            if (err != TOX_ERR_BOOTSTRAP_OK)
                fprintf(stderr, "Failed to bootstrap DHT via: %s %d (error %d)\n",
                        bs_node->ipv4, bs_node->port, err);
        }

        if (bs_node->ipv6) {
            tox_bootstrap(cwl->tox, bs_node->ipv6, bs_node->port, bin_key, &err);
            if (err != TOX_ERR_BOOTSTRAP_OK)
                fprintf(stderr, "Failed to bootstrap DHT via: %s %d (error %d)\n",
                        bs_node->ipv6, bs_node->port, err);
        }

    }
}

static void crawler_interrupt(int sig)
{
    vlogI("Controller - INT signal catched, interrupte all crawlers.");
    interrupted = 1;
}

/*
 * Return true if public_key is in the crawler's nodes list.
 * TODO: A hashtable would be nice but the str8C holds up for now.
 */
static bool node_crawled(Crawler *cwl, const uint8_t *public_key)
{
    for (uint32_t i = 0; i < cwl->num_nodes; ++i) {
        if (memcmp(public_key, cwl->nodes_list[i].public_key, TOX_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

static void getnodes_response_callback(IP_Port *ip_port, const uint8_t *public_key, void *object)
{
    Crawler *cwl = object;

    if (node_crawled(cwl, public_key)) {
        return;
    }

    if (cwl->num_nodes + 1 >= cwl->nodes_list_size) {
        Node_format *tmp = realloc(cwl->nodes_list, cwl->nodes_list_size * 2 * sizeof(Node_format));

        if (tmp == NULL) {
            return;
        }

        cwl->nodes_list = tmp;
        cwl->nodes_list_size *= 2;
    }

    Node_format node;
    memcpy(&node.ip_port, ip_port, sizeof(IP_Port));
    memcpy(node.public_key, public_key, TOX_PUBLIC_KEY_SIZE);
    memcpy(&cwl->nodes_list[cwl->num_nodes++], &node, sizeof(Node_format));
    cwl->last_new_node = time(NULL);

    {
        char id_str[128];
        char ip_str[IP_NTOA_LEN];
        size_t len = sizeof(id_str);
        base58_encode(public_key, TOX_PUBLIC_KEY_SIZE, id_str, &len);
        ip_ntoa(&ip_port->ip, ip_str, sizeof(ip_str));

        vlogV("Crawler[%u/%u] - %s %s - %u", cwl->round, cwl->index, id_str, ip_str, cwl->num_nodes);
    }
}

/*
 * Sends a getnodes request to up to config->requests_per_interval nodes in the nodes list that have not been queried.
 * Returns the number of requests sent.
 */
static size_t crawler_send_node_requests(Crawler *cwl)
{
    if (!timedout(cwl->last_getnodes_request, config->request_interval)) {
        return 0;
    }

    size_t count = 0;
    uint32_t i;

    for (i = cwl->send_ptr; count < config->requests_per_interval && i < cwl->num_nodes; ++i) {
        DHT_getnodes(cwl->dht, &cwl->nodes_list[i].ip_port,
                     cwl->nodes_list[i].public_key,
                     cwl->nodes_list[i].public_key);

        for (size_t j = 0; j < config->random_requests; ++j) {
            int r = rand() % cwl->num_nodes;

            DHT_getnodes(cwl->dht, &cwl->nodes_list[i].ip_port,
                         cwl->nodes_list[i].public_key,
                         cwl->nodes_list[r].public_key);
        }

        ++count;
    }

    cwl->send_ptr = i;
    cwl->last_getnodes_request = time(NULL);

    return count;
}

/*
 * Returns a pointer to an inactive crawler in the threads array.
 * Returns NULL if there are no crawlers available.
 */
static Crawler *crawler_new(void)
{
    Crawler *cwl;
    TOX_ERR_NEW err;
    struct Tox_Options options;

    cwl = calloc(1, sizeof(Crawler));
    if (cwl == NULL)
        return NULL;

    cwl->nodes_list = malloc(config->initial_nodes_list_size * sizeof(Node_format));
    if (cwl->nodes_list == NULL) {
        free(cwl);
        return NULL;
    }
    cwl->nodes_list_size = config->initial_nodes_list_size;

    tox_options_default(&options);
    cwl->tox = tox_new(&options, &err);
    if (err != TOX_ERR_NEW_OK || cwl->tox == NULL) {
        vlogE("Controller - create new Tox instance for crawler failed: %d\n", err);
        free(cwl->nodes_list);
        free(cwl);
        return NULL;
    }

    cwl->dht = ((Messenger *)cwl->tox)->dht;   // Casting fuckery so we can access the DHT object directly

    DHT_callback_getnodes_response(cwl->dht, getnodes_response_callback, cwl);

    cwl->stamp = now();
    cwl->last_getnodes_request = cwl->stamp;
    cwl->last_new_node = cwl->stamp;
    cwl->round = (last_index / config->max_crawlers) + 1;
    cwl->index = (last_index % config->max_crawlers) + 1;

    crawler_bootstrap(cwl);

    return cwl;
}

static int mkdir_internal(const char *path, mode_t mode)
{
    struct stat st;
    int rc = 0;

    if (stat(path, &st) != 0 && errno == ENOENT) {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            rc = -1;
    } else if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        rc = -1;
    }

    return rc;
}

static int mkdirs(const char *path, mode_t mode)
{
    int rc = 0;
    char *pp;
    char *sp;
    char copypath[PATH_MAX];

    strncpy(copypath, path, sizeof(copypath));
    copypath[sizeof(copypath) - 1] = 0;

    pp = copypath;
    while (rc == 0 && (sp = strchr(pp, '/')) != 0) {
        if (sp != pp) {
            /* Neither root nor double slash in path */
            *sp = '\0';
            rc = mkdir_internal(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }

    if (rc == 0)
        rc = mkdir_internal(path, mode);

    return rc;
}

static int crawler_get_data_filename(Crawler *cwl, char *buf, size_t buf_len)
{
    char tmstr[32];
    char path[PATH_MAX];
    struct stat st;

    strftime(tmstr, sizeof(tmstr), "%Y-%m-%d", localtime(&cwl->stamp));
    snprintf(path, sizeof(path), "%s/%s", config->data_dir, tmstr);

    if (stat(path, &st) == -1 && errno == ENOENT) {
        if (mkdirs(path, 0700) == -1) {
            return -1;
        }
    }

    strftime(tmstr, sizeof(tmstr), "%H%M%S", localtime(&cwl->stamp));
    snprintf(buf, buf_len, "%s/%s.lst", path, tmstr);

    return 0;
}

#define TEMP_FILE_EXT ".tmp"

/* Dumps crawler nodes list to file. */
static int crawler_dump_nodes(Crawler *cwl)
{
    int rc;
    char data_file[PATH_MAX];
    char temp_file[PATH_MAX];
    FILE *fp;
    char id_str[64];
    char ip_str[IP_NTOA_LEN];

    rc = crawler_get_data_filename(cwl, data_file, sizeof(data_file));
    if (rc != 0) {
        vlogE("Crwaler[%u/%u] - get node list filename failed: %d", cwl->round, cwl->index, errno);
        return -1;
    }

    vlogD("Crwaler[%u/%u] - current node list filename: %s", cwl->round, cwl->index, data_file);

    snprintf(temp_file, sizeof(temp_file), "%s%s", data_file, TEMP_FILE_EXT);

    fp = fopen(temp_file, "w");
    if (fp == NULL) {
        vlogE("Crwaler[%u/%u] - open node list filename failed: %d", cwl->round, cwl->index, errno);
        return -1;
    }

    for (uint32_t i = 0; i < cwl->num_nodes; ++i) {
        size_t len = sizeof(id_str);
        base58_encode(cwl->nodes_list[i].public_key, CRYPTO_PUBLIC_KEY_SIZE, id_str, &len);
        ip_ntoa(&cwl->nodes_list[i].ip_port.ip, ip_str, sizeof(ip_str));
        fprintf(fp, "%s %s\n", id_str, ip_str);
    }

    fclose(fp);

    if (rename(temp_file, data_file) != 0) {
        vlogE("Crwaler[%u/%u] - rename temp node list filename failed: %d", cwl->round, cwl->index, errno);
        return -1;
    }

    return 0;
}

static void crawler_kill(Crawler *cwl)
{
    tox_kill(cwl->tox);
    free(cwl->nodes_list);
    free(cwl);
}

/* Returns true if the crawler is unable to find new nodes in the DHT or the exit flag has been triggered */
static bool crawler_finished(Crawler *cwl)
{
    if (interrupted || (cwl->send_ptr == cwl->num_nodes &&
            timedout(cwl->last_new_node, config->timeout))) {
        return true;
    }

    return false;
}

void *crawler_thread_routine(void *data)
{
    Crawler *cwl = (Crawler *)data;

    __sync_add_and_fetch(&running_crawlers, 1);

    vlogI("Crawler[%u/%u] - created and running.", cwl->round, cwl->index);

    while (!crawler_finished(cwl)) {
        tox_iterate(cwl->tox, NULL);
        crawler_send_node_requests(cwl);
        usleep(tox_iteration_interval(cwl->tox) * 1000);
    }

    vlogI("Crawler[%u/%u] - discovered %u nodes.", cwl->round, cwl->index, cwl->num_nodes);

    if (!interrupted) {
        int rc;

        vlogI("Crawler[%u/%u] - dumping nodes list...", cwl->round, cwl->index);
        rc = crawler_dump_nodes(cwl);
        if (rc != 0) {
            vlogE("Crawler[%u/%u] - dumping nodes list failed: ", cwl->round, cwl->index, rc);
        } else {
            vlogI("Crawler[%u/%u] - dumping nodes list success", cwl->round, cwl->index);
        }
    }

    crawler_kill(cwl);

    __sync_sub_and_fetch(&running_crawlers, 1);

    vlogI("Crawler[%u/%u] finished and cleaned up.", cwl->round, cwl->index);

    return NULL;
}

/*
 * Control crawler instances according config parameters.
 *
 * Returns 0 on success or if new instance is not needed, otherwise returns
 * error number
 */
#define INTERVAL2       90

static int crawler_controller(void)
{
    pthread_attr_t attr;
    Crawler *cwl;
    uint32_t interval;
    int rc;

    interval = (last_index % config->max_crawlers) ? INTERVAL2 : config->interval;

    vlogV("Controller - inspection, %d crawlers running.", running_crawlers);
    vlogD("Controller - inspection, current interval %d.", interval);

    if (running_crawlers >= config->max_crawlers || ! timedout(last_crawler_stamp, interval))
        return 0;

    cwl = crawler_new();
    if (cwl == NULL) {
        vlogE("Controller - Create new crawler failed.");
        return -1;
    }

    memset(&attr, 0, sizeof(attr)); // guarantee no random values if init failed.
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    rc = pthread_create(&cwl->tid, &attr, crawler_thread_routine, (void *)cwl);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        vlogE("Controller - Create new crawler thread failed: %d\n", rc);
        return -1;
    }

    last_crawler_stamp = now();

    last_index++;
    if ((last_index % config->max_crawlers) == 0)
        last_crawler_stamp -= (INTERVAL2 * config->max_crawlers);

    return 0;
}

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>

int sys_coredump_set(bool enable)
{
    const struct rlimit rlim = {
        enable ? RLIM_INFINITY : 0,
        enable ? RLIM_INFINITY : 0
    };

    return setrlimit(RLIMIT_CORE, &rlim);
}
#endif

static void usage(void)
{
    printf("Elastos Carrier Crawler.\n");
    printf("Usage: elacrawler [OPTION]...\n");
    printf("\n");
    printf("  -c, --config=CONFIG_FILE  Set config file path.\n");
    printf("      --once                Run once then exit.\n");
    printf("      --debug               Wait for debugger attach after start.\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    int wait_for_attach = 0;
    char config_file[PATH_MAX+1] = {0};
    int log_level = -1;

    int opt;
    int idx;
    struct option options[] = {
        { "config",         required_argument,  NULL, 'c' },
        { "verbose",        required_argument,  NULL, 'v' },
        { "debug",          no_argument,        NULL, 1 },
        { "help",           no_argument,        NULL, 'h' },
        { NULL,             0,                  NULL, 0 }
    };

#ifdef HAVE_SYS_RESOURCE_H
    sys_coredump_set(true);
#endif

    while ((opt = getopt_long(argc, argv, "c:v:h?",
            options, &idx)) != -1) {
        switch (opt) {
        case 'c':
            strncpy(config_file, optarg, sizeof(config_file));
            config_file[sizeof(config_file)-1] = 0;
            break;

        case 'v':
            log_level = atoi(optarg);
            break;

        case 1:
            wait_for_attach = 1;
            break;

        case 'h':
        case '?':
        default:
            usage();
            exit(-1);
        }
    }

    if (!*config_file) {
        usage();
        exit(-1);
    }

    if (wait_for_attach) {
        printf("Wait for debugger attaching, process id is: %d.\n", getpid());
#ifndef _MSC_VER
        printf("After debugger attached, press any key to continue......");
        getchar();
        getchar();
#else
        DebugBreak();
#endif
    }

    config = load_config(config_file);
    if (!config) {
        fprintf(stderr, "loading configure failed !\n");
        return -1;
    }

    vlog_init(log_level > 0 ? log_level : config->log_level, config->log_file, NULL);

    signal(SIGINT, crawler_interrupt);

    if (pthread_mutex_init(&threads.lock, NULL) != 0) {
        fprintf(stderr, "pthread mutex failed to init in main()\n");
        exit(EXIT_FAILURE);
    }


    while (true) {
        int rc;

        if (interrupted)
            break;

        rc = crawler_controller();
        sleep(rc == 0 ? 5 : 30);
    }

    deref(config);

    return 0;
}

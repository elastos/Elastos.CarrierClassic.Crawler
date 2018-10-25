/*  util.c
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
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <base58.h>

/* Returns the current unix time. */
time_t get_time(void)
{
    return time(NULL);
}

/* Returns true if timestamp has timed out according to timeout value. */
bool timed_out(time_t timestamp, time_t timeout)
{
    return timestamp + timeout <= get_time();
}

/* Puts the current time in buf in the format of [HH:mm:ss] */
void get_time_format(char *buf, int bufsize)
{
    struct tm *timeinfo;
    time_t t = get_time();
    timeinfo = localtime((const time_t*) &t);
    strftime(buf, bufsize, "%H:%M:%S", timeinfo);
}

/*
 * Converts a base58-based string of length hex_len to binary format and puts the result in output.
 * output_size must be exactly half of hex_len.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */

int base58_string_to_bin(const char *key, size_t base58_len, uint8_t *bin, size_t length)
{
    if (length == 0 || base58_len != strlen(key))
        return -1;

    return (base58_decode(key, strlen(key), bin, length) == 32 ? 0 : -1);
}

/*
 * Converts a base58-based string of length hex_len to binary format and puts the result in output.
 * output_size must be exactly half of hex_len.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int bin_to_base58_string(const uint8_t *bin, size_t bin_len, char *output, size_t output_size)
{
    size_t i;
    size_t textlen = output_size;
    char *key;

    if (!output || textlen < 46)
        return  -1;

    return base58_encode(bin, bin_len, output, &textlen) ? 0 : -1;
}
/* Puts logfile path into buf in the form: BASE_LOG_PATH/YYYY-mm-dd/unix-timestamp.cwl
 *
 * -The crawler's present working directory is treated as root.
 * -The date is the current day, and the unixtime is the current unixtime.
 * -If the current day's directory does not exist it is automatically created.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
#define BASE_LOG_PATH "../crawler_logs"
int get_log_path(char *buf, size_t buf_len)
{
    time_t tm = get_time();

    char tmstr[32];
    strftime(tmstr, sizeof(tmstr), "%Y-%m-%d", localtime(&tm));

    char path[strlen(BASE_LOG_PATH) + strlen(tmstr) + 3];
    snprintf(path, sizeof(path), "%s/%s/", BASE_LOG_PATH, tmstr);

    struct stat st;

    if (stat(BASE_LOG_PATH, &st) == -1) {
        if (mkdir(BASE_LOG_PATH, 0700) == -1) {
            return -1;
        }
    }

    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) == -1) {
            return -1;
        }
    }

    strftime(tmstr, sizeof(tmstr), "%H%M%S", localtime(&tm));
    snprintf(buf, buf_len, "%s/%s.cwl", path, tmstr);

    return 0;
}


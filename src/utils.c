#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "utils.h"

void get_timestamp_iso8601(char *buf, size_t size) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%S", &tm);
}

void get_username_by_pid(pid_t pid, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        strncpy(buf, "unknown", size);
        return;
    }

    char line[256];
    uid_t uid = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%u", &uid);
            break;
        }
    }
    fclose(f);

    if (uid == (uid_t)-1) {
        strncpy(buf, "unknown", size);
        return;
    }

    struct passwd *pw = getpwuid(uid);
    if (pw) {
        strncpy(buf, pw->pw_name, size - 1);
    } else {
        snprintf(buf, size, "%u", uid);
    }
}

void get_cwd_by_pid(pid_t pid, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cwd", pid);

    char *res = realpath(path, NULL);
    if (res) {
        strncpy(buf, res, size - 1);
        free(res);
    } else {
        strncpy(buf, "/", size - 1);
    }
}

void read_proc_cmdline(pid_t pid, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        buf[0] = '\0';
        return;
    }

    size_t pos = 0;
    int c;
    while ((c = fgetc(f)) != EOF && pos < size - 1) {
        if (c == '\0') {
            if (pos > 0 && pos < size - 1) {
                buf[pos++] = ' ';
            }
        } else {
            buf[pos++] = (char)c;
        }
    }
    buf[pos] = '\0';

    if (pos > 0 && buf[pos - 1] == ' ') {
        buf[pos - 1] = '\0';
    }

    fclose(f);
}

void read_proc_comm(pid_t pid, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        buf[0] = '\0';
        return;
    }

    if (fgets(buf, size, f)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }
    }
    fclose(f);
}

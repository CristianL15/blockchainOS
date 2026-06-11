#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log_local.h"

static char log_path[1024] = "./log/local.log";
static char *cached_lines[65536];
static int cached_count = 0;

int local_log_init(const char *path) {
    if (path) {
        strncpy(log_path, path, sizeof(log_path) - 1);
    }

    char dir[1024];
    strncpy(dir, log_path, sizeof(dir) - 1);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
        system(cmd);
    }

    return 0;
}

void local_log_write(const AuditEvent *ev) {
    FILE *f = fopen(log_path, "a");
    if (!f) return;

    char json[JSON_EVENT_MAX];
    audit_event_to_json(ev, json, sizeof(json));
    fprintf(f, "%s\n", json);
    fclose(f);
}

int local_log_read_all(char ***lines, int *count) {
    for (int i = 0; i < cached_count; i++) {
        free(cached_lines[i]);
    }
    cached_count = 0;

    FILE *f = fopen(log_path, "r");
    if (!f) {
        *lines = NULL;
        *count = 0;
        return 0;
    }

    char buf[8192];
    while (fgets(buf, sizeof(buf), f) && cached_count < 65536) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
        cached_lines[cached_count] = strdup(buf);
        cached_count++;
    }
    fclose(f);

    *lines = cached_lines;
    *count = cached_count;
    return 0;
}

int local_log_simulate_tamper(int line, int field_index, const char *new_value) {
    (void)field_index;

    char **lines = NULL;
    int count = 0;
    local_log_read_all(&lines, &count);

    if (line < 0 || line >= count) return -1;

    char *orig = lines[line];
    char *hash_pos = strstr(orig, "\"hash\"");
    if (!hash_pos) return -1;

    char *cmd_pos = strstr(orig, "\"command\":\"");
    if (!cmd_pos) return -1;
    cmd_pos += 11;

    char *cmd_end = strchr(cmd_pos, '"');
    if (!cmd_end) return -1;

    char new_line[8192];
    size_t prefix_len = cmd_pos - orig;
    strncpy(new_line, orig, prefix_len);
    new_line[prefix_len] = '\0';
    strncat(new_line, new_value, sizeof(new_line) - strlen(new_line) - 1);
    strncat(new_line, cmd_end, sizeof(new_line) - strlen(new_line) - 1);

    FILE *f = fopen(log_path, "w");
    if (!f) return -1;

    for (int i = 0; i < count; i++) {
        if (i == line) {
            fprintf(f, "%s\n", new_line);
        } else {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    return 0;
}

void local_log_clear(void) {
    if (access(log_path, F_OK) == 0) {
        unlink(log_path);
    }
}

void local_log_destroy(void) {
    for (int i = 0; i < cached_count; i++) {
        free(cached_lines[i]);
    }
    cached_count = 0;
}

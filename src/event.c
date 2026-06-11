#include <stdio.h>
#include <string.h>
#include <time.h>

#include "event.h"
#include "crypto.h"

void audit_event_init(AuditEvent *ev, const char *type, const char *cmd,
                      pid_t pid, int return_code) {
    memset(ev, 0, sizeof(AuditEvent));
    strncpy(ev->event_type, type, EVENT_TYPE_MAX - 1);
    strncpy(ev->command, cmd, COMMAND_MAX - 1);
    ev->pid = pid;
    ev->return_code = return_code;
    strncpy(ev->user, "unknown", USER_MAX - 1);
    strncpy(ev->cwd, "/", CWD_MAX - 1);
}

void audit_event_compute_hash(AuditEvent *ev) {
    char buf[JSON_EVENT_MAX];
    snprintf(buf, sizeof(buf),
             "{\"event_type\":\"%s\",\"command\":\"%s\",\"user\":\"%s\","
             "\"pid\":%d,\"cwd\":\"%s\",\"timestamp\":\"%s\",\"return_code\":%d}",
             ev->event_type, ev->command, ev->user,
             ev->pid, ev->cwd, ev->timestamp, ev->return_code);
    sha256_hash(buf, ev->hash);
}

void audit_event_to_json(const AuditEvent *ev, char *buf, size_t buf_size) {
    snprintf(buf, buf_size,
             "{\"event_type\":\"%s\",\"command\":\"%s\",\"user\":\"%s\","
             "\"pid\":%d,\"cwd\":\"%s\",\"timestamp\":\"%s\",\"return_code\":%d,\"hash\":\"%s\"}",
             ev->event_type, ev->command, ev->user,
             ev->pid, ev->cwd, ev->timestamp, ev->return_code, ev->hash);
}

int audit_event_from_json(AuditEvent *ev, const char *json) {
    memset(ev, 0, sizeof(AuditEvent));

    const char *p;

    p = strstr(json, "\"event_type\":\"");
    if (!p) return -1;
    p += 14;
    int i = 0;
    while (*p && *p != '"' && i < EVENT_TYPE_MAX - 1) ev->event_type[i++] = *p++;
    ev->event_type[i] = '\0';

    p = strstr(json, "\"command\":\"");
    if (!p) return -1;
    p += 11;
    i = 0;
    while (*p && *p != '"' && i < COMMAND_MAX - 1) {
        if (*p == '\\' && *(p+1)) { p++; }
        ev->command[i++] = *p++;
    }
    ev->command[i] = '\0';

    p = strstr(json, "\"user\":\"");
    if (!p) return -1;
    p += 8;
    i = 0;
    while (*p && *p != '"' && i < USER_MAX - 1) ev->user[i++] = *p++;
    ev->user[i] = '\0';

    p = strstr(json, "\"pid\":");
    if (!p) return -1;
    p += 6;
    ev->pid = 0;
    while (*p && *p >= '0' && *p <= '9') { ev->pid = ev->pid * 10 + (*p - '0'); p++; }

    p = strstr(json, "\"cwd\":\"");
    if (!p) return -1;
    p += 7;
    i = 0;
    while (*p && *p != '"' && i < CWD_MAX - 1) ev->cwd[i++] = *p++;
    ev->cwd[i] = '\0';

    p = strstr(json, "\"timestamp\":\"");
    if (!p) return -1;
    p += 13;
    i = 0;
    while (*p && *p != '"' && i < TIMESTAMP_MAX - 1) ev->timestamp[i++] = *p++;
    ev->timestamp[i] = '\0';

    p = strstr(json, "\"return_code\":");
    if (!p) return -1;
    p += 14;
    int sign = 1;
    if (*p == '-') { sign = -1; p++; }
    ev->return_code = 0;
    while (*p && *p >= '0' && *p <= '9') { ev->return_code = ev->return_code * 10 + (*p - '0'); p++; }
    ev->return_code *= sign;

    p = strstr(json, "\"hash\":\"");
    if (!p) return -1;
    p += 8;
    i = 0;
    while (*p && *p != '"' && i < HASH_HEX_SIZE - 1) ev->hash[i++] = *p++;
    ev->hash[i] = '\0';

    return 0;
}

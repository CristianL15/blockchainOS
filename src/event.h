#ifndef EVENT_H
#define EVENT_H

#include <sys/types.h>
#include <unistd.h>
#include <stddef.h>

#define EVENT_TYPE_MAX 16
#define COMMAND_MAX 4096
#define USER_MAX 64
#define CWD_MAX 1024
#define TIMESTAMP_MAX 32
#define HASH_HEX_SIZE 65
#define JSON_EVENT_MAX 8192

typedef struct {
    char event_type[EVENT_TYPE_MAX];
    char command[COMMAND_MAX];
    char user[USER_MAX];
    pid_t pid;
    char cwd[CWD_MAX];
    char timestamp[TIMESTAMP_MAX];
    int return_code;
    char hash[HASH_HEX_SIZE];
} AuditEvent;

void audit_event_init(AuditEvent *ev, const char *type, const char *cmd,
                      pid_t pid, int return_code);

void audit_event_compute_hash(AuditEvent *ev);

void audit_event_to_json(const AuditEvent *ev, char *buf, size_t buf_size);

int audit_event_from_json(AuditEvent *ev, const char *json);

#endif

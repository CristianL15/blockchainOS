#ifndef AUDIT_MONITOR_H
#define AUDIT_MONITOR_H

#include "event.h"

typedef void (*event_callback_t)(const AuditEvent *ev);

typedef struct {
    int running;
    event_callback_t callback;
} AuditMonitor;

int  audit_monitor_init(AuditMonitor *am, event_callback_t cb);
void audit_monitor_start(AuditMonitor *am);
void audit_monitor_stop(AuditMonitor *am);
void audit_monitor_destroy(AuditMonitor *am);

#endif

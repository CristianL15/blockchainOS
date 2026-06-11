#ifndef PROC_MONITOR_H
#define PROC_MONITOR_H

#include "event.h"

typedef void (*event_callback_t)(const AuditEvent *ev);

typedef struct {
    pid_t *pids;
    int count;
    int capacity;
    int running;
    int interval_ms;
    event_callback_t callback;
} ProcMonitor;

int  proc_monitor_init(ProcMonitor *pm, int interval_ms, event_callback_t cb);
void proc_monitor_start(ProcMonitor *pm);
void proc_monitor_stop(ProcMonitor *pm);
void proc_monitor_destroy(ProcMonitor *pm);

#endif

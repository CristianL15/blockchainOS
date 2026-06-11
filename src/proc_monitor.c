#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include "proc_monitor.h"
#include "utils.h"

static int pid_set_contains(ProcMonitor *pm, pid_t pid) {
    for (int i = 0; i < pm->count; i++) {
        if (pm->pids[i] == pid) return 1;
    }
    return 0;
}

static void pid_set_add(ProcMonitor *pm, pid_t pid) {
    if (pm->count >= pm->capacity) {
        int newcap = pm->capacity ? pm->capacity * 2 : 1024;
        pid_t *np = realloc(pm->pids, sizeof(pid_t) * newcap);
        if (!np) return;
        pm->pids = np;
        pm->capacity = newcap;
    }
    pm->pids[pm->count++] = pid;
}

int proc_monitor_init(ProcMonitor *pm, int interval_ms, event_callback_t cb) {
    memset(pm, 0, sizeof(ProcMonitor));
    pm->interval_ms = interval_ms > 0 ? interval_ms : 500;
    pm->callback = cb;
    pm->running = 0;
    pm->pids = NULL;
    pm->count = 0;
    pm->capacity = 0;
    return 0;
}

void proc_monitor_destroy(ProcMonitor *pm) {
    free(pm->pids);
    memset(pm, 0, sizeof(ProcMonitor));
}

static void capture_new_process(ProcMonitor *pm, pid_t pid) {
    AuditEvent ev;
    char cmd[COMMAND_MAX] = "";

    read_proc_cmdline(pid, cmd, sizeof(cmd));
    if (!cmd[0]) {
        read_proc_comm(pid, cmd, sizeof(cmd));
    }
    if (!cmd[0]) return;

    audit_event_init(&ev, "process_creation", cmd, pid, 0);

    char username[64];
    get_username_by_pid(pid, username, sizeof(username));
    strncpy(ev.user, username, USER_MAX - 1);

    char cwd_path[CWD_MAX];
    get_cwd_by_pid(pid, cwd_path, sizeof(cwd_path));
    strncpy(ev.cwd, cwd_path, CWD_MAX - 1);

    char ts[TIMESTAMP_MAX];
    get_timestamp_iso8601(ts, sizeof(ts));
    strncpy(ev.timestamp, ts, TIMESTAMP_MAX - 1);

    audit_event_compute_hash(&ev);

    if (pm->callback) pm->callback(&ev);
}

void proc_monitor_start(ProcMonitor *pm) {
    pm->running = 1;

    DIR *proc = opendir("/proc");
    if (!proc) {
        fprintf(stderr, "Cannot open /proc\n");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            pid_t pid = atoi(entry->d_name);
            pid_set_add(pm, pid);
        }
    }
    closedir(proc);

    while (pm->running) {
        ProcMonitor current;
        memset(&current, 0, sizeof(current));

        proc = opendir("/proc");
        if (!proc) break;

        while ((entry = readdir(proc)) != NULL) {
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
                pid_t pid = atoi(entry->d_name);
                pid_set_add(&current, pid);

                if (!pid_set_contains(pm, pid)) {
                    capture_new_process(pm, pid);
                }
            }
        }
        closedir(proc);

        free(pm->pids);
        pm->pids = current.pids;
        pm->count = current.count;
        pm->capacity = current.capacity;

        usleep(pm->interval_ms * 1000);
    }
}

void proc_monitor_stop(ProcMonitor *pm) {
    pm->running = 0;
}

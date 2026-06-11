#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <libaudit.h>
#include <linux/audit.h>

#ifndef AUDIT_USER_LOGIN
#define AUDIT_USER_LOGIN 2100
#endif

#include "audit_monitor.h"
#include "utils.h"

int audit_monitor_init(AuditMonitor *am, event_callback_t cb) {
    memset(am, 0, sizeof(AuditMonitor));
    am->callback = cb;
    am->running = 0;
    return 0;
}

void audit_monitor_destroy(AuditMonitor *am) {
    memset(am, 0, sizeof(AuditMonitor));
}

static void fill_audit_event(AuditEvent *ev) {
    char ts[TIMESTAMP_MAX];
    get_timestamp_iso8601(ts, sizeof(ts));
    strncpy(ev->timestamp, ts, TIMESTAMP_MAX - 1);

    if (ev->pid > 0) {
        char cwd_path[CWD_MAX];
        get_cwd_by_pid(ev->pid, cwd_path, sizeof(cwd_path));
        strncpy(ev->cwd, cwd_path, CWD_MAX - 1);
    }

    audit_event_compute_hash(ev);
}

static void dispatch(AuditMonitor *am, AuditEvent *ev) {
    if (am->callback) am->callback(ev);
}

static char *field_str(const char *msg, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "%s=\"", key);
    char *start = strstr(msg, pattern);
    if (!start) return NULL;
    start += strlen(pattern);
    char *end = strchr(start, '"');
    if (!end) return NULL;
    size_t len = end - start;
    if (len > COMMAND_MAX - 1) len = COMMAND_MAX - 1;
    char *val = malloc(len + 1);
    if (!val) return NULL;
    strncpy(val, start, len);
    val[len] = '\0';
    return val;
}

static long field_long(const char *msg, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), " %s=", key);
    char *p = strstr(msg, pattern);
    if (!p) {
        snprintf(pattern, sizeof(pattern), "%s=", key);
        p = strstr(msg, pattern);
        if (!p) return 0;
        p += strlen(key) + 1;
    } else {
        p += strlen(key) + 2;
    }
    return atol(p);
}

static void parse_execve(AuditMonitor *am, struct audit_reply *rep) {
    const char *msg = rep->message;
    AuditEvent ev;
    audit_event_init(&ev, "execve", msg, 0, 0);

    ev.pid = (pid_t)field_long(msg, "pid");

    char *exe = field_str(msg, "exe");
    if (exe) {
        strncpy(ev.command, exe, COMMAND_MAX - 1);
        free(exe);
    }

    if (!ev.command[0]) {
        char *comm = field_str(msg, "comm");
        if (comm) {
            strncpy(ev.command, comm, COMMAND_MAX - 1);
            free(comm);
        }
    }

    long uid_val = field_long(msg, "uid");
    struct passwd *pw = getpwuid((uid_t)uid_val);
    if (pw) {
        strncpy(ev.user, pw->pw_name, USER_MAX - 1);
    } else {
        snprintf(ev.user, USER_MAX, "%ld", uid_val);
    }

    fill_audit_event(&ev);
    dispatch(am, &ev);
}

static void parse_syscall(AuditMonitor *am, struct audit_reply *rep) {
    const char *msg = rep->message;
    long nr = field_long(msg, "syscall");
    long exit_val = field_long(msg, "exit");

    /* skip uninteresting syscalls to reduce noise */
    int interesting = 0;
    switch (nr) {
    case 2:   /* open */
    case 257: /* openat */
    case 85:  /* creat */
    case 3:   /* close */
    case 0:   /* read */
    case 1:   /* write */
    case 9:   /* mmap */
    case 10:  /* mprotect */
    case 11:  /* munmap */
    case 56:  /* clone */
    case 57:  /* fork */
    case 58:  /* vfork */
    case 59:  /* execve — handled by AUDIT_EXECVE directly */
    case 322: /* execveat */
    case 29:  /* pause */
    case 62:  /* kill */
    case 49:  /* bind */
    case 50:  /* listen */
    case 43:  /* accept */
    case 42:  /* connect */
    case 82:  /* rename */
    case 87:  /* link */
    case 88:  /* unlink */
        interesting = 1;
        break;
    }

    if (!interesting) return;

    AuditEvent ev;
    char cmd[COMMAND_MAX];
    char *exe = field_str(msg, "exe");
    char *comm = field_str(msg, "comm");
    if (exe) {
        snprintf(cmd, sizeof(cmd), "%s (syscall=%ld exit=%ld)", exe, nr, exit_val);
        free(exe);
    } else if (comm) {
        snprintf(cmd, sizeof(cmd), "%s (syscall=%ld exit=%ld)", comm, nr, exit_val);
        free(comm);
    } else {
        snprintf(cmd, sizeof(cmd), "(syscall=%ld exit=%ld)", nr, exit_val);
    }

    audit_event_init(&ev, "syscall", cmd, 0, 0);
    ev.pid = (pid_t)field_long(msg, "pid");

    long uid_val = field_long(msg, "uid");
    struct passwd *pw = getpwuid((uid_t)uid_val);
    if (pw) strncpy(ev.user, pw->pw_name, USER_MAX - 1);
    else snprintf(ev.user, USER_MAX, "%ld", uid_val);

    fill_audit_event(&ev);
    dispatch(am, &ev);
}

static void parse_path(AuditMonitor *am, struct audit_reply *rep) {
    const char *msg = rep->message;

    char *name = field_str(msg, "name");
    if (!name) return;

    AuditEvent ev;
    audit_event_init(&ev, "file_access", name, 0, 0);
    free(name);

    ev.pid = (pid_t)field_long(msg, "pid");

    long uid_val = field_long(msg, "ouid");
    struct passwd *pw = getpwuid((uid_t)uid_val);
    if (pw) strncpy(ev.user, pw->pw_name, USER_MAX - 1);
    else snprintf(ev.user, USER_MAX, "%ld", uid_val);

    /* nametype: NORMAL, CREATE, DELETE, etc. */
    char *nt = field_str(msg, "nametype");
    if (nt) {
        char buf[COMMAND_MAX + 64];
        snprintf(buf, sizeof(buf), "%s (%s)", ev.command, nt);
        strncpy(ev.command, buf, COMMAND_MAX - 1);
        free(nt);
    }

    fill_audit_event(&ev);
    dispatch(am, &ev);
}

static void parse_user_login(AuditMonitor *am, struct audit_reply *rep) {
    const char *msg = rep->message;
    AuditEvent ev;
    audit_event_init(&ev, "user_login", msg, 0, 0);

    ev.pid = (pid_t)field_long(msg, "pid");

    char *exe = field_str(msg, "exe");
    if (exe) {
        strncpy(ev.command, exe, COMMAND_MAX - 1);
        free(exe);
    }

    char *host = field_str(msg, "addr");
    if (!host) host = field_str(msg, "hostname");
    if (host) {
        char buf[COMMAND_MAX + 128];
        snprintf(buf, sizeof(buf), "%s from %s", ev.command[0] ? ev.command : "(unknown)", host);
        strncpy(ev.command, buf, COMMAND_MAX - 1);
        free(host);
    }

    long uid_val = field_long(msg, "uid");
    struct passwd *pw = getpwuid((uid_t)uid_val);
    if (pw) strncpy(ev.user, pw->pw_name, USER_MAX - 1);
    else snprintf(ev.user, USER_MAX, "%ld", uid_val);

    /* res=success / res=failed */
    char *res = field_str(msg, "res");
    if (res) {
        char buf[COMMAND_MAX + 64];
        snprintf(buf, sizeof(buf), "%s [%s]", ev.command, res);
        strncpy(ev.command, buf, COMMAND_MAX - 1);
        free(res);
    }

    fill_audit_event(&ev);
    dispatch(am, &ev);
}

static void parse_anom_abend(AuditMonitor *am, struct audit_reply *rep) {
    const char *msg = rep->message;
    AuditEvent ev;
    audit_event_init(&ev, "process_crash", msg, 0, 0);

    ev.pid = (pid_t)field_long(msg, "pid");

    char *exe = field_str(msg, "exe");
    if (exe) {
        strncpy(ev.command, exe, COMMAND_MAX - 1);
        free(exe);
    }

    if (!ev.command[0]) {
        char *comm = field_str(msg, "comm");
        if (comm) {
            strncpy(ev.command, comm, COMMAND_MAX - 1);
            free(comm);
        }
    }

    long sig = field_long(msg, "sig");
    char sig_buf[64];
    snprintf(sig_buf, sizeof(sig_buf), " signal=%ld", sig);
    if (strlen(ev.command) + strlen(sig_buf) < COMMAND_MAX - 1) {
        strcat(ev.command, sig_buf);
    }

    long uid_val = field_long(msg, "uid");
    struct passwd *pw = getpwuid((uid_t)uid_val);
    if (pw) strncpy(ev.user, pw->pw_name, USER_MAX - 1);
    else snprintf(ev.user, USER_MAX, "%ld", uid_val);

    fill_audit_event(&ev);
    dispatch(am, &ev);
}

void audit_monitor_start(AuditMonitor *am) {
    am->running = 1;

    int fd = audit_open();
    if (fd < 0) {
        fprintf(stderr, "audit_open() failed: %s (run as root)\n", strerror(errno));
        return;
    }

    if (audit_is_enabled(fd) == 0) {
        fprintf(stderr, "Warning: audit disabled. Enable: auditctl -e 1\n");
    }

    struct audit_rule_data *rule;
    rule = calloc(1, sizeof(struct audit_rule_data));
    rule->flags = AUDIT_FILTER_EXIT;
    rule->action = AUDIT_ALWAYS;
    rule->field_count = 0;

    audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    free(rule);

    while (am->running) {
        struct audit_reply rep;
        int rc = audit_get_reply(fd, &rep, GET_REPLY_BLOCKING, 0);
        if (rc <= 0) {
            if (errno == EINTR) continue;
            break;
        }

        switch (rep.type) {
        case AUDIT_EXECVE:
            parse_execve(am, &rep);
            break;
        case AUDIT_SYSCALL:
            parse_syscall(am, &rep);
            break;
        case AUDIT_PATH:
            parse_path(am, &rep);
            break;
        case AUDIT_USER_LOGIN:
            parse_user_login(am, &rep);
            break;
        case AUDIT_ANOM_ABEND:
            parse_anom_abend(am, &rep);
            break;
        }
    }

    close(fd);
}

void audit_monitor_stop(AuditMonitor *am) {
    am->running = 0;
}

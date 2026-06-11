#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "capture.h"
#include "utils.h"

static void report_event(pid_t pid, int return_code,
                         event_callback_t callback) {
    AuditEvent ev;
    char cmd[COMMAND_MAX] = "";

    read_proc_cmdline(pid, cmd, sizeof(cmd));
    if (!cmd[0]) return;

    audit_event_init(&ev, "execve", cmd, pid, return_code);

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
    if (callback) callback(&ev);
}

int capture_run_command(char *const argv[], event_callback_t callback) {
    pid_t pid = fork();
    if (pid == -1) return -1;

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(argv[0], argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    ptrace(PTRACE_SETOPTIONS, pid, NULL,
           (void *)(unsigned long)(PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT));

    while (1) {
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        if (waitpid(pid, &status, 0) < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) break;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            int event = (status >> 16) & 0xffff;

            if (event == PTRACE_EVENT_EXEC) {
                report_event(pid, 0, callback);
                continue;
            }

            if (event == PTRACE_EVENT_EXIT) {
                unsigned long exit_data = 0;
                ptrace(PTRACE_GETEVENTMSG, pid, NULL, &exit_data);
                continue;
            }
        }
    }

    return 0;
}

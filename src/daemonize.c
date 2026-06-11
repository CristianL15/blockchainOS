#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "daemonize.h"

#define PIDFILE_PATH "/var/run/blockchain_auditor.pid"

int daemonize(const char *pidfile) {
    if (!pidfile) pidfile = PIDFILE_PATH;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) {
        FILE *f = fopen(pidfile, "w");
        if (f) {
            fprintf(f, "%d\n", pid);
            fclose(f);
        }
        return 1;
    }

    if (setsid() < 0) return -1;

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);

    umask(0);

    chdir("/");

    for (int i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
        close(i);
    }

    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);

    return 0;
}

int daemon_stop(const char *pidfile) {
    if (!pidfile) pidfile = PIDFILE_PATH;

    FILE *f = fopen(pidfile, "r");
    if (!f) {
        fprintf(stderr, "PID file not found: %s\n", pidfile);
        return -1;
    }

    pid_t pid;
    fscanf(f, "%d", &pid);
    fclose(f);

    if (kill(pid, SIGTERM) == 0) {
        unlink(pidfile);
        return 0;
    }

    fprintf(stderr, "Failed to stop daemon (PID %d): %s\n", pid, "not running");
    unlink(pidfile);
    return -1;
}

int daemon_status(const char *pidfile) {
    if (!pidfile) pidfile = PIDFILE_PATH;

    FILE *f = fopen(pidfile, "r");
    if (!f) return 0;

    pid_t pid;
    fscanf(f, "%d", &pid);
    fclose(f);

    if (kill(pid, 0) == 0) {
        printf("Daemon running (PID %d)\n", pid);
        return 1;
    }

    unlink(pidfile);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <math.h>

#include "event.h"
#include "queue.h"
#include "http_client.h"
#include "log_local.h"
#include "capture.h"
#include "proc_monitor.h"
#include "audit_monitor.h"
#include "daemonize.h"
#include "utils.h"

#define PIDFILE "/var/run/blockchain_auditor.pid"
#define ENV_GATEWAY_URL "GATEWAY_URL"
#define DEFAULT_GATEWAY "http://localhost:8443"

static AsyncQueue g_queue;
static volatile int g_running = 1;
static int g_use_gateway = 1;

static void event_callback(const AuditEvent *ev) {
    if (g_use_gateway) {
        queue_push(&g_queue, ev);
    }
    local_log_write(ev);
}

static void *worker_thread(void *arg) {
    (void)arg;
    AuditEvent ev;

    while (g_running || queue_count(&g_queue) > 0) {
        int rc = queue_pop(&g_queue, &ev, 1000);
        if (rc == 0 && g_use_gateway) {
            int retries = 3;
            while (retries > 0) {
                if (http_client_post_event(&ev) == 0) break;
                retries--;
                if (retries > 0) {
                    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };
                    nanosleep(&ts, NULL);
                }
            }
        }
    }
    return NULL;
}

static void sigint_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static int cmd_run(int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "Usage: auditor run [--local-only] <command> [args...]\n");
        return 1;
    }

    char **cmd_argv = argv;
    int cmd_argc = argc;

    if (strcmp(argv[0], "--local-only") == 0) {
        g_use_gateway = 0;
        cmd_argv++;
        cmd_argc--;
    }

    if (cmd_argc < 1) {
        fprintf(stderr, "Usage: auditor run [--local-only] <command> [args...]\n");
        return 1;
    }

    pthread_t thread;
    if (g_use_gateway) {
        pthread_create(&thread, NULL, worker_thread, NULL);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc = capture_run_command(cmd_argv, event_callback);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (g_use_gateway) {
        g_running = 0;
        queue_shutdown(&g_queue);
        pthread_join(thread, NULL);
    }

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("\n=== Audit Result ===\n");
    printf("Command:   %s\n", cmd_argv);
    printf("Exit code: %d\n", rc);
    printf("Time:      %.4fs\n", elapsed);
    printf("Gateway:   %s\n", g_use_gateway ? "enabled" : "disabled (local only)");

    return rc;
}

static int cmd_daemon(int argc, char **argv) {
    int use_audit = 0;
    int interval = 200;
    int daemon_bg = 0;

    static struct option opts[] = {
        {"audit",    no_argument,       0, 'a'},
        {"interval", required_argument, 0, 'i'},
        {"daemon",   no_argument,       0, 'd'},
        {0,0,0,0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "ai:d", opts, NULL)) != -1) {
        switch (opt) {
            case 'a': use_audit = 1; break;
            case 'i': interval = atoi(optarg); if (interval < 10) interval = 10; break;
            case 'd': daemon_bg = 1; break;
        }
    }

    if (daemon_bg) {
        int rc = daemonize(PIDFILE);
        if (rc == 1) { printf("Daemon started (PID file: %s)\n", PIDFILE); return 0; }
        if (rc < 0) { fprintf(stderr, "Failed to daemonize\n"); return 1; }
    }

    if (use_audit) {
        printf("Starting audit daemon (Linux Audit)...\n");
    } else {
        printf("Starting /proc polling daemon (interval=%dms)...\n", interval);
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, NULL);

    if (use_audit) {
        AuditMonitor am;
        audit_monitor_init(&am, event_callback);
        audit_monitor_start(&am);
        audit_monitor_destroy(&am);
    } else {
        ProcMonitor pm;
        proc_monitor_init(&pm, interval, event_callback);
        proc_monitor_start(&pm);
        proc_monitor_destroy(&pm);
    }

    g_running = 0;
    queue_shutdown(&g_queue);
    pthread_join(thread, NULL);

    return 0;
}

static int cmd_verify(int argc, char **argv) {
    int check_local = 0;
    if (argc > 0 && strcmp(argv[0], "--local") == 0) check_local = 1;

    printf("=== Blockchain Integrity Verification ===\n\n");

    char response[16384];
    int rc = http_client_get("/api/verify", response, sizeof(response));
    if (rc == 0) {
        printf("Gateway response:\n%s\n", response);
    } else {
        printf("Gateway unavailable\n");
    }

    if (check_local) {
        printf("\n--- Local Log Check ---\n");
        char **logs = NULL;
        int count = 0;
        local_log_read_all(&logs, &count);
        printf("Local events: %d\n", count);

        if (count > 0 && rc == 0) {
            printf("Comparing local events against blockchain...\n");
            printf("(Run 'auditor integrity-test' for detailed verification)\n");
        }
    }

    return 0;
}

static int cmd_status(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("=== Blockchain Auditor Status ===\n\n");

    const char *gw = getenv(ENV_GATEWAY_URL);
    if (!gw) gw = DEFAULT_GATEWAY;
    printf("Gateway URL:   %s\n", gw);

    char response[8192];
    int rc = http_client_get("/api/status", response, sizeof(response));
    if (rc == 0) {
        printf("Gateway:       online\n%s\n", response);
    } else {
        printf("Gateway:       offline\n");
    }

    char **logs = NULL;
    int count = 0;
    local_log_read_all(&logs, &count);
    printf("Local events:  %d\n", count);

    daemon_status(PIDFILE);

    return 0;
}

static int cmd_benchmark(int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "Usage: auditor benchmark [-n N] <command> [args...]\n");
        return 1;
    }

    int iterations = 10;
    int opt;
    while ((opt = getopt(argc, argv, "n:")) != -1) {
        if (opt == 'n') iterations = atoi(optarg);
    }

    char **cmd_argv = argv + optind;
    if (cmd_argv[0] == NULL) {
        fprintf(stderr, "Usage: auditor benchmark [-n N] <command> [args...]\n");
        return 1;
    }

    printf("Benchmarking: %s (%d iterations)\n", cmd_argv[0], iterations);

    double *times = malloc(sizeof(double) * iterations);
    if (!times) return 1;

    double total = 0, min = 1e9, max = 0;

    for (int i = 0; i < iterations; i++) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        capture_run_command(cmd_argv, NULL);
        clock_gettime(CLOCK_MONOTONIC, &end);

        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        times[i] = elapsed;
        total += elapsed;
        if (elapsed < min) min = elapsed;
        if (elapsed > max) max = elapsed;
        printf("  Run %3d: %.4fs\n", i + 1, elapsed);
    }

    double avg = total / iterations;
    double var = 0;
    for (int i = 0; i < iterations; i++) {
        double diff = times[i] - avg;
        var += diff * diff;
    }
    var /= iterations;

    printf("\nResults:\n");
    printf("  Average: %.4fs\n", avg);
    printf("  StdDev:  %.4fs\n", sqrt(var));
    printf("  Min:     %.4fs\n", min);
    printf("  Max:     %.4fs\n", max);

    free(times);
    return 0;
}

static int cmd_stress(int argc, char **argv) {
    int count = 100;
    if (argc > 0) count = atoi(argv[0]);
    if (count < 1) count = 100;
    if (count > 10000) count = 10000;

    printf("Stress test: %d events\n", count);

    const char *commands[] = {
        "/bin/ls", "/usr/bin/whoami", "/bin/date", "/bin/pwd",
        "/bin/uname", "/usr/bin/id", "/bin/echo", "/bin/hostname",
        "/usr/bin/uptime", "/bin/true"
    };
    int num_cmds = sizeof(commands) / sizeof(commands[0]);

    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, NULL);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int queue_peak = 0;

    for (int i = 0; i < count; i++) {
        const char *cmd = commands[i % num_cmds];
        char *args[] = {(char *)cmd, NULL};
        capture_run_command(args, event_callback);

        int qc = queue_count(&g_queue);
        if (qc > queue_peak) queue_peak = qc;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    g_running = 0;
    queue_shutdown(&g_queue);
    pthread_join(thread, NULL);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("\nResults:\n");
    printf("  Events:      %d\n", count);
    printf("  Total time:  %.4fs\n", elapsed);
    printf("  Throughput:  %.1f events/s\n", count / elapsed);
    printf("  Queue peak:  %d\n", queue_peak);
    printf("  Gateway:     %s\n", g_use_gateway ? "enabled" : "disabled");

    return 0;
}

static int cmd_integrity_test(int argc, char **argv) {
    int tamper_line = -1;
    const char *tamper_value = "TAMPERED";

    if (argc > 0) tamper_line = atoi(argv[0]);
    if (argc > 1) tamper_value = argv[1];

    printf("=== Integrity Test ===\n\n");

    int rc = http_client_get("/api/verify", NULL, 0);
    if (rc == 0) {
        printf("Gateway:      online\n");
        char response[16384];
        http_client_get("/api/verify", response, sizeof(response));
        printf("Verification: %s\n", response);
    } else {
        printf("Gateway:      offline (skipping blockchain check)\n");
    }

    char **logs = NULL;
    int count = 0;
    local_log_read_all(&logs, &count);
    printf("Local events: %d\n\n", count);

    int tamper_applied = 0;
    if (tamper_line >= 0 && tamper_line < count) {
        local_log_simulate_tamper(tamper_line, 0, tamper_value);
        printf("  [tamper] applied: line %d -> \"%s\"\n", tamper_line, tamper_value);
        tamper_applied = 1;
        local_log_read_all(&logs, &count);
    }

    int verified = 0;
    int failed = 0;
    for (int i = 0; i < count; i++) {
        AuditEvent ev;
        if (audit_event_from_json(&ev, logs[i]) != 0) {
            printf("  [%3d] PARSE ERROR\n", i);
            failed++;
            continue;
        }
        char stored_hash[65];
        strncpy(stored_hash, ev.hash, sizeof(stored_hash) - 1);
        ev.hash[0] = '\0';
        audit_event_compute_hash(&ev);
        if (strcmp(ev.hash, stored_hash) == 0) {
            verified++;
        } else {
            printf("  [%3d] HASH MISMATCH: stored=%s computed=%s\n",
                   i, stored_hash, ev.hash);
            failed++;
        }
    }

    printf("\n  Verified: %d/%d", verified, count);
    if (failed > 0) printf(", FAILED: %d", failed);
    printf("\n");
    if (tamper_applied) printf("  (tamper simulation active)\n");

    printf("\nIntegrity check complete.\n");
    return failed > 0 ? 1 : 0;
}

static int cmd_clear(void) {
    local_log_clear();
    printf("Local logs cleared.\n");
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  run <cmd> [args...]     Execute and trace a command\n");
    printf("    --local-only          Log locally only (skip gateway)\n");
    printf("  daemon                  Start process monitoring daemon\n");
    printf("    --audit               Use Linux Audit (requires root)\n");
    printf("    --interval <ms>       Polling interval (default: 500)\n");
    printf("    --daemon              Fork to background\n");
    printf("  daemon stop             Stop the daemon\n");
    printf("  daemon status           Check daemon status\n");
    printf("  verify [--local]        Verify blockchain integrity\n");
    printf("  status                  Show system status\n");
    printf("  benchmark [-n N] <cmd>  Run performance benchmark\n");
    printf("  stress [-c N]           Run stress test\n");
    printf("  integrity-test [line]   Run integrity test\n");
    printf("  clear                   Clear local logs\n\n");
    printf("Environment:\n");
    printf("  GATEWAY_URL             Gateway URL (default: %s)\n", DEFAULT_GATEWAY);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *gw_url = getenv(ENV_GATEWAY_URL);
    if (!gw_url) gw_url = DEFAULT_GATEWAY;

    local_log_init(NULL);

    if (http_client_init(gw_url) != 0) {
        fprintf(stderr, "Warning: HTTP client init failed\n");
    }

    queue_init(&g_queue, QUEUE_DEFAULT_SIZE);

    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    int rc = 0;

    if (strcmp(argv[1], "run") == 0) {
        rc = cmd_run(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "daemon") == 0) {
        if (argc > 2 && strcmp(argv[2], "stop") == 0) {
            rc = daemon_stop(PIDFILE);
        } else if (argc > 2 && strcmp(argv[2], "status") == 0) {
            rc = daemon_status(PIDFILE) < 0 ? 1 : 0;
        } else {
            rc = cmd_daemon(argc - 2, argv + 2);
        }
    } else if (strcmp(argv[1], "verify") == 0) {
        rc = cmd_verify(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "status") == 0) {
        rc = cmd_status(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "benchmark") == 0) {
        rc = cmd_benchmark(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "stress") == 0) {
        rc = cmd_stress(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "integrity-test") == 0) {
        rc = cmd_integrity_test(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "clear") == 0) {
        rc = cmd_clear();
    } else {
        print_usage(argv[0]);
        rc = 1;
    }

    queue_destroy(&g_queue);
    http_client_destroy();
    local_log_destroy();

    return rc;
}

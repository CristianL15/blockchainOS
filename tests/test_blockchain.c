#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../src/event.h"
#include "../src/crypto.h"
#include "../src/capture.h"
#include "../src/utils.h"

static AuditEvent g_ev;

static int tests_passed = 0;
static int tests_total = 0;

#define TEST(name) do { \
    tests_total++; \
    printf("  TEST %2d: %-45s ", tests_total, name); \
} while(0)

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n"); \
        return 1; \
    } \
} while(0)

#define PASS() do { \
    tests_passed++; \
    printf("OK\n"); \
} while(0)

static int test_event_init_and_hash(void) {
    TEST("event init with execve type");
    AuditEvent ev;
    audit_event_init(&ev, "execve", "/bin/echo hello", 12345, 0);
    CHECK(strcmp(ev.event_type, "execve") == 0);
    CHECK(strcmp(ev.command, "/bin/echo hello") == 0);
    CHECK(ev.pid == 12345);
    CHECK(ev.return_code == 0);
    CHECK(ev.hash[0] == '\0');
    PASS();

    TEST("event hash computation");
    audit_event_compute_hash(&ev);
    CHECK(ev.hash[0] != '\0');
    CHECK(strlen(ev.hash) == 64);
    PASS();

    return 0;
}

static int test_event_json(void) {
    TEST("event JSON serialization");
    AuditEvent ev;
    audit_event_init(&ev, "execve", "ls -la /tmp", 9999, 0);
    strncpy(ev.user, "testuser", USER_MAX - 1);
    strncpy(ev.cwd, "/tmp", CWD_MAX - 1);
    strncpy(ev.timestamp, "2026-06-04T12:00:00", TIMESTAMP_MAX - 1);
    audit_event_compute_hash(&ev);

    char json[4096];
    audit_event_to_json(&ev, json, sizeof(json));
    CHECK(strstr(json, "\"event_type\":\"execve\"") != NULL);
    CHECK(strstr(json, "\"command\":\"ls -la /tmp\"") != NULL);
    CHECK(strstr(json, "\"user\":\"testuser\"") != NULL);
    CHECK(strstr(json, "\"pid\":9999") != NULL);
    CHECK(strstr(json, "\"cwd\":\"/tmp\"") != NULL);
    CHECK(strstr(json, "\"return_code\":0") != NULL);
    CHECK(strstr(json, "\"hash\":") != NULL);
    CHECK(json[strlen(json) - 1] == '}');
    PASS();

    return 0;
}

static int test_timestamp_format(void) {
    TEST("ISO8601 timestamp format");
    char ts[TIMESTAMP_MAX];
    get_timestamp_iso8601(ts, sizeof(ts));
    CHECK(strlen(ts) > 0);
    CHECK(ts[4] == '-');
    CHECK(ts[7] == '-');
    CHECK(ts[10] == 'T');
    CHECK(ts[13] == ':');
    CHECK(ts[16] == ':');
    PASS();

    return 0;
}

static int test_crypto(void) {
    TEST("SHA-256 of known string");
    char hash[65] = {0};
    sha256_hash("hello", hash);
    CHECK(strcmp(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") == 0);
    PASS();

    TEST("SHA-256 of empty string");
    sha256_hash("", hash);
    CHECK(strcmp(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    PASS();

    return 0;
}

static void capture_callback(const AuditEvent *ev) {
    g_ev = *ev;
}

static int test_capture_invalid_cmd(void) {
    TEST("capture of non-existent command");
    char *argv[] = {"/nonexistent/binary", NULL};
    int ret = capture_run_command(argv, NULL);
    CHECK(ret == 0);
    PASS();
    return 0;
}

static int test_capture_happy_path(void) {
    TEST("capture /bin/true (exit 0)");
    memset(&g_ev, 0, sizeof(g_ev));
    char *argv[] = {"/bin/true", NULL};
    int ret = capture_run_command(argv, capture_callback);
    CHECK(ret == 0);
    PASS();
    return 0;
}

int main(void) {
    printf("=== Blockchain Auditor: C Module Tests ===\n\n");

    int failures = 0;
    failures += test_event_init_and_hash();
    failures += test_event_json();
    failures += test_timestamp_format();
    failures += test_crypto();
    failures += test_capture_invalid_cmd();
    failures += test_capture_happy_path();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_total);
    if (failures > 0) printf(", %d FAILED", failures);
    printf(" ===\n");

    return failures > 0 ? 1 : 0;
}

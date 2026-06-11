#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <unistd.h>

void get_timestamp_iso8601(char *buf, size_t size);
void get_username_by_pid(pid_t pid, char *buf, size_t size);
void get_cwd_by_pid(pid_t pid, char *buf, size_t size);
void read_proc_cmdline(pid_t pid, char *buf, size_t size);
void read_proc_comm(pid_t pid, char *buf, size_t size);

#endif

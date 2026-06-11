#ifndef LOG_LOCAL_H
#define LOG_LOCAL_H

#include "event.h"

int  local_log_init(const char *path);
void local_log_write(const AuditEvent *ev);
int  local_log_read_all(char ***lines, int *count);
int  local_log_simulate_tamper(int line, int field_index, const char *new_value);
void local_log_clear(void);
void local_log_destroy(void);

#endif

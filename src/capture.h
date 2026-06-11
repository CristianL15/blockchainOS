#ifndef CAPTURE_H
#define CAPTURE_H

#include "event.h"

typedef void (*event_callback_t)(const AuditEvent *ev);

int capture_run_command(char *const argv[], event_callback_t callback);

#endif

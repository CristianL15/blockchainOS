#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>
#include <stddef.h>
#include "event.h"

#define QUEUE_DEFAULT_SIZE 4096

typedef struct {
    AuditEvent *buffer;
    int head;
    int tail;
    int size;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
    int shutdown;
} AsyncQueue;

int  queue_init(AsyncQueue *q, int size);
void queue_destroy(AsyncQueue *q);
int  queue_push(AsyncQueue *q, const AuditEvent *ev);
int  queue_pop(AsyncQueue *q, AuditEvent *ev, int timeout_ms);
void queue_shutdown(AsyncQueue *q);
int  queue_count(AsyncQueue *q);

#endif

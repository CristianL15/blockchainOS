#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "queue.h"

int queue_init(AsyncQueue *q, int size) {
    memset(q, 0, sizeof(AsyncQueue));
    if (size <= 0) size = QUEUE_DEFAULT_SIZE;

    q->buffer = (AuditEvent *)malloc(sizeof(AuditEvent) * size);
    if (!q->buffer) return -1;

    q->size = size;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->shutdown = 0;

    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_full, NULL);
    pthread_cond_init(&q->not_empty, NULL);

    return 0;
}

void queue_destroy(AsyncQueue *q) {
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_full);
    pthread_cond_destroy(&q->not_empty);
    free(q->buffer);
    memset(q, 0, sizeof(AsyncQueue));
}

int queue_push(AsyncQueue *q, const AuditEvent *ev) {
    pthread_mutex_lock(&q->mutex);

    while (q->count >= q->size && !q->shutdown) {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }

    if (q->shutdown) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }

    q->buffer[q->tail] = *ev;
    q->tail = (q->tail + 1) % q->size;
    q->count++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);

    return 0;
}

int queue_pop(AsyncQueue *q, AuditEvent *ev, int timeout_ms) {
    pthread_mutex_lock(&q->mutex);

    if (q->count == 0 && !q->shutdown) {
        if (timeout_ms > 0) {
            struct timespec ts;
            struct timeval tv;
            gettimeofday(&tv, NULL);
            ts.tv_sec = tv.tv_sec + timeout_ms / 1000;
            ts.tv_nsec = (tv.tv_usec + (timeout_ms % 1000) * 1000) * 1000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&q->not_empty, &q->mutex, &ts);
        } else {
            pthread_cond_wait(&q->not_empty, &q->mutex);
        }
    }

    if (q->count == 0 || q->shutdown) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }

    *ev = q->buffer[q->head];
    q->head = (q->head + 1) % q->size;
    q->count--;

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);

    return 0;
}

void queue_shutdown(AsyncQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->shutdown = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
}

int queue_count(AsyncQueue *q) {
    pthread_mutex_lock(&q->mutex);
    int c = q->count;
    pthread_mutex_unlock(&q->mutex);
    return c;
}

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "event.h"

int http_client_init(const char *gateway_url);
void http_client_destroy(void);
int http_client_post_event(const AuditEvent *ev);
int http_client_get(const char *endpoint, char *response, size_t resp_size);

#endif

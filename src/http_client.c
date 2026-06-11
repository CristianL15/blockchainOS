#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "http_client.h"

static CURL *curl = NULL;
static char base_url[512] = "";

struct WriteBuf {
    char *data;
    size_t len;
    size_t cap;
};

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    struct WriteBuf *buf = (struct WriteBuf *)userdata;
    if (buf->len + total >= buf->cap) {
        buf->cap = buf->len + total + 4096;
        char *np = realloc(buf->data, buf->cap);
        if (!np) return 0;
        buf->data = np;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

int http_client_init(const char *gateway_url) {
    if (!gateway_url) gateway_url = "http://localhost:8443";
    strncpy(base_url, gateway_url, sizeof(base_url) - 1);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "BlockchainOS-Auditor/1.0");

    return 0;
}

void http_client_destroy(void) {
    if (curl) curl_easy_cleanup(curl);
    curl_global_cleanup();
    memset(base_url, 0, sizeof(base_url));
}

int http_client_post_event(const AuditEvent *ev) {
    if (!curl) return -1;

    char json[JSON_EVENT_MAX];
    audit_event_to_json(ev, json, sizeof(json));

    char url[1024];
    snprintf(url, sizeof(url), "%s/api/events", base_url);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));

    struct WriteBuf buf = {0};
    buf.data = malloc(1024);
    buf.cap = 1024;
    buf.len = 0;
    buf.data[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    int ret = 0;
    if (res != CURLE_OK) {
        fprintf(stderr, "HTTP POST failed: %s\n", curl_easy_strerror(res));
        ret = -1;
    }

    free(buf.data);
    return ret;
}

int http_client_get(const char *endpoint, char *response, size_t resp_size) {
    if (!curl) return -1;

    char url[1024];
    snprintf(url, sizeof(url), "%s%s", base_url, endpoint);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, NULL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);

    struct WriteBuf buf = {0};
    buf.data = malloc(resp_size);
    buf.cap = resp_size;
    buf.len = 0;
    buf.data[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        strncpy(response, buf.data, resp_size - 1);
    }
    free(buf.data);

    return (res == CURLE_OK) ? 0 : -1;
}

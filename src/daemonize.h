#ifndef DAEMONIZE_H
#define DAEMONIZE_H

int daemonize(const char *pidfile);
int daemon_stop(const char *pidfile);
int daemon_status(const char *pidfile);

#endif

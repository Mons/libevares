#include <ev.h>
#include <ares.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#ifndef cwarn
#define cwarn(fmt, ...)   do{ \
	fprintf(stderr, "[WARN] %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != 0x0a) { fprintf(stderr, "\n"); } \
	} while(0)
#endif

typedef struct {
	ev_io    io;
	ev_timer tw;
	struct ev_loop * loop;
	struct {
		ares_channel channel;
		struct ares_options options;
	} ares;
	struct timeval timeout;
} ev_ares;

struct _ev_ares_result;
typedef void (*ev_ares_callback)(struct _ev_ares_result *result);

struct _ev_ares_result {
	ev_ares         *resolver;
	//which request
	char            *host;
	int              family;
	
	int              status;
	char            *error;
	int              timeouts;
	struct hostent  *hosts;
	ev_ares_callback callback;
};

typedef struct _ev_ares_result ev_ares_result;

int ev_ares_init(ev_ares *resolver, double timeout);

void ev_ares_resolve(struct ev_loop * loop, ev_ares * resolver, char * hostname, int family, ev_ares_callback callback);

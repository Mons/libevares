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

typedef void (*ev_ares_callback_v)(void *result);

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

#define mktype(type,add,...)\
typedef struct { \
	ev_ares         *resolver;\
	char            *query;\
	int              status;\
	const char      *error;\
	int              timeouts;\
	ev_ares_callback_v callback;\
	add; \
} ev_ares_result_ ##type ; \
typedef void (*ev_ares_callback_##type)(ev_ares_result_##type *result);\
void ev_ares_##type     (struct ev_loop * loop, ev_ares * resolver, char * hostname, ##__VA_ARGS__, ev_ares_callback_##type callback)

mktype(a,struct ares_addrttl a[16];int count);
mktype(aaaa,struct ares_addr6ttl aaaa[16];int count);
mktype(mx,struct ares_mx_reply * mx);
mktype(txt,struct ares_txt_reply * txt);
mktype(srv,struct ares_srv_reply * srv);
mktype(soa,struct ares_soa_reply * soa);
mktype(ns,struct hostent *ns);
mktype(ptr,struct hostent *ptr; int family, int family);
/*TODO:
srv
txt
cname
soa
ns
*/
#undef mktype

int ev_ares_init(ev_ares *resolver, double timeout);

void ev_ares_resolve(struct ev_loop * loop, ev_ares * resolver, char * hostname, int family, ev_ares_callback callback);


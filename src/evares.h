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

#define IOMAX 8

typedef struct {
	ev_io io;
	int   id;
} io_ptr;

typedef struct {
	//ev_io    io;
	io_ptr     ios[8];
	int        ioc;
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

struct ev_ares_soa_reply {
	char        *nsname;
	char        *hostmaster;
	unsigned int serial;
	unsigned int refresh;
	unsigned int retry;
	unsigned int expire;
	unsigned int minttl;
	int          ttl;
};

struct ev_ares_ns_reply {
	struct ev_ares_ns_reply   *next;
	char                      *host;
	int                        ttl;
};

struct ev_ares_a_reply {
	struct ev_ares_a_reply    *next;
	char                      *host;
	struct in_addr             ip;
	int                        ttl;
};

struct ev_ares_aaaa_reply {
	struct ev_ares_aaaa_reply *next;
	char                      *host;
	struct ares_in6_addr       ip6;
	int                        ttl;
};

struct ev_ares_mx_reply {
	struct ev_ares_mx_reply   *next;
	char                      *host;
	unsigned short             priority;
	int                        ttl;
};

struct ev_ares_srv_reply {
	struct ev_ares_srv_reply  *next;
	char                      *host;
	unsigned short             priority;
	unsigned short             weight;
	unsigned short             port;
	int                        ttl;
};

struct ev_ares_ptr_reply {
	struct ev_ares_ptr_reply  *next;
	char                      *host;
	int                        ttl;
};

struct ev_ares_txt_reply {
	struct ev_ares_txt_reply  *next;
	unsigned char             *txt;
	size_t                     length;  /* length excludes null termination */
	int                        ttl;
};

struct ev_ares_naptr_reply {
	struct ev_ares_naptr_reply *next;
	unsigned char           *flags;
	unsigned short           order;
	unsigned char           *service;
	unsigned char           *regexp;
	char                    *replacement;
	unsigned short           preference;
	int                      ttl;
};

#define mktype(type,add,...)\
typedef struct { \
	ev_ares         *resolver;\
	char            *query;\
	int              status;\
	const char      *error;\
	int              timeouts;\
	void            *any;\
	ev_ares_callback_v callback;\
	add; \
} ev_ares_result_ ##type ; \
typedef void (*ev_ares_callback_##type)(ev_ares_result_##type *result);\
void ev_ares_##type (struct ev_loop * loop, ev_ares * resolver, char * hostname, ##__VA_ARGS__, void *any, ev_ares_callback_##type callback)

mktype(soa,   struct ev_ares_soa_reply     * soa);
mktype(ns,    struct ev_ares_ns_reply      * ns);
mktype(a,     struct ev_ares_a_reply       * a);
mktype(aaaa,  struct ev_ares_aaaa_reply    * aaaa);
mktype(mx,    struct ev_ares_mx_reply      * mx);
mktype(srv,   struct ev_ares_srv_reply     * srv);
mktype(ptr,   struct ev_ares_ptr_reply     * ptr);
mktype(txt,   struct ev_ares_txt_reply     * txt);
mktype(naptr, struct ev_ares_naptr_reply   * naptr);
mktype(hba,   struct hostent *hosts; int family, int family);

#undef mktype

int ev_ares_init(ev_ares *resolver, double timeout);
int ev_ares_clean(ev_ares *resolver);

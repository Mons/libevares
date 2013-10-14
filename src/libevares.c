#include <evares.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <stdlib.h>
#include "ev_ares_parse_srv_reply.c"
#include "ev_ares_parse_mx_reply.c"
#include "ev_ares_parse_ns_reply.c"
#include "ev_ares_parse_ptr_reply.c"
#include "ev_ares_parse_txt_reply.c"
#include "ev_ares_parse_soa_reply.c"
#include "ev_ares_parse_a_reply.c"
#include "ev_ares_parse_aaaa_reply.c"
#include "ev_ares_parse_naptr_reply.c"

static void io_cb (EV_P_ ev_io *w, int revents) {
	ev_ares * resolver = (ev_ares *) w;
	
	ares_socket_t rfd = ARES_SOCKET_BAD, wfd = ARES_SOCKET_BAD;
	
	if (revents & EV_READ)  rfd = w->fd;
	if (revents & EV_WRITE) wfd = w->fd;
	
	ares_process_fd(resolver->ares.channel, rfd, wfd);
	
	return;
}

static void ev_ares_sock_state_cb(void *data, int s, int read, int write) {
	struct timeval *tvp, tv;
	memset(&tv,0,sizeof(tv));
	ev_ares * resolver = (ev_ares *) data;
	if( !ev_is_active( &resolver->tw ) && (tvp = ares_timeout(resolver->ares.channel, NULL, &tv)) ) {
		double timeout = (double)tvp->tv_sec+(double)tvp->tv_usec/1.0e6;
		//cwarn("Set timeout to %0.8lf",timeout);
		if (timeout > 0) {
			// TODO
			//ev_timer_set(&eares->tw,timeout,0.);
			//ev_timer_start()
		}
	}
	//cwarn("[%p] Change state fd %d read:%d write:%d; max time: %u.%u (%p)", data, s, read, write, tv.tv_sec, tv.tv_usec, tvp);
	if (ev_is_active(&resolver->io) && resolver->io.fd != s) return;
	if (read || write) {
		ev_io_set( &resolver->io, s, (read ? EV_READ : 0) | (write ? EV_WRITE : 0) );
		ev_io_start( resolver->loop, &resolver->io );
	}
	else {
		ev_io_stop(resolver->loop, &resolver->io);
		ev_io_set( &resolver->io, -1, 0);
	}
}

int ev_ares_init(ev_ares *resolver, double timeout) {
	memset(resolver,0,sizeof(ev_ares));
	
	resolver->ares.options.sock_state_cb_data = resolver;
	resolver->ares.options.sock_state_cb = ev_ares_sock_state_cb;
	
	resolver->timeout.tv_sec = timeout;
	resolver->timeout.tv_usec = (timeout - (int)timeout) * 1e6;
	
	ev_init(&resolver->io,io_cb);
	
	return ares_init_options(&resolver->ares.channel, &resolver->ares.options, ARES_OPT_SOCK_STATE_CB);
}

int ev_ares_clean(ev_ares *resolver) {
	ares_destroy(resolver->ares.channel);
	ares_destroy_options(&resolver->ares.options);
}

// methods

typedef struct _sortable list_t;
struct _sortable {
	struct _sortable *next;
	char             *dummy;
	unsigned short    value;
};

static void sort_split(list_t* src, list_t ** front, list_t **back) {
	list_t *fast, *slow;
	if (!src || !src->next) {
		*front = src;
		*back = NULL;
	}
	else {
		slow = src;
		fast = src->next;
		while (fast) {
			fast = fast->next;
			if (fast) {
				slow = slow->next;
				fast = fast->next;
			}
		}
		*front = src;
		*back = slow->next;
		slow->next = NULL;
	}
}


static inline list_t * sort_merge (list_t * a, list_t * b);
static inline list_t * sort_merge (list_t * a, list_t * b) {
	list_t * res = NULL;
	if (!a) return b;
	else if (!b) return a;
	if (a->value <= b->value) {
		res = a;
		res->next = sort_merge(a->next,b);
	}
	else {
		res = b;
		res->next = sort_merge(a,b->next);
	}
	return res;
}

static void sort_list ( list_t** list );
static void sort_list ( list_t** list )
{
	list_t* head = *list;
	list_t *a, *b;
	if (!head || !head->next) { return; }
	sort_split( head, &a,&b );
	sort_list( &a );
	sort_list( &b );
	
	*list = sort_merge(a,b);
	return;
}

static void ev_ares_internal_gethostbyaddr_callback(ev_ares_result_hba * res, int status, int timeouts, struct hostent *ptr) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	res->hosts = ptr;
	res->callback(res);
	free(res);
	return;
}

void ev_ares_gethostbyaddr (struct ev_loop * loop, ev_ares * resolver, char * hostname, void *any, ev_ares_callback_hba callback) {
	resolver->loop = loop;
	ev_ares_result_hba * res = malloc(sizeof(ev_ares_result_hba));
	int length;
	char addr[ sizeof(struct in6_addr) ];
	res->any      = any;
	res->resolver = resolver;
	res->query    = hostname;
	res->callback = (ev_ares_callback_v) callback;
	
	if (inet_pton(AF_INET, hostname, addr) == 1) {
		length = sizeof(struct in_addr);
		res->family   = AF_INET;
	}
	else
	if (inet_pton(AF_INET6, hostname, addr) == 1) {
		length = sizeof(struct in6_addr);
		res->family   = AF_INET6;
	}
	else
	{
		res->status = errno;
		res->error = strerror(errno);
		res->hosts = 0;
		callback(res);
		free(res);
		return;
	}
	
	ares_gethostbyaddr(resolver->ares.channel, addr, length, res->family, (ares_host_callback) ev_ares_internal_gethostbyaddr_callback, res);
	return;
}

#define gen_method(type,dosort)\
static void ev_ares_internal_##type##_callback(ev_ares_result_##type * res, int status, int timeouts, unsigned char *abuf, int alen) {\
	res->timeouts = timeouts;\
	res->status = status;\
	res->error = ares_strerror(status);\
	struct ev_ares_##type##_reply* reply = NULL;\
	if (status == ARES_SUCCESS) {\
		int pstatus = ev_ares_parse_##type##_reply(abuf, alen, &reply);\
		if (pstatus == ARES_SUCCESS) {\
			if (dosort) sort_list( (list_t **) &reply );\
		} else {\
			res->status = pstatus;\
			res->error  = ares_strerror(pstatus);\
		}\
		res->type = reply;\
	}\
	res->callback(res);\
	ev_ares_free_##type##_reply(reply);\
	free(res);\
}\
void ev_ares_##type    (struct ev_loop * loop, ev_ares * resolver, char * hostname, void * any, ev_ares_callback_##type callback) {\
	resolver->loop = loop;\
	ev_ares_result_##type * res = malloc(sizeof(ev_ares_result_##type));\
	\
	res->any      = any; \
	res->resolver = resolver;\
	res->query    = hostname;\
	res->callback = (ev_ares_callback_v) callback;\
	\
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_##type, (ares_callback) ev_ares_internal_##type##_callback, res);\
	return;\
}

gen_method(a,0);
gen_method(aaaa,0);
gen_method(mx,1);
gen_method(ns,0);
gen_method(ptr,0);
gen_method(srv,1);
gen_method(txt,0);
gen_method(soa,0);
gen_method(naptr,1);

#undef gen_metod

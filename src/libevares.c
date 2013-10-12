#include <evares.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <stdlib.h>

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

// methods

static void ev_ares_internal_a_callback(ev_ares_result_a * res, int status, int timeouts, unsigned char *abuf, int alen) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	if (status == ARES_SUCCESS) {
		res->count = sizeof(res->a)/sizeof(res->a[0]);
		int pstatus = ares_parse_a_reply(abuf, alen, NULL, res->a, &res->count);
		if (pstatus != ARES_SUCCESS) {
			res->count  = 0;
			res->status = pstatus;
			res->error  = ares_strerror(pstatus);
		}
	} else {
		res->count = 0;
	}
	res->callback(res);
	free(res);
	return;
}

void ev_ares_a     (struct ev_loop * loop, ev_ares * resolver, char * hostname, ev_ares_callback_a callback) {
	resolver->loop = loop;
	ev_ares_result_a * res = malloc(sizeof(ev_ares_result_a));
	
	res->resolver = resolver;
	res->query    = hostname;
	res->callback = (ev_ares_callback_v) callback;
	
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_a, (ares_callback) ev_ares_internal_a_callback, res);
	return;
}

static void ev_ares_internal_aaaa_callback(ev_ares_result_aaaa * res, int status, int timeouts, unsigned char *abuf, int alen) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	if (status == ARES_SUCCESS) {
		res->count = sizeof(res->aaaa)/sizeof(res->aaaa[0]);
		int pstatus = ares_parse_aaaa_reply(abuf, alen, NULL, res->aaaa, &res->count);
		if (pstatus != ARES_SUCCESS) {
			res->count  = 0;
			res->status = pstatus;
			res->error  = ares_strerror(pstatus);
		}
	} else {
		res->count = 0;
	}
	res->callback(res);
	free(res);
	return;
}

void ev_ares_aaaa     (struct ev_loop * loop, ev_ares * resolver, char * hostname, ev_ares_callback_aaaa callback) {
	resolver->loop = loop;
	ev_ares_result_aaaa * res = malloc(sizeof(ev_ares_result_aaaa));
	
	res->resolver = resolver;
	res->query    = hostname;
	res->callback = (ev_ares_callback_v) callback;
	
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_aaaa, (ares_callback) ev_ares_internal_aaaa_callback, res);
	return;
}

typedef struct _sortable list_t;
struct _sortable {
	struct _sortable *next;
	char             *dummy;
	unsigned short    value;
};

void sort_split(list_t* src, list_t ** front, list_t **back) {
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


list_t * sort_merge (list_t * a, list_t * b);
list_t * sort_merge (list_t * a, list_t * b) {
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

void sort_list ( list_t** list );
void sort_list ( list_t** list )
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

static void ev_ares_internal_mx_callback(ev_ares_result_mx * res, int status, int timeouts, unsigned char *abuf, int alen) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	struct ares_mx_reply* mx = NULL;
	if (status == ARES_SUCCESS) {
		int pstatus = ares_parse_mx_reply(abuf, alen, &mx);
		if (pstatus == ARES_SUCCESS) {
			sort_list( (list_t **) &mx );
		} else {
			res->status = pstatus;
			res->error  = ares_strerror(pstatus);
		}
		res->mx = mx;
	}
	res->callback(res);
	if(mx)
		ares_free_data(mx);
	free(res);
}

void ev_ares_mx    (struct ev_loop * loop, ev_ares * resolver, char * hostname, ev_ares_callback_mx callback) {
	resolver->loop = loop;
	ev_ares_result_mx * res = malloc(sizeof(ev_ares_result_mx));
	
	res->resolver = resolver;
	res->query    = hostname;
	res->callback = (ev_ares_callback_v) callback;
	
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_mx, (ares_callback) ev_ares_internal_mx_callback, res);
	return;
}

static void ev_ares_internal_ns_callback(ev_ares_result_ns * res, int status, int timeouts, unsigned char *abuf, int alen) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	struct hostent *ns = 0;
	if (status == ARES_SUCCESS) {
		int pstatus = ares_parse_ns_reply(abuf, alen, &ns);
		if (pstatus != ARES_SUCCESS) {
			res->status = pstatus;
			res->error  = ares_strerror(pstatus);
		}
	}
	res->ns = ns;
	res->callback(res);
	if (ns)
		ares_free_hostent(ns);
	free(res);
	return;
}

void ev_ares_ns     (struct ev_loop * loop, ev_ares * resolver, char * hostname, ev_ares_callback_ns callback) {
	resolver->loop = loop;
	ev_ares_result_ns * res = malloc(sizeof(ev_ares_result_ns));
	
	res->resolver = resolver;
	res->query    = hostname;
	res->callback = (ev_ares_callback_v) callback;
	
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_ns, (ares_callback) ev_ares_internal_ns_callback, res);
	return;
}

static void ev_ares_internal_ptr_callback(ev_ares_result_ptr * res, int status, int timeouts, unsigned char *abuf, int alen) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	struct hostent *ptr = 0;
	if (status == ARES_SUCCESS) {
		int pstatus = ares_parse_ptr_reply(abuf, alen, 0, 0, res->family, &ptr);
		if (pstatus != ARES_SUCCESS) {
			res->status = pstatus;
			res->error  = ares_strerror(pstatus);
		}
	}
	res->ptr = ptr;
	res->callback(res);
	if (ptr)
		ares_free_hostent(ptr);
	free(res);
	return;
}

void ev_ares_ptr     (struct ev_loop * loop, ev_ares * resolver, char * hostname, int family, ev_ares_callback_ptr callback) {
	resolver->loop = loop;
	ev_ares_result_ptr * res = malloc(sizeof(ev_ares_result_ptr));
	
	res->resolver = resolver;
	res->query    = hostname;
	res->family   = family;
	res->callback = (ev_ares_callback_v) callback;
	
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_ptr, (ares_callback) ev_ares_internal_ptr_callback, res);
	return;
}

static void ev_ares_internal_gethostbyaddr_callback(ev_ares_result_ptr * res, int status, int timeouts, struct hostent *ptr) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	res->ptr = ptr;
	res->callback(res);
	free(res);
	return;
}

void ev_ares_gethostbyaddr (struct ev_loop * loop, ev_ares * resolver, char * hostname, ev_ares_callback_ptr callback) {
	resolver->loop = loop;
	ev_ares_result_ptr * res = malloc(sizeof(ev_ares_result_ptr));
	int length;
	char addr[ sizeof(struct in6_addr) ];
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
		res->ptr = 0;
		callback(res);
		free(res);
		return;
	}
	
	ares_gethostbyaddr(resolver->ares.channel, addr, length, res->family, (ares_host_callback) ev_ares_internal_gethostbyaddr_callback, res);
	return;
}



static void ev_ares_internal_srv_callback(ev_ares_result_srv * res, int status, int timeouts, unsigned char *abuf, int alen) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	struct ares_srv_reply* reply = NULL;
	if (status == ARES_SUCCESS) {
		int pstatus = ares_parse_srv_reply(abuf, alen, &reply);
		if (pstatus == ARES_SUCCESS) {
			sort_list( (list_t **) &reply );
		} else {
			res->status = pstatus;
			res->error  = ares_strerror(pstatus);
		}
		res->srv = reply;
	}
	
	res->callback(res);
	if(reply)
		ares_free_data(reply);
	free(res);
}
void ev_ares_srv    (struct ev_loop * loop, ev_ares * resolver, char * hostname, ev_ares_callback_srv callback) {
	resolver->loop = loop;
	ev_ares_result_srv * res = malloc(sizeof(ev_ares_result_srv));
	
	res->resolver = resolver;
	res->query    = hostname;
	res->callback = (ev_ares_callback_v) callback;
	
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_srv, (ares_callback) ev_ares_internal_srv_callback, res);
	return;
}

#define gen_method(type)\
static void ev_ares_internal_##type##_callback(ev_ares_result_##type * res, int status, int timeouts, unsigned char *abuf, int alen) {\
	res->timeouts = timeouts;\
	res->status = status;\
	res->error = ares_strerror(status);\
	struct ares_##type##_reply* reply = NULL;\
	if (status == ARES_SUCCESS) {\
		int pstatus = ares_parse_##type##_reply(abuf, alen, &reply);\
		if (pstatus != ARES_SUCCESS) {\
			res->status = pstatus;\
			res->error  = ares_strerror(pstatus);\
		}\
		res->type = reply;\
	}\
	res->callback(res);\
	if(reply)\
		ares_free_data(reply);\
	free(res);\
}\
void ev_ares_##type    (struct ev_loop * loop, ev_ares * resolver, char * hostname, ev_ares_callback_##type callback) {\
	resolver->loop = loop;\
	ev_ares_result_##type * res = malloc(sizeof(ev_ares_result_##type));\
	\
	res->resolver = resolver;\
	res->query    = hostname;\
	res->callback = (ev_ares_callback_v) callback;\
	\
	ares_query(resolver->ares.channel, hostname, ns_c_in, ns_t_##type, (ares_callback) ev_ares_internal_##type##_callback, res);\
	return;\
}

gen_method(txt);
gen_method(soa);

#undef gen_metod


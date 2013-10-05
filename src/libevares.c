#include <evares.h>

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

static void ev_ares_internal_callback(ev_ares_result * res, int status, int timeouts, struct hostent *host) {
	res->timeouts = timeouts;
	res->status = status;
	res->error = ares_strerror(status);
	res->hosts = host;
	res->callback(res);
	free(res);
}

void ev_ares_resolve(struct ev_loop * loop, ev_ares * resolver, char * hostname, int family, ev_ares_callback callback) {
	resolver->loop = loop;
	ev_ares_result * res = malloc(sizeof(ev_ares_result));
	
	res->resolver = resolver;
	res->host = hostname;
	res->family = family;
	
	res->callback = callback;
	
	ares_gethostbyname(resolver->ares.channel, hostname, family, (ares_host_callback) ev_ares_internal_callback, res);
	return;
}

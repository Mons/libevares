#include "evares.h" // also provide ev.h + ares.h

#include <stdlib.h>
#include <stdio.h>

static void callback(ev_ares_result * res);
static void callback(ev_ares_result * res) {
	printf("Result for '%s' (%s): %s\n",res->host, res->family == AF_INET ? "IPv4" : "IPv6", res->error);
	if (res->status != ARES_SUCCESS) return;
	char ip[INET6_ADDRSTRLEN];
	int i = 0;
	for (i = 0; res->hosts->h_addr_list[i]; ++i) {
		inet_ntop(res->hosts->h_addrtype, res->hosts->h_addr_list[i], ip, sizeof(ip));
		printf("%s\n", ip);
	}
	
	// We may call "recursive" resolving, to inspect for memory leaks
	//ev_ares_resolve(res->resolver->loop, res->resolver, res->host, res->family, callback);
	
	// res struct will be freed just after return from callback
	return;
}

int main (int argc, char *argv[]) {
	struct ev_loop *loop = EV_DEFAULT;
	
	if (argc < 2) { fprintf(stderr, "Uaage:\n\t%s domain\n",argv[0]); return 1; }
	char *hostname = argv[1];
	
	// Declare resolver struct;
	ev_ares resolver;
	
	printf("Resolving '%s'\n",hostname);
	
	// Initialize ares library.
	int status;
	if ((status = ares_library_init(ARES_LIB_INIT_ALL) )!= ARES_SUCCESS) {
		fprintf(stderr,"Ares error: %s\n",ares_strerror(status));
		return 1;
	}
	
	//Initialize resolver with timeout 1.3
	if (( status = ev_ares_init(&resolver, 1.3) ) != ARES_SUCCESS) {
		fprintf(stderr,"Ares error: %s\n",ares_strerror(status));
		return 1;
	}
	
	// Initiate 2 resolves, with IPv4 and IPv6
	// hostname variable must not be freed until resolve callback, since it referenced as result->host
	
	ev_ares_resolve(loop, &resolver, hostname, AF_INET, callback);
	ev_ares_resolve(loop, &resolver, hostname, AF_INET6, callback);
	
	// Run loop
	ev_run (loop, 0);
}

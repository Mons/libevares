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

static void callback_mx(ev_ares_result_mx * res) {
	printf("Result for MX '%s': %s\n",res->query, res->error);
	struct ares_mx_reply* current = res->mx;
	int i;
	for (; current != NULL; current = current->next) {
		printf(": host = %s; prio = %d\n", current->host, current->priority);
	}
	return;
}

static void callback_txt(ev_ares_result_txt * res) {
	printf("Result for TXT '%s': %s\n",res->query, res->error);
	struct ares_txt_reply* current = res->txt;
	int i;
	for (; current != NULL; current = current->next) {
		printf(": %s\n",current->txt);
	}
	return;
}

static void callback_a(ev_ares_result_a * res) {
	printf("Result for A '%s': %s\n",res->query, res->error);
	int i;
	char ip[INET_ADDRSTRLEN];
	for (i=0; i < res->count; i++) {
		inet_ntop(AF_INET, &res->a[i].ipaddr, ip, sizeof(ip));
		printf(": ip = %s, ttl = %d\n",ip, res->a[i].ttl);
	}
	return;
}

static void callback_ns(ev_ares_result_ns * res) {
	printf("Result for NS '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	int i = 0;
	for (i = 0; res->ns->h_aliases[i]; ++i) {
		printf(": %s\n", res->ns->h_aliases[i]);
	}
	return;
}

static void callback_ptr(ev_ares_result_ptr * res) {
	printf("Result for PTR '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	int i = 0;
	for (i = 0; res->ptr->h_aliases[i]; ++i) {
		printf(": %s\n", res->ptr->h_aliases[i]);
	}
	return;
}

static void callback_aaaa(ev_ares_result_aaaa * res) {
	printf("Result for AAAA '%s': %s\n",res->query, res->error);
	int i;
	char ip[INET6_ADDRSTRLEN];
	for (i=0; i < res->count; i++) {
		inet_ntop(AF_INET6, &res->aaaa[i].ip6addr, ip, sizeof(ip));
		printf(": ip = %s, ttl = %d\n",ip, res->aaaa[i].ttl);
	}
	return;
}

static void callback_srv(ev_ares_result_srv * res) {
	printf("Result for SRV '%s': %s\n",res->query, res->error);
	struct ares_srv_reply* current = res->srv;
	int i;
	for (; current != NULL; current = current->next) {
		printf(": %s:%d (prio=%d; weight=%d)\n",current->host,current->port, current->priority, current->weight);
	}
	return;
}

static void callback_soa(ev_ares_result_soa * res) {
	printf("Result for SOA '%s': %s\n",res->query, res->error);
	struct ares_soa_reply* soa = res->soa;
	printf("NS: %s; Hostmaster: %s, Serial: %d; Ref: %d; Ret: %d; Exp: %d; Mttl: %d\n",
		soa->nsname, soa->hostmaster, soa->serial, soa->refresh, soa->retry, soa->expire, soa->minttl);
	return;
}

#define JSRV "_xmpp-client._tcp."

int main (int argc, char *argv[]) {
	struct ev_loop *loop = EV_DEFAULT;
	
	if (argc < 2) { fprintf(stderr, "Uaage:\n\t%s domain\n",argv[0]); return 1; }
	char *hostname = argv[1];
	char *jabber = malloc(strlen(argv[1]) + strlen(JSRV) + 1); // will be freed on exit ;)
	strcat(jabber,JSRV);
	strcat(jabber,argv[1]);
	
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
	
	// hostname variable must not be freed until resolve callback, since it referenced as result->host
	
	ev_ares_a(loop,&resolver,hostname,callback_a);
	ev_ares_aaaa(loop,&resolver,hostname,callback_aaaa);
	ev_ares_ns(loop,&resolver,hostname,callback_ns);
	ev_ares_mx(loop,&resolver,hostname,callback_mx);
	
	ev_ares_srv(loop,&resolver,jabber,callback_srv);
	ev_ares_txt(loop,&resolver,hostname,callback_txt);
	ev_ares_soa(loop,&resolver,hostname,callback_soa);
	
	ev_ares_ptr(loop,&resolver,"8.8.8.8.in-addr.arpa", AF_INET, callback_ptr);
	ev_ares_ptr(loop,&resolver,"a.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.c.0.0.1.0.4.0.5.4.1.0.0.a.2.ip6.arpa", AF_INET6, callback_ptr);
	ev_ares_gethostbyaddr(loop,&resolver,"8.8.8.8", callback_ptr);
	ev_ares_gethostbyaddr(loop,&resolver,"2a00:1450:4010:c04::66", callback_ptr);
	
	// Run loop
	ev_run (loop, 0);
}

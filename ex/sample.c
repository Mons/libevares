#include "evares.h" // also provide ev.h + ares.h

#include <stdlib.h>
#include <stdio.h>

static void callback_soa(ev_ares_result_soa * res) {
	printf("Result for SOA '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_soa_reply* soa = res->soa;
	printf(": NS: %s; Hostmaster: %s, Serial: %d; Ref: %d; Ret: %d; Exp: %d; Mttl: %d; TTL: %d\n",
		soa->nsname, soa->hostmaster, soa->serial, soa->refresh, soa->retry, soa->expire, soa->minttl, soa->ttl);
	return;
}

static void callback_ns(ev_ares_result_ns * res) {
	printf("Result for NS '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_ns_reply* r = res->ns;
	for (; r != NULL; r = r->next) {
		printf(": %s; ttl=%d\n",r->host,r->ttl);
	}
}

static void callback_a(ev_ares_result_a * res) {
	printf("Result for A '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_a_reply* r = res->a;
	char ips[INET_ADDRSTRLEN];
	for (; r != NULL; r = r->next) {
		inet_ntop(AF_INET, &r->ip, ips, sizeof(ips));
		printf(": %s (%s); ttl=%d\n",ips, r->host, r->ttl);
	}
	return;
}

static void callback_aaaa(ev_ares_result_aaaa * res) {
	printf("Result for AAAA '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_aaaa_reply* r = res->aaaa;
	char ips[INET6_ADDRSTRLEN];
	for (; r != NULL; r = r->next) {
		inet_ntop(AF_INET6, &r->ip6, ips, sizeof(ips));
		printf(": %s (%s); ttl=%d\n", ips, r->host, r->ttl);
	}
	return;
}

static void callback_mx(ev_ares_result_mx * res) {
	printf("Result for MX '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_mx_reply* r = res->mx;
	int i;
	for (; r != NULL; r = r->next) {
		printf(": host = %s; prio = %d; ttl = %d\n", r->host, r->priority, r->ttl);
	}
	return;
}

static void callback_srv(ev_ares_result_srv * res) {
	printf("Result for SRV '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_srv_reply* srv = res->srv;
	int i;
	for (; srv != NULL; srv = srv->next) {
		printf(": %s:%d (prio=%d; weight=%d; ttl=%d)\n", srv->host, srv->port, srv->priority, srv->weight, srv->ttl);
	}
	return;
}

static void callback_txt(ev_ares_result_txt * res) {
	printf("Result for TXT '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_txt_reply* r = res->txt;
	for (; r != NULL; r = r->next) {
		printf(": %s (ttl=%d)\n", r->txt, r->ttl);
	}
	return;
}

static void callback_ptr(ev_ares_result_ptr * res) {
	printf("Result for PTR '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_ptr_reply* r = res->ptr;
	for (; r != NULL; r = r->next) {
		printf(": %s; ttl=%d\n",r->host,r->ttl);
	}
}

static void callback_naptr(ev_ares_result_naptr * res) {
	printf("Result for NAPTR '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	struct ev_ares_naptr_reply* r = res->naptr;
	for (; r != NULL; r = r->next) {
		printf(": flags=%s, service=%s, re=%s, repl=%s order=%d pref=%d\n",
		r->flags, r->service, r->regexp, r->replacement, r->order, r->preference);
	}
}

static void callback_hba(ev_ares_result_hba * res) {
	printf("Result for hostbyaddr '%s': %s\n",res->query, res->error);
	if (res->status != ARES_SUCCESS) return;
	int i = 0;
	for (i = 0; res->hosts->h_aliases[i]; ++i) {
		printf(": %s\n", res->hosts->h_aliases[i]);
	}
	return;
}

#define JSRV "_xmpp-client._tcp."

int main (int argc, char *argv[]) {
	struct ev_loop *loop = EV_DEFAULT;
	
	if (argc < 2) { fprintf(stderr, "Usage:\n\t%s domain\n",argv[0]); return 1; }
	char *hostname = argv[1];
	char *jabber = calloc(1,strlen(argv[1]) + strlen(JSRV) + 1); // will be freed on exit ;)
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
	
	ev_ares_soa(loop,&resolver,hostname,0,callback_soa);
	
	ev_ares_ns(loop,&resolver,hostname,0,callback_ns);
	
	ev_ares_a(loop,&resolver,hostname,0,callback_a);
	ev_ares_aaaa(loop,&resolver,hostname,0,callback_aaaa);
	
	ev_ares_mx(loop,&resolver,hostname,0,callback_mx);
	
	ev_ares_srv(loop,&resolver,jabber,0,callback_srv);
	ev_ares_txt(loop,&resolver,hostname,0,callback_txt);
	
	ev_ares_gethostbyaddr(loop,&resolver,"8.8.8.8", 0, callback_hba);
	ev_ares_gethostbyaddr(loop,&resolver,"2a00:1450:4010:c04::66", 0,callback_hba);
	
	// Raw PTR queries
	ev_ares_ptr(loop,&resolver,"8.8.8.8.in-addr.arpa", 0,callback_ptr);
	ev_ares_ptr(loop,&resolver,"a.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.c.0.0.1.0.4.0.5.4.1.0.0.a.2.ip6.arpa", 0,callback_ptr);
	
	//This is the only NAPTR example i found ;)
	ev_ares_naptr(loop,&resolver,"0.2.0.1.1.6.5.1.0.3.1.loligo.com.",0,callback_naptr);
	
	// Run loop
	ev_run (loop, 0);
	
	free(jabber);
	ev_ares_clean(&resolver);
	ares_library_cleanup();
}

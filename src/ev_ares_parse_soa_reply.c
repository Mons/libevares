#include "ares_dns.h"

static int ev_ares_free_soa_reply(struct ev_ares_soa_reply * reply) {
	if (!reply) return;
	if (reply->nsname) free(reply->nsname);
	if (reply->hostmaster) free(reply->hostmaster);
	free(reply);
}

static int
ev_ares_parse_soa_reply(const unsigned char *abuf, int alen,
                       struct ev_ares_soa_reply **soa_out)
{
  const unsigned char *aptr;
  long len;
  char *qname = NULL, *rr_name = NULL;
  struct ev_ares_soa_reply *soa = NULL;
  int qdcount, ancount;
  int status;
  int rr_ttl;

  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* parse message header */
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  if (qdcount != 1 || ancount != 1)
    return ARES_EBADRESP;
  aptr = abuf + HFIXEDSZ;

  /* query name */
  status = ares_expand_name(aptr, abuf, alen, &qname, &len);
  if (status != ARES_SUCCESS)
    goto failed_stat;
  aptr += len;

  /* skip qtype & qclass */
  if (aptr + QFIXEDSZ > abuf + alen)
    goto failed;
  aptr += QFIXEDSZ;

  /* rr_name */
  status = ares_expand_name(aptr, abuf, alen, &rr_name, &len);
  if (status != ARES_SUCCESS)
    goto failed_stat;
  aptr += len;

  /* skip rr_type, rr_class, rr_ttl, rr_rdlen */
  if (aptr + RRFIXEDSZ > abuf + alen)
    goto failed;

  rr_ttl = DNS_RR_TTL(aptr);

  aptr += RRFIXEDSZ;

  /* allocate result struct */
  soa = calloc(1,sizeof(struct ev_ares_soa_reply));
  if (!soa)
    return ARES_ENOMEM;
  
  soa->ttl = rr_ttl;
  
  /* nsname */
  status = ares_expand_name(aptr, abuf, alen, &soa->nsname, &len);
  if (status != ARES_SUCCESS)
    goto failed_stat;
  aptr += len;

  /* hostmaster */
  status = ares_expand_name(aptr, abuf, alen, &soa->hostmaster, &len);
  if (status != ARES_SUCCESS)
    goto failed_stat;
  aptr += len;

  /* integer fields */
  if (aptr + 5 * 4 > abuf + alen)
    goto failed;
  soa->serial = DNS__32BIT(aptr + 0 * 4);
  soa->refresh = DNS__32BIT(aptr + 1 * 4);
  soa->retry = DNS__32BIT(aptr + 2 * 4);
  soa->expire = DNS__32BIT(aptr + 3 * 4);
  soa->minttl = DNS__32BIT(aptr + 4 * 4);

  free(qname);
  free(rr_name);

  *soa_out = soa;

  return ARES_SUCCESS;

failed:
  status = ARES_EBADRESP;

failed_stat:
  ev_ares_free_soa_reply(soa);
  if (qname)
    free(qname);
  if (rr_name)
    free(rr_name);
  return status;
}


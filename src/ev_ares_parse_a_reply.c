#include "ares_dns.h"

static void ev_ares_free_a_reply(struct ev_ares_a_reply *reply) {
	struct ev_ares_a_reply* next;
	for (;reply;) {
		if (reply->host) free(reply->host);
		next = reply->next;
		free(reply);
		reply = next;
	}
}

static int
ev_ares_parse_a_reply (const unsigned char *abuf, int alen,
                        struct ev_ares_a_reply **a_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len, rr_ttl, cname_ttl = INT_MAX;
  int naddrs = 0, naliases = 0;
  long len;
  char *hostname = NULL, *rr_name = NULL, *rr_data = NULL;
  struct ev_ares_a_reply *a_head = NULL;
  struct ev_ares_a_reply *a_last = NULL;
  struct ev_ares_a_reply *a_curr;

  /* Set *a_out to NULL for all failure cases. */
  *a_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT (abuf);
  ancount = DNS_HEADER_ANCOUNT (abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0)
    return ARES_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares_expand_name (aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      free (hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares_expand_name (aptr, abuf, alen, &rr_name, &len);
      //cwarn("expanded name: %s",rr_name);
      if (status != ARES_SUCCESS)
        {
          break;
        }
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE (aptr);
      rr_class = DNS_RR_CLASS (aptr);
      rr_ttl = DNS_RR_TTL (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a A record */
      if (rr_class == C_IN && rr_type == T_A) {
        if ( rr_len == sizeof(struct in_addr) && strcasecmp(rr_name, hostname) == 0 ) {
          if (aptr + sizeof(struct in_addr) > abuf + alen) {
            status = ARES_EBADRESP;
            break;
          }
          a_curr = calloc(1,sizeof(struct ev_ares_a_reply));
          if (!a_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (a_last)
            {
              a_last->next = a_curr;
            }
          else
            {
              a_head = a_curr;
            }
          a_last = a_curr;

          a_curr->ttl = rr_ttl;
          a_curr->host = rr_name;
          rr_name = NULL;
          memcpy(&a_curr->ip, aptr, sizeof(struct in_addr));
          naddrs++;
        }
      }
      else
      if (rr_class == C_IN && rr_type == T_CNAME) {
        naliases++;
        
        status = ares_expand_name(aptr, abuf, alen, &rr_data, &len);
        if (status != ARES_SUCCESS)
          break;
        
        if (cname_ttl > rr_ttl)
          cname_ttl = rr_ttl;
        
        free(hostname);
        hostname = rr_data;
      }
      if (rr_name)
        free(rr_name);
      rr_name = NULL;

      /* Move on to the next record */
      aptr += rr_len;
    }

  if (hostname)
    free (hostname);
  if (rr_name)
    free (rr_name);

  if (status == ARES_SUCCESS && naddrs == 0 && naliases == 0)
    /* the check for naliases to be zero is to make sure CNAME responses
       don't get caught here */
    status = ARES_ENODATA;

  /* clean up on error */
  if (status == ARES_SUCCESS)
    {
      if (naliases > 0) {
        for (a_curr = a_head;a_curr;a_curr = a_curr->next)
          {
            if (a_curr->ttl > cname_ttl)
              a_curr->ttl = cname_ttl;
          }
      }
    }
  else
    {
      if (a_head)
        ev_ares_free_a_reply (a_head);
      return status;
    }

  /* everything looks fine, return the data */
  *a_out = a_head;

  return ARES_SUCCESS;
}

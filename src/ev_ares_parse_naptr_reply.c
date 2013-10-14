#include "ares_dns.h"

#ifndef T_NAPTR
	#define T_NAPTR 35 /* naming authority pointer */
#endif

static void ev_ares_free_naptr_reply(struct ev_ares_naptr_reply *reply) {
	struct ev_ares_naptr_reply* next;
	for (;reply;) {
		if (reply->flags) free(reply->flags);
		if (reply->service) free(reply->service);
		if (reply->regexp) free(reply->regexp);
		if (reply->replacement) free(reply->replacement);
		next = reply->next;
		free(reply);
		reply = next;
	}
}


static int
ev_ares_parse_naptr_reply (const unsigned char *abuf, int alen,
                           struct ev_ares_naptr_reply **naptr_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len, rr_ttl;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ev_ares_naptr_reply *naptr_head = NULL;
  struct ev_ares_naptr_reply *naptr_last = NULL;
  struct ev_ares_naptr_reply *naptr_curr;

  /* Set *naptr_out to NULL for all failure cases. */
  *naptr_out = NULL;

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
      rr_ttl = DNS_RR_TTL(aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a NAPTR record */
      if (rr_class == C_IN && rr_type == T_NAPTR)
        {
          /* parse the NAPTR record itself */

          /* Allocate storage for this NAPTR answer appending it to the list */
          naptr_curr = calloc(1,sizeof(struct ev_ares_naptr_reply));
          if (!naptr_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (naptr_last)
            {
              naptr_last->next = naptr_curr;
            }
          else
            {
              naptr_head = naptr_curr;
            }
          naptr_last = naptr_curr;

          vptr = aptr;
          naptr_curr->ttl = rr_ttl;
          naptr_curr->order = DNS__16BIT(vptr);
          vptr += sizeof(unsigned short);
          naptr_curr->preference = DNS__16BIT(vptr);
          vptr += sizeof(unsigned short);

          status = ares_expand_string(vptr, abuf, alen, &naptr_curr->flags, &len);
          if (status != ARES_SUCCESS)
            break;
          vptr += len;

          status = ares_expand_string(vptr, abuf, alen, &naptr_curr->service, &len);
          if (status != ARES_SUCCESS)
            break;
          vptr += len;

          status = ares_expand_string(vptr, abuf, alen, &naptr_curr->regexp, &len);
          if (status != ARES_SUCCESS)
            break;
          vptr += len;

          status = ares_expand_name(vptr, abuf, alen, &naptr_curr->replacement, &len);
          if (status != ARES_SUCCESS)
            break;
        }

      /* Don't lose memory in the next iteration */
      free (rr_name);
      rr_name = NULL;

      /* Move on to the next record */
      aptr += rr_len;
    }

  if (hostname)
    free (hostname);
  if (rr_name)
    free (rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      if (naptr_head)
        ev_ares_free_naptr_reply (naptr_head);
      return status;
    }

  /* everything looks fine, return the data */
  *naptr_out = naptr_head;

  return ARES_SUCCESS;
}


#include "ares_dns.h"

static void ev_ares_free_mx_reply(struct ev_ares_mx_reply *reply) {
	struct ev_ares_mx_reply* next;
	for (;reply;) {
		if (reply->host) free(reply->host);
		next = reply->next;
		free(reply);
		reply = next;
	}
}

static int
ev_ares_parse_mx_reply (const unsigned char *abuf, int alen,
                        struct ev_ares_mx_reply **mx_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len, rr_ttl;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ev_ares_mx_reply *mx_head = NULL;
  struct ev_ares_mx_reply *mx_last = NULL;
  struct ev_ares_mx_reply *mx_curr;

  /* Set *mx_out to NULL for all failure cases. */
  *mx_out = NULL;

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
      rr_ttl = DNS_RR_TTL (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a MX record */
      if (rr_class == C_IN && rr_type == T_MX)
        {
          /* parse the MX record itself */
          if (rr_len < 2)
            {
              status = ARES_EBADRESP;
              break;
            }

          /* Allocate storage for this MX answer appending it to the list */
          mx_curr = calloc(1,sizeof(struct ev_ares_mx_reply));
          if (!mx_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (mx_last)
            {
              mx_last->next = mx_curr;
            }
          else
            {
              mx_head = mx_curr;
            }
          mx_last = mx_curr;

          mx_curr->ttl = rr_ttl;
          vptr = aptr;
          mx_curr->priority = DNS__16BIT(vptr);
          vptr += sizeof(unsigned short);

          status = ares_expand_name (vptr, abuf, alen, &mx_curr->host, &len);
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
      if (mx_head)
        ev_ares_free_mx_reply (mx_head);
      return status;
    }

  /* everything looks fine, return the data */
  *mx_out = mx_head;

  return ARES_SUCCESS;
}

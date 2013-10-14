#include "ares_dns.h"

static void ev_ares_free_txt_reply(struct ev_ares_txt_reply *reply) {
	struct ev_ares_txt_reply* next;
	for (;reply;) {
		if (reply->txt) free(reply->txt);
		next = reply->next;
		free(reply);
		reply = next;
	}
}

static int
ev_ares_parse_txt_reply (const unsigned char *abuf, int alen,
                         struct ev_ares_txt_reply **txt_out)
{
  size_t substr_len;
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr;
  const unsigned char *strptr;
  int status, rr_type, rr_class, rr_len, rr_ttl;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ev_ares_txt_reply *txt_head = NULL;
  struct ev_ares_txt_reply *txt_last = NULL;
  struct ev_ares_txt_reply *txt_curr;

  /* Set *txt_out to NULL for all failure cases. */
  *txt_out = NULL;

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

      /* Check if we are really looking at a TXT record */
      if (rr_class == C_IN && rr_type == T_TXT)
        {
          /*
           * There may be multiple substrings in a single TXT record. Each
           * substring may be up to 255 characters in length, with a
           * "length byte" indicating the size of the substring payload.
           * RDATA contains both the length-bytes and payloads of all
           * substrings contained therein.
           */

          strptr = aptr;
          while (strptr < (aptr + rr_len))
            {
              substr_len = (unsigned char)*strptr;
              if (strptr + substr_len + 1 > aptr + rr_len)
                {
                  status = ARES_EBADRESP;
                  break;
                }

              ++strptr;

              /* Allocate storage for this TXT answer appending it to the list */
              txt_curr = calloc(1,sizeof(struct ev_ares_txt_reply));
              if (!txt_curr)
                {
                  status = ARES_ENOMEM;
                  break;
                }
              if (txt_last)
                {
                  txt_last->next = txt_curr;
                }
              else
                {
                  txt_head = txt_curr;
                }
              txt_last = txt_curr;

              txt_curr->ttl = rr_ttl;
              txt_curr->length = substr_len;
              txt_curr->txt = malloc (substr_len + 1/* Including null byte */);
              if (txt_curr->txt == NULL)
                {
                  status = ARES_ENOMEM;
                  break;
                }
              memcpy ((char *) txt_curr->txt, strptr, substr_len);

              /* Make sure we NULL-terminate */
              txt_curr->txt[substr_len] = 0;

              strptr += substr_len;
            }
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
      if (txt_head)
        ev_ares_free_txt_reply (txt_head);
      return status;
    }

  /* everything looks fine, return the data */
  *txt_out = txt_head;

  return ARES_SUCCESS;
}

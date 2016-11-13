/* Sniffit hostname resolving part                                       */
/*  - getaddrbyname: Godmar Back / Shudoh Kazuyuki                       */

#include "sn_defines.h"
#include <netdb.h>
#include <arpa/inet.h>

_32_bit getaddrbyname (const char *name)
{
  _32_bit ret;
  struct hostent *he;

  if ((ret = inet_addr (name)) != INADDR_NONE)
    {				/* dotted-decimal */
      return ret;
    }
  else
    {
      if (!(he = gethostbyname (name)))
	{
#ifdef DEBUG
	  debug_msg ("GetAddr: Couldn't get host.");
#endif
	  /* perror(name); */
	}

      return he ? *(_32_bit *) *he->h_addr_list : 0;
    }
}

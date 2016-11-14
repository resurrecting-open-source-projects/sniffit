/* Sniffit Packet Discription File                                        */
/*   - by: Brecht Claerhout                            */

#include "sn_config.h"
#include "sn_defines.h"
#include "sn_structs.h"
#include <string.h>
#include <netinet/in.h>

extern int PROTO_HEAD;
extern char NO_CHKSUM;

/* This routine stolen from ping.c */
unsigned short in_cksum(unsigned short *addr,int len)
{
register int nleft = len;   /* leave this alone.. my opinion is that the   */
register unsigned short *w = addr;
                            /* register is needed to make it work for both */
register int sum = 0;       /* BIG and LITTLE endian machines              */
unsigned short answer = 0;
                        /* but then again, who am I to make such statement */

while (nleft > 1)
        {
        sum += *w++;
        nleft -= 2;
        }
if (nleft == 1)
        {
        *(unsigned char *)(&answer) = *(unsigned char *)w ;
        sum += answer;
        }
sum = (sum >> 16) + (sum & 0xffff);
sum += (sum >> 16);
answer = ~sum;
return(answer);
}

int unwrap_packet (unsigned char *sp, struct unwrap *unwrapped)
{
	struct IP_header  IPhead;
	struct TCP_header TCPhead;
	struct ICMP_header ICMPhead;
	struct UDP_header UDPhead;

	int i;
 	short int dummy; /* 2 bytes, important */

        /*
        printf("\n");
        for(i=0;i<20;i++)  printf("%X ",sp[i]);
        printf("\n");
        */
	memcpy(&IPhead,(sp+PROTO_HEAD),sizeof(struct IP_header));
                                                  /* IP header Conversion */
 	unwrapped->IP_len = (IPhead.verlen & 0xF) << 2;

	unwrapped->TCP_len = 0;         	/* Reset structure NEEDED!!! */
	unwrapped->UDP_len = 0;
        unwrapped->DATA_len= 0;
	unwrapped->FRAG_f  = 0;
	unwrapped->FRAG_nf = 0;

	if(NO_CHKSUM == 0)
		{
		sp[PROTO_HEAD+10]=0;       /* reset checksum to zero, Q&D way*/
		sp[PROTO_HEAD+11]=0;
		if(in_cksum((sp+PROTO_HEAD),unwrapped->IP_len) != IPhead.checksum)
			{
#ifdef DEBUG_ONSCREEN
			printf("Packet dropped... (invalid IP chksum)\n");
			printf("%X   %X (len %d)\n",in_cksum((sp+PROTO_HEAD),unwrapped->IP_len),IPhead.checksum,unwrapped->IP_len);
#endif
			return NO_IP;
			}
		if(0)
			{
#ifdef DEBUG_ONSCREEN
			printf("Packet dropped... (invalid IP version)\n");
#endif
			return NO_IP_4;
			}
		memcpy((sp+PROTO_HEAD),&IPhead,sizeof(struct IP_header));
					/* restore orig buffer      */
        			 	/* general programming rule */
		}

#ifdef DEBUG_ONSCREEN
	printf("IPheadlen: %d   total length: %d\n", unwrapped->IP_len,
						    ntohs(IPhead.length));
#endif

        dummy=ntohs(IPhead.flag_offset); dummy<<=3;
        if( dummy!=0 )                            /* we have offset */
		{
		unwrapped->FRAG_nf = 1;
                }
        dummy=ntohs(IPhead.flag_offset); dummy>>=13;
        if( (dummy&IP_MF)&&(unwrapped->FRAG_nf==0) ) /* first frag */
		{
		unwrapped->FRAG_f = 1;
                }

	if(IPhead.protocol == TCP )		             /* TCP */
		{
                if(unwrapped->FRAG_nf == 0)   /* packet contains TCP header */
                  {
		  if( (ntohs(IPhead.length)-(unwrapped->IP_len))<20 )
		    {
		    if(unwrapped->FRAG_f==1)
	              {unwrapped->DATA_len = ntohs(IPhead.length) -
                                                         (unwrapped->IP_len);
                       if(unwrapped->DATA_len<0)
                         {unwrapped->DATA_len=0; return CORRUPT_IP;}
                       return TCP_FRAG_HEAD;
                      }
                    else
                      {return CORRUPT_IP;}
                    }

		  memcpy(&TCPhead,(sp+PROTO_HEAD+(unwrapped->IP_len)),
						sizeof(struct TCP_header));
		  unwrapped->TCP_len = ntohs(TCPhead.offset_flag) & 0xF000;
		  unwrapped->TCP_len >>= 10;
		  unwrapped->DATA_len = ntohs(IPhead.length) -
				(unwrapped->IP_len) - (unwrapped->TCP_len);

                  /* IP options can not cause SEGFAULT */
                  if(unwrapped->DATA_len<0) /* Fragmented TCP options */
                    {
		    if(unwrapped->FRAG_f==1)
                      {unwrapped->TCP_len=0;
                       unwrapped->DATA_len = ntohs(IPhead.length) -
                                                      (unwrapped->IP_len);
                       if(unwrapped->DATA_len<0)
                         {unwrapped->DATA_len=0; return CORRUPT_IP;}
                       return TCP_FRAG_HEAD;
                      }
                    else
                      {return CORRUPT_IP;}
                    }
                  }
                else
                  {
		  unwrapped->DATA_len = ntohs(IPhead.length) - (unwrapped->IP_len);
                  if(unwrapped->DATA_len<0)
                         {unwrapped->DATA_len=0; return CORRUPT_IP;}
                  }
		return TCP;
		}
	if(IPhead.protocol == ICMP )		             /* ICMP */
		{
                if(unwrapped->FRAG_nf == 0) /* Should contain header */
                  {
		  if( (ntohs(IPhead.length)-(unwrapped->IP_len))<4 )
		    {return NOT_SUPPORTED;}; /* no handling of frag headers*/

		  memcpy(&ICMPhead,(sp+PROTO_HEAD+(unwrapped->IP_len)),
						sizeof(struct ICMP_header));
		  unwrapped->ICMP_len = ICMP_HEADLENGTH;
		  unwrapped->DATA_len = ntohs(IPhead.length) -
				(unwrapped->IP_len) - (unwrapped->ICMP_len);

                  if(unwrapped->DATA_len<0)
                    {
		    if(unwrapped->FRAG_f==1)
                      {unwrapped->TCP_len=0;
                       unwrapped->DATA_len = ntohs(IPhead.length) -
                                                      (unwrapped->IP_len);
                       if(unwrapped->DATA_len<0)
                         {unwrapped->DATA_len=0; return CORRUPT_IP;}
                       return NOT_SUPPORTED;  /* don't handle fragmented ICMP */
                      }
                    else
                      {return CORRUPT_IP;}
                    }
                  return ICMP;
		  }
                else
                  {
                  return NOT_SUPPORTED; /* don't handle fragmented ICMP */
                  }
		}
	if(IPhead.protocol == UDP )		               /* UDP */
		{
                if(unwrapped->FRAG_nf == 0)
                  {
		  if( ((IPhead.length)-(unwrapped->IP_len))<8 )
		    {return NOT_SUPPORTED;}; /* don't handle frag. header */

  		  memcpy(&UDPhead,(sp+PROTO_HEAD+(unwrapped->IP_len)),
						sizeof(struct UDP_header));
		  unwrapped->UDP_len = UDP_HEADLENGTH;
		  unwrapped->DATA_len = ntohs(IPhead.length) -
				(unwrapped->IP_len) - (unwrapped->UDP_len);

                  if(unwrapped->DATA_len<0)
                    {
		    if(unwrapped->FRAG_f==1)
                      {unwrapped->UDP_len=0;
                       unwrapped->DATA_len = ntohs(IPhead.length) -
                                                      (unwrapped->IP_len);
                       if(unwrapped->DATA_len<0)
                         {unwrapped->DATA_len=0; return CORRUPT_IP;}
                       return NOT_SUPPORTED;
                      } /* don't handle fragmented UDP */
                    else
                      {return CORRUPT_IP;}
                    }
                  return UDP;
                  }
                else
		  {
                  return NOT_SUPPORTED; /* don't handle fragmented UDP */
                  }
		}
	return NOT_SUPPORTED;
}



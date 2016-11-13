/* Sniffit Packet Discription File                                        */
/*   - by: Brecht Claerhout                            */

#include "sn_config.h"
#include "sn_defines.h"
#include "sn_structs.h"
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

	memcpy(&IPhead,(sp+PROTO_HEAD),sizeof(struct IP_header));
                                                  /* IP header Conversion */
 	unwrapped->IP_len = (IPhead.verlen & 0xF) << 2;
	
	unwrapped->TCP_len = 0;         	/* Reset structure NEEDED!!! */
	unwrapped->UDP_len = 0;
	unwrapped->DATA_len = 0;
        
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
	if(IPhead.protocol == TCP )		             /* TCP */
		{
		memcpy(&TCPhead,(sp+PROTO_HEAD+(unwrapped->IP_len)),
						sizeof(struct TCP_header));
		unwrapped->TCP_len = ntohs(TCPhead.offset_flag) & 0xF000;
		unwrapped->TCP_len >>= 10; 
		unwrapped->DATA_len = ntohs(IPhead.length) -
				(unwrapped->IP_len) - (unwrapped->TCP_len); 
		return TCP;
		}
	if(IPhead.protocol == ICMP )		             /* ICMP */
		{
		memcpy(&ICMPhead,(sp+PROTO_HEAD+(unwrapped->IP_len)),
						sizeof(struct ICMP_header));
		unwrapped->ICMP_len = ICMP_HEADLENGTH;
		unwrapped->DATA_len = ntohs(IPhead.length) -
				(unwrapped->IP_len) - (unwrapped->ICMP_len); 
		return ICMP; 
		}
	if(IPhead.protocol == UDP )		               /* UDP */
		{
		memcpy(&UDPhead,(sp+PROTO_HEAD+(unwrapped->IP_len)),
						sizeof(struct UDP_header));
		unwrapped->UDP_len = UDP_HEADLENGTH;
		unwrapped->DATA_len = ntohs(IPhead.length) -
				(unwrapped->IP_len) - (unwrapped->UDP_len); 
		return UDP; 
		}
	return -1; 
}



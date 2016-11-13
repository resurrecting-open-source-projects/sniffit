/* Sniffit Packets include file                                                      */

#ifndef _SN_PACKETS_H_
#define _SN_PACKETS_H_

unsigned short in_cksum(unsigned short *,int);
int unwrap_packet (const unsigned char *, struct unwrap *);

#endif

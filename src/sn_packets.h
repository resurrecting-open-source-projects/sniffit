/* Sniffit Packets include file                                                      */

#ifndef _SN_PACKETS_H_
#define _SN_PACKETS_H_

extern unsigned short in_cksum(const unsigned char *,int);
extern int unwrap_packet (const unsigned char *, struct unwrap *);

#endif

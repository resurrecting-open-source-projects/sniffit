/* Sniffit Packet Discription File                             */

#ifndef _SN_PACKETSTRUCTS_H_
#define _SN_PACKETSTRUCTS_H_

#include <sys/time.h>

struct packetheader
{
        struct timeval ts;      /* time stamp */
        unsigned long caplen;          /* length of portion present */
        unsigned long len;             /* length this packet (off wire) */
};

struct IP_header                        /* The IPheader (without options) */
{
	unsigned char verlen, type;
	unsigned short length, ID, flag_offset;
	unsigned char TTL, protocol;
	unsigned short checksum;
	_32_bit source, destination;
};

struct pseudo_IP_header
{
        _32_bit source, destination;
        char zero_byte, protocol;
        unsigned short TCP_UDP_len;
};

struct TCP_header                       /* The TCP header (without options) */
{
	unsigned short source, destination;
	_32_bit seq_nr, ACK_nr;
	unsigned short offset_flag, window, checksum, urgent;
};

struct ICMP_header                                /* The ICMP header */
{
	unsigned char type, code;
	unsigned short checksum;
};

struct UDP_header                                /* The UDP header */
{
	unsigned short source, destination;
	unsigned short length, checksum;
};

struct unwrap                                          /* some extra info */
{
	int IP_len, TCP_len, ICMP_len, UDP_len;         /* header lengths */
	int DATA_len;                                     /* keep signed! */
	char FRAG_f;                                    /* first fragment */
	char FRAG_nf;                           /* not the first fragment */
};


#endif
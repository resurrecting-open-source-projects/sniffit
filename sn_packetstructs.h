/* Sniffit Packet Discription File                             */

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
	unsigned long int source, destination;
};

struct pseudo_IP_header 
{
        unsigned long int source, destination;
        char zero_byte, protocol;
        unsigned short TCP_UDP_len;
};            

struct TCP_header                       /* The TCP header (without options) */
{
	unsigned short source, destination;
	unsigned long int seq_nr, ACK_nr;
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

struct unwrap                                           /* some extra info */
{
	int IP_len, TCP_len, ICMP_len, UDP_len;         /* header lengths */ 
	int DATA_len;
};

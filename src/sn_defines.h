/* Sniffit Defines File                                                    */

#include "sn_config.h"

/*** typedefs ******************/

#ifdef USE_32_LONG_INT
typedef unsigned long int _32_bit;
#endif
#ifdef USE_32_INT
typedef unsigned int _32_bit;
#endif
typedef unsigned short _16_bit;

/*** Normal Sniffit operations */

#define VERSION   "0.4.0"                          /* Program Version */
#define SNAPLEN   MTU                            /* Ethernet Packet Length */
#define MSDELAY   1000                                     /* pcap timeout */
#define PACKETS   1					  /* pcap dispatch */
#define CNT	  -1                                    /* pcap loop count */
#define LENGTH_OF_INTERPROC_DATA	5*SNAPLEN       /* buffer capacity */
#define SCBUF     30			           /* scroll buffer length */
#define LOG_PASS_BUF  20+1	                /* login/pwd buffer length */
#define TELNET_ENTER	0x0d		 /* Enter in telnet login session  */
#define FTP_ENTER	0x0d  /* first char of Enter in FTP login session  */
 
#define DEST        0
#define SOURCE      1
#define BOTH        2
#define INTERACTIVE 99

/* Packet examining defines (finish) */
/* 	0-9  : TCP	*/
/* 	10-19: ICMP	*/
/* 	20-29: UDP      */
#define DROP_PACKET		-2		/* Skip Packet completely */
#define DONT_EXAMINE		-1		/* Skip Packet */
#define TCP_EXAMINE		0		/* TCP - 'for us' */
#define TCP_FINISH		1		/* TCP - end connection */
#define TCP_EX_FRAG_HEAD	2               /* defined lower */
#define TCP_EX_FRAG_NF		3
#define ICMP_EXAMINE		10		/* ICMP - examine */
#define UDP_EXAMINE		20		/* UDP - examine */

#define F_TCP		1			/* Flags for PROTOCOLS */
#define F_ICMP		2
#define F_UDP		4
#define F_IP            8

/*** Logparam defines */

#define	LOGPARAM_LOG_ON		1
#define	LOGPARAM_RAW		2
#define LOGPARAM_NORM		4
#define LOGPARAM_TELNET		8
#define LOGPARAM_FTP		16
#define LOGPARAM_MAIL		32

/*** Interface defines */

#ifdef INCLUDE_INTERFACE
#define ENTER 13

#define WIN_COLOR_NORMAL 	1    /* Color pairs for various functions */
#define WIN_COLOR_POINT  	2
#define WIN_COLOR_DATA   	3
#define WIN_COLOR_INPUT  	4
#define WIN_COLOR_MENU  	5
#define WIN_COLOR_PACKET_INFO	6
#define WIN_COLOR_PKTCNT	7

#define CONN_NAMELEN         56     /* length of string      */
#define DESC_BYTES           60     /* length of description */

#define MENU " Masks: F1-Source IP  F2-Dest. IP  F3-Source Port  F4-Dest. Port"
#endif

/* First undefine all Plugins, just to be sure */

#undef PLUGIN0_NAME
#undef PLUGIN1_NAME
#undef PLUGIN2_NAME
#undef PLUGIN3_NAME
#undef PLUGIN4_NAME
#undef PLUGIN5_NAME
#undef PLUGIN6_NAME
#undef PLUGIN7_NAME
#undef PLUGIN8_NAME
#undef PLUGIN9_NAME


#define	IP_VERSION	4

#define URG 32       /*TCP-flags */
#define ACK 16
#define PSH 8
#define RST 4
#define SYN 2
#define FIN 1

/* unwrap packet */
#define NOT_SUPPORTED	-1
#define NO_IP   	0
#define NO_IP_4 	1000
#define CORRUPT_IP	1001
#define TCP_FRAG_HEAD	1002
#define UDP_FRAG_HEAD	1003
#define ICMP_FRAG_HEAD	1004
#define ICMP    	1                       /* Protocol Numbers */
#define TCP     	6
#define UDP     	17

#define ICMP_HEADLENGTH 4               /* fixed ICMP header length */
#define UDP_HEADLENGTH  8               /* fixed UDP header length */

#define IP_DELAY        32
#define IP_THROUGHPUT   16
#define IP_RELIABILITY  8

#define IP_DF   2
#define IP_MF   1                         

/*** ICMP types ********************************************************/
#define ICMP_TYPE_0     "Echo reply"
#define ICMP_TYPE_3     "Destination unreachable"
#define ICMP_TYPE_4     "Source quench"
#define ICMP_TYPE_5     "Redirect"
#define ICMP_TYPE_8     "Echo"
#define ICMP_TYPE_11    "Time exceeded"
#define ICMP_TYPE_12    "Parameter problem"
#define ICMP_TYPE_13    "Timestamp"
#define ICMP_TYPE_14    "Timestamp reply"
#define ICMP_TYPE_15    "Information request"
#define ICMP_TYPE_16    "Information reply"
#define ICMP_TYPE_17    "Address mask request"
#define ICMP_TYPE_18    "Address mask reply"
                                               
/*** Services (standardised) *******************************************/
#define FTP_DATA_1	20
#define FTP_1		21
#define SSH_1	 	22
#define TELNET_1	23
#define MAIL_1		25
#define IDENT_1		113	
#define HTTP_1		80	
#define HTTP_2		80	
#define HTTP_3		80	
#define HTTP_4		80	
#define IRC_1		6667	
#define X11_1		6000	


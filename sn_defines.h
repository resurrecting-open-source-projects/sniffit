/* Sniffit Defines File                                                         */

#include "sn_config.h"

/*** Normal Sniffit operations */

#define VERSION   "0.3.5"                               /* Program Version */
#define SNAPLEN   MTU                            /* Ethernet Packet Length */
#define MSDELAY   0                               /* Delay between Packets */
#define PACKETS   1                       /* Number of packets to dispatch */
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
#define DONT_EXAMINE	-1			/* Skip Packet */
#define TCP_EXAMINE	0			/* TCP - 'for us' */
#define TCP_FINISH	1			/* TCP - end connection */
#define ICMP_EXAMINE	10			/* ICMP - examine */
#define UDP_EXAMINE	20			/* UDP - examine */

#define F_TCP		1			/* Flags for PROTOCOLS */
#define F_ICMP		2
#define F_UDP		4
#define F_IP            8

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

#define CONN_NAMELEN         56    /* length of string */

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


/***************************** Packet Defines  ****************************/
#define ETHERHEAD 14    /* Length Ethernet Packet header */
#define PPPHEAD 4       /* Length PPP Packet header */
#define SLIPHEAD 16     /* Length SLIP Packet header */

#define	IP_VERSION	4

#define URG 32       /*TCP-flags */
#define ACK 16
#define PSH 8
#define RST 4
#define SYN 2
#define FIN 1

#define NO_IP   0
#define NO_IP_4 1000
#define ICMP    1                       /* Protocol Numbers */
#define TCP     6
#define UDP     17

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
#define ICMP_TYPE_18    "Adress mask reply"
                                               

/* Sniffit Defines File -- Brecht Claerhout                                */

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "pcap.h"

/* Ethernet Device */

#ifdef LINUX
#define	ETH_DEV	"eth"
#endif
#ifdef SUNOS
#define	ETH_DEV	"le"
#endif
#ifdef IRIX
#define	ETH_DEV	"et"
#endif

#ifdef INCLUDE_INTERFACE
#include <ncurses/ncurses.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

/*** Normal Sniffit operations */

#define VERSION   "0.2.2"                 /* Program Version */
#define SNAPLEN   1500                    /* Ethernet Packet Length */
#define MSDELAY   0                       /* Delay between Packets */
#define PACKETS   1                       /* Number of packets to dispatch */
#define LENGTH_OF_INTERPROC_DATA	5*1500  /* buffer capacity */

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

#define CONN_NAMELEN         55    /* length of string */

#define MENU " Masks: F1-Source IP  F2-Dest. IP  F3-Source Port  F4-Dest. Port"
#endif



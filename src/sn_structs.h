/* Sniffit Structs File                                                       */

#ifndef _SN_STRUCTS_H_
#define _SN_STRUCTS_H_

#include <stdio.h>
#include "sn_packetstructs.h"

/**** Global data **********************************************************/
struct file_info
{
        char proto, filename[50];
        FILE *f;
        unsigned long bytes;
        _32_bit exp_seq;     /* expected seq to avoid double logging */
	int time_out;
	char log;                      /* log=0  : do nothing        */
	                               /* log=1  : log 'login'       */
	                               /* log=2  : 'login' logged    */
	                               /* log=3  : log password      */
	                               /* log=4  : password logged   */
	                               /* log=99 : no more detection */
	char scroll_buf[SCBUF+1];                  /* scroll buffer */
	char *buffer;			     /* pointer to a buffer */
	struct file_info *next;
};

/**** Global data (config) **************************************************/
struct cfg_file_contense
{
char host[16];
unsigned int priority;
unsigned char wildcard;
unsigned short port;
};

/**** Global data (plugins) *************************************************/
struct Plugin_data {
	struct unwrap PL_info;
	struct IP_header PL_iphead;
	struct TCP_header PL_tcphead;
	struct UDP_header PL_udphead;
	unsigned char PL_data[MTU];
	unsigned char PL_packet[MTU];
};

/**** Global data (interactive) *********************************************/
#ifdef INCLUDE_INTERFACE
#include "sn_curses.h"

struct box_window
{
	WINDOW *main_window, *work_window;
};


struct shared_conn_data           /* shared memory connection datastructure */
  {
  char connection [CONN_NAMELEN];                 /* full ID string of conn */
  char desc [DESC_BYTES];                         /* connection description */
  int timeout;
  };
struct shared_logged_conn            /* shared memory logging datastructure */
  {
  char log_enter [CONN_NAMELEN];                          /* normal logging */
  };
struct snif_mask                                         /* struct for mask */
  {
  _32_bit source_ip, destination_ip;
  _16_bit source_port, destination_port;
  };

/* (packet generation) */
struct generate_mask
{
	_32_bit dest_ip, source_ip;
	_16_bit	dest_port, source_port;
	_32_bit 	pkt_no;
};

struct sp_data_exchange {
        int fd;                                /* Sh!t from transmit_TCP  */
        char *data;
        int datalen;
        _32_bit source; unsigned short source_port;
        _32_bit dest;   unsigned short dest_port;
        _32_bit seq, ack;
        unsigned short flags;
        char *buffer;               /* work buffer */
        int IP_optlen;             /* IP options length in bytes  */
        int TCP_optlen;            /* TCP options length in bytes */
        };
#endif

#endif

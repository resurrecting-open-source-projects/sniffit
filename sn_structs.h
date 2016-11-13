/* Sniffit Structs File                                                       */

#include <stdio.h>
#include "sn_packetstructs.h"

/**** Global data **********************************************************/ 
struct file_info 
{
        char proto, filename[50];
        FILE *f;
        unsigned long bytes;
        unsigned long exp_seq;     /* expected seq to avoid double logging */
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
unsigned char host[16];
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
  int timeout;                   
  };
struct shared_logged_conn            /* shared memory logging datastructure */
  {
  char log_enter [CONN_NAMELEN];                          /* normal logging */
  };
struct snif_mask                                         /* struct for mask */
  {
  unsigned long source_ip, destination_ip;
  unsigned short source_port, destination_port;
  };

/* (packet generation) */
struct generate_mask
{
	unsigned long  dest_ip, source_ip;
	unsigned short	dest_port, source_port;
	unsigned long 	pkt_no;
};

struct sp_data_exchange {
        int fd;                                /* Sh!t from transmit_TCP  */
        char *data;
        int datalen;
        unsigned long source; unsigned short source_port;
        unsigned long dest;   unsigned short dest_port;
        unsigned long seq, ack;
        unsigned short flags;
        char *buffer;               /* work buffer */
        int IP_optlen;             /* IP options length in bytes  */
        int TCP_optlen;            /* TCP options length in bytes */
        };                            
#endif


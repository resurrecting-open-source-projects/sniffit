/* Sniffit Packet Generation File                                         */
/*   - Idea/development/code:Amlan Saha                                   */
/*   - Packet code/debugging: Brecht Claerhout                            */

#include "sn_config.h"
#ifdef INCLUDE_INTERFACE
#ifdef GENERATION
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>     
#include "sn_curses.h"
#include "sn_defines.h"
#include "sn_structs.h"
#include "sn_generation.h"  

extern volatile int screen_busy;

void exec_generate(struct generate_mask *generate)
{
WINDOW *Msg_dsp;
int count=0, count_ptr, fd;
char msg[80];
char dummy_data[]="This Packet was fired with Sniffit!";

#ifdef DEBUG
		debug_msg("Gener: Start of execution");
#endif

count_ptr=(generate->pkt_no);

Msg_dsp=newwin(1,COLS,LINES-1,0);
wattrset(Msg_dsp,A_BOLD);
wattrset(Msg_dsp,COLOR_PAIR(WIN_COLOR_PKTCNT));

fd=open_sending();
while(count<count_ptr) 
	{
	/* Packet firing routine here */
#ifdef DEBUG
		debug_msg("Gener: Transmitting Packet");
#endif
	transmit_UDP(fd, dummy_data,0 ,strlen(dummy_data), 
				generate->source_ip, generate->source_port,
				generate->dest_ip, generate->dest_port);

#ifdef DEBUG
		debug_msg("Gener:  End");
#endif
	if(count==count_ptr-1)
		{
		sprintf(msg,"DISPATCH COMPLETE-Press ENTER");
		} 
	else {	
		sprintf(msg,"Packet No: %d dispatched.",count+1);	
	     }
	mvwaddstr(Msg_dsp,0,27,msg);
	while(screen_busy!=0) {};
	wnoutrefresh(Msg_dsp);
	doupdate();
	count++;
	}
delwin(Msg_dsp);
close(fd);
input_field(msg,NULL,0);
forced_refresh();
}

/**************************************************************************/
/* Actual packet generation functions below                               */
/* code stolen from Spoofit (my own ;)                                    */
/*                                                                        */
/* int open_sending (void)                                                */ 
/*   Returns a filedescriptor to the sending socket.                      */
/*   close it with close (int filedesc)                                   */
/*                                                                        */ 
/* void transmit_TCP (int sp_fd, char *sp_data,                           */
/*	              int sp_ipoptlen, int sp_tcpoptlen, int sp_datalen,  */
/*                    char *sp_source, unsigned short sp_source_port,     */ 
/*                    char *sp_dest,unsigned short sp_dest_port,          */ 
/*                    unsigned long sp_seq, unsigned long sp_ack,         */ 
/*                    unsigned short sp_flags)                            */ 
/*   fire data away in a TCP packet                                       */
/*    sp_fd         : raw socket filedesc.                                */ 
/*    sp_data       : IP options (you should do the padding)              */
/*                    TCP options (you should do the padding)             */
/*                    data to be transmitted                              */
/*                    (NULL is nothing)                                   */
/*                    note that all is optional, and IP en TCP options are*/
/*                    not often used.                                     */
/*                    All data is put after eachother in one buffer.      */
/*    sp_ipoptlen   : length of IP options (in bytes)                     */
/*    sp_tcpoptlen  : length of TCP options (in bytes)                    */
/*    sp_datalen    : amount of data to be transmitted (bytes)            */
/*    sp_source     : spoofed host that"sends packet"                     */
/*    sp_source_port: spoofed port that "sends packet"                    */
/*    sp_dest       : host that should receive packet                     */
/*    sp_dest_port  : port that should receive packet                     */
/*    sp_seq        : sequence number of packet                           */
/*    sp_ack        : ACK of packet                                       */
/*    sp_flags      : flags of packet (URG,ACK,PSH,RST,SYN,FIN)           */
/*                                                                        */
/* void transmit_UDP (int sp_fd, char *sp_data,                           */
/*                    int sp_ipoptlen, int sp_datalen,                    */
/*		      char *sp_source, unsigned short sp_source_port,     */
/*                    char *sp_dest, unsigned short sp_dest_port)         */
/*   fire data away in an UDP packet                                      */
/*    sp_fd         : raw socket filedesc.                                */ 
/*    sp_data       : IP options                                          */
/*                    data to be transmitted                              */
/*                    (NULL if none)                                      */
/*    sp_ipoptlen   : length of IP options (in bytes)                     */
/*    sp_datalen    : amount of data to be transmitted                    */ 
/*    sp_source     : spoofed host that"sends packet"                     */
/*    sp_source_port: spoofed port that "sends packet"                    */
/*    sp_dest       : host that should receive packet                     */
/*    sp_dest_port  : port that should receive packet                     */
/*                                                                        */
/**************************************************************************/

#define SP_IP_HEAD_BASE 	20          /* using fixed lengths to send   */ 
#define SP_TCP_HEAD_BASE 	20                /* no options etc...       */ 
#define SP_UDP_HEAD_BASE 	8              /* Always fixed */ 


int open_sending (void)
{
struct protoent *sp_proto;   
int sp_fd;
int dummy=1;

/* they don't come rawer */
if ((sp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW))==-1) 
        perror("Couldn't open Socket."), exit(1);

#ifdef DEBUG
	printf("Raw socket ready\n");
#endif
return sp_fd;
}

void sp_send_packet (struct sp_data_exchange *sp, unsigned char proto)
{
int sp_status;
struct sockaddr_in sp_server;
struct hostent *sp_help;
int HEAD_BASE;

/* Construction of destination */
bzero((char *)&sp_server, sizeof(struct sockaddr)); 
sp_server.sin_family = AF_INET;
sp_server.sin_addr.s_addr = sp->dest; 

/*
if (sp_server.sin_addr.s_addr == (unsigned int)-1)
        {  
        if (!(sp_help=gethostbyname(sp->dest))) 
        fprintf(stderr,"unknown host %s\n", sp->dest), exit(1);
        bcopy(sp_help->h_addr, (caddr_t)&sp_server.sin_addr, sp_help->h_length);
        };
*/
switch(proto)
   	{
	case 6: HEAD_BASE = SP_TCP_HEAD_BASE;  break;                  /* TCP */
	case 17: HEAD_BASE = SP_UDP_HEAD_BASE; break;                  /* UDP */
	default: exit(1); break;
	};
sp_status = sendto(sp->fd, (char *)(sp->buffer), sp->datalen+HEAD_BASE+SP_IP_HEAD_BASE+sp->IP_optlen, 0, 
			(struct sockaddr *)&sp_server,sizeof(struct sockaddr)); 
if (sp_status < 0 || sp_status != sp->datalen+HEAD_BASE+SP_IP_HEAD_BASE+sp->IP_optlen)
        {
        if (sp_status < 0)
          perror("Sendto"), exit(1);
        printf("hmm... Only transmitted %d of %d bytes.\n", sp_status, 
						sp->datalen+HEAD_BASE);
        };
#ifdef DEBUG
	printf("Packet transmitted...\n");
#endif
}

void sp_fix_IP_packet (struct sp_data_exchange *sp, unsigned char proto)
{ 
struct IP_header *sp_help_ip;
int HEAD_BASE;

switch(proto)
   	{
	case 6: HEAD_BASE = SP_TCP_HEAD_BASE;  break;                  /* TCP */
	case 17: HEAD_BASE = SP_UDP_HEAD_BASE; break;                  /* UDP */
	default: exit(1); break;
	};

sp_help_ip = (struct IP_header *) (sp->buffer);
sp_help_ip->verlen = (IP_VERSION << 4) | ((SP_IP_HEAD_BASE+sp->IP_optlen)/4);
sp_help_ip->type = 0;
sp_help_ip->length = htons(SP_IP_HEAD_BASE+HEAD_BASE+sp->datalen+sp->IP_optlen+sp->TCP_optlen);
sp_help_ip->ID = htons(12545);                                  /* TEST */ 
sp_help_ip->flag_offset = 0;
sp_help_ip->TTL = 69;
sp_help_ip->protocol = proto;
sp_help_ip->source = sp->source;
sp_help_ip->destination =  sp->dest;
sp_help_ip->checksum=in_cksum((unsigned short *) (sp->buffer), 
						SP_IP_HEAD_BASE+sp->IP_optlen);
#ifdef DEBUG
	printf("IP header fixed...\n");
#endif
}

void sp_fix_TCP_packet (struct sp_data_exchange *sp)
{ 
char sp_pseudo_ip_construct[MTU];
struct TCP_header *sp_help_tcp;
struct pseudo_IP_header *sp_help_pseudo;
int i;

for(i=0;i<MTU;i++)
  {sp_pseudo_ip_construct[i]=0;}

sp_help_tcp = (struct TCP_header *) (sp->buffer+SP_IP_HEAD_BASE+sp->IP_optlen);
sp_help_pseudo = (struct pseudo_IP_header *) sp_pseudo_ip_construct;

sp_help_tcp->offset_flag = htons( (((SP_TCP_HEAD_BASE+sp->TCP_optlen)/4)<<12) | sp->flags); 
sp_help_tcp->seq_nr = htonl(sp->seq);
sp_help_tcp->ACK_nr = htonl(sp->ack);
sp_help_tcp->source = htons(sp->source_port);
sp_help_tcp->destination = htons(sp->dest_port);
sp_help_tcp->window = htons(0x7c00);             /* dummy for now 'wujx' */

sp_help_pseudo->source = sp->source;
sp_help_pseudo->destination =  sp->dest;
sp_help_pseudo->zero_byte = 0;
sp_help_pseudo->protocol = 6;
sp_help_pseudo->TCP_UDP_len = htons(sp->datalen+SP_TCP_HEAD_BASE+sp->TCP_optlen);

memcpy(sp_pseudo_ip_construct+12, sp_help_tcp, sp->TCP_optlen+sp->datalen+SP_TCP_HEAD_BASE);
sp_help_tcp->checksum=in_cksum((unsigned short *) sp_pseudo_ip_construct, 
				  sp->datalen+12+SP_TCP_HEAD_BASE+sp->TCP_optlen);
#ifdef DEBUG
	printf("TCP header fixed...\n");
#endif
}

void transmit_TCP (int sp_fd, char *sp_data, 
			   int sp_ipoptlen, int sp_tcpoptlen, int sp_datalen, 
		           unsigned long sp_source, unsigned short sp_source_port,
			   unsigned long sp_dest, unsigned short sp_dest_port,
                           unsigned long sp_seq, unsigned long sp_ack, 
                           unsigned short sp_flags)
{
char sp_buffer[1500];
struct sp_data_exchange sp_struct;

bzero(sp_buffer,1500);
if (sp_ipoptlen!=0) 
	memcpy(sp_buffer+SP_IP_HEAD_BASE,sp_data,sp_ipoptlen);

if (sp_tcpoptlen!=0) 
	memcpy(sp_buffer+SP_IP_HEAD_BASE+SP_TCP_HEAD_BASE+sp_ipoptlen,
			                    sp_data+sp_ipoptlen,sp_tcpoptlen);
if (sp_datalen!=0) 
	memcpy(sp_buffer+SP_IP_HEAD_BASE+SP_TCP_HEAD_BASE+sp_ipoptlen+sp_tcpoptlen,
			sp_data+sp_ipoptlen+sp_tcpoptlen,sp_datalen);

sp_struct.fd          = sp_fd; 
sp_struct.data        = sp_data;
sp_struct.datalen     = sp_datalen;
sp_struct.source      = sp_source;
sp_struct.source_port = sp_source_port;
sp_struct.dest        = sp_dest;
sp_struct.dest_port   = sp_dest_port;
sp_struct.seq         = sp_seq;
sp_struct.ack         = sp_ack;
sp_struct.flags       = sp_flags;
sp_struct.buffer      = sp_buffer;
sp_struct.IP_optlen   = sp_ipoptlen;          
sp_struct.TCP_optlen  = sp_tcpoptlen;          

sp_fix_TCP_packet(&sp_struct);
sp_fix_IP_packet(&sp_struct, 6);
sp_send_packet(&sp_struct, 6);
}

void sp_fix_UDP_packet (struct sp_data_exchange *sp)
{ 
char sp_pseudo_ip_construct[MTU];
struct UDP_header *sp_help_udp;
struct pseudo_IP_header *sp_help_pseudo;
int i;

for(i=0;i<MTU;i++)
  {sp_pseudo_ip_construct[i]=0;}

sp_help_udp = (struct UDP_header *) (sp->buffer+SP_IP_HEAD_BASE+sp->IP_optlen);
sp_help_pseudo = (struct pseudo_IP_header *) sp_pseudo_ip_construct;

sp_help_udp->source = htons(sp->source_port);
sp_help_udp->destination = htons(sp->dest_port);
sp_help_udp->length =  htons(sp->datalen+SP_UDP_HEAD_BASE);

sp_help_pseudo->source = sp->source;
sp_help_pseudo->destination =  sp->dest;
sp_help_pseudo->zero_byte = 0;
sp_help_pseudo->protocol = 17;
sp_help_pseudo->TCP_UDP_len = htons(sp->datalen+SP_UDP_HEAD_BASE);

memcpy(sp_pseudo_ip_construct+12, sp_help_udp, sp->datalen+SP_UDP_HEAD_BASE);
sp_help_udp->checksum=in_cksum((unsigned short *) sp_pseudo_ip_construct, 
						     sp->datalen+12+SP_UDP_HEAD_BASE);
#ifdef DEBUG
	printf("UDP header fixed...\n");
#endif
}

void transmit_UDP (int sp_fd, char *sp_data, 
			   int sp_ipoptlen, int sp_datalen, 
		           unsigned long sp_source, unsigned short sp_source_port,
			   unsigned long sp_dest, unsigned short sp_dest_port)
{
char sp_buffer[1500];
struct sp_data_exchange sp_struct;
bzero(sp_buffer,1500);


if (sp_ipoptlen!=0) 
	memcpy(sp_buffer+SP_IP_HEAD_BASE,sp_data,sp_ipoptlen);
if (sp_data!=NULL) 
	memcpy(sp_buffer+SP_IP_HEAD_BASE+SP_UDP_HEAD_BASE+sp_ipoptlen,
					     sp_data+sp_ipoptlen,sp_datalen);

sp_struct.fd          = sp_fd; 
sp_struct.data        = sp_data;
sp_struct.datalen     = sp_datalen;
sp_struct.source      = sp_source;
sp_struct.source_port = sp_source_port;
sp_struct.dest        = sp_dest;
sp_struct.dest_port   = sp_dest_port;
sp_struct.buffer      = sp_buffer;
sp_struct.IP_optlen   = sp_ipoptlen;
sp_struct.TCP_optlen  = 0;

sp_fix_UDP_packet(&sp_struct);
sp_fix_IP_packet(&sp_struct, 17);
sp_send_packet(&sp_struct, 17);
}

#endif
#endif

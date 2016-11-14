/* Sniffit Data File                                                         */

/**** Network Devices *******************************************************/


/* Older configuration system of Sniffit */
/* ether: 14                             */
/* ppp  : 4                              */
/* slip : 16                             */
/* lo   : 4                              */

#ifdef LINUX
/*
#define NETDEV_NR      3
char *NETDEV[]={"lo","ppp","eth"};
int HEADSIZE []={4  ,0   ,14};
*/
#define NETDEV_NR      3
char *NETDEV[]={"ppp","slip","eth"}; 		/* echo on loopback   */
int HEADSIZE []={0   ,0     ,14};		/* slip needs testing */
#endif

#ifdef SUNOS
#define NETDEV_NR      3
char *NETDEV[]={"le","hme"};
int HEADSIZE[]={14  ,14};		/* ppp: 4 or 0 or nothing? */
#endif

#ifdef IRIX
#define NETDEV_NR      2
char *NETDEV[]={"ppp","et"};
int HEADSIZE[]={0    ,14};		/* ppp: 4 or 0 or nothing */
#endif

#ifdef FREEBSD				/* ppp: 4 or 0 ? */
/*
#define NETDEV_NR      2
char *NETDEV[]={"ppp","ed"};
int HEADSIZE[]={4    ,14};
*/
#define NETDEV_NR      1
char *NETDEV[]={"ed"};
int HEADSIZE[]={14};
#endif

#ifdef BSDI				/* ppp: 4 or 0 ? */
/*
#define NETDEV_NR      2
char *NETDEV[]={"ppp","ef"};
int HEADSIZE[]={4    ,14};
*/
#define NETDEV_NR      1
char *NETDEV[]={"ef"};
int HEADSIZE[]={14};
#endif

#ifdef DEC_OSF
#define NETDEV_NR      1
char *NETDEV[]={"ln"};
int HEADSIZE[]={14};
#endif

#ifdef NETBSD
#ifdef i386
#define NETDEV_NR      21
char *NETDEV[]={"ppp","ai","de","ec","ef","eg","el","en","ep","fe","fea","fpa","fxp","ix","iy","lc","le","ne","sm","tl","we"};
int HEADSIZE[]={4    ,14  ,14  ,14  ,14  ,14  ,14  ,14  ,14  ,14  ,14   ,14   ,14   ,14  ,14  ,14  ,14  ,14  ,14  ,14  ,14  };
#elif defined(sparc)
#define NETDEV_NR      3
char *NETDEV[]={"ppp","le","ie"};
int HEADSIZE[]={4    ,14  ,14};
#elif defined(amiga)
#define ETH_DEV_NR      6
char *NETDEV[]={"ppp","bah","ed","es","le","qn"};
int HEADSIZE[]={4    ,14  ,14   ,14  ,14  ,14};
#else
#error Unknown network devices for this NetBSD architecture.
#endif
#endif

#ifdef AIX                          /* only for the AIX powerpack ;) */
#define NETDEV_NR      4            /* not usefull without it        */
char *NETDEV[]={"en","et","tr","fi"};
int HEADSIZE[]={14  ,22  ,22  ,24};
#endif

#ifdef HPUX                        /* only for the HPUX powerpack ;) */
#define NETDEV_NR      2           /* not usefull without it        */
char *NETDEV[]={"le","sam"};
int HEADSIZE[]={14  ,14   };
#endif

/**** Global data **********************************************************/
pcap_t *dev_desc;
pcap_dumper_t *dev_dump;
void *start_dynam;
int dynam_len;
char Logfile[250];                                      /* name of logfile */
FILE *LogFILE;                                           /* logfile stream */
/* char *IP; *//* was with older '-p' */
char IP[256];
unsigned long SNIFLEN;                            /* bytes we need to snif */
short DEST_PORT, SRC_PORT;                             /* destination port */
char non_printable, *logging_device;

/**** Global data (packets) *************************************************/
int PROTO_HEAD;    /* Base Protocol head length (ethernet, PPP ,....) */

char *IP_TYPE_precedence[8]=
        {"Routine", "Priority", "Immediate", "Flash", "Flash override",
        "Critical", "Internetwork control", "Network control"};

char *IP_PROTOCOL_number[34]=

{"Reserved","ICMP","IGMP","GGP","Unassigned","ST","TCP","UCL","EGP","IGP",
      "BBN-MON","NVP-II","PUP","ARGUS","EMCOM","XNET","CHAOS","UDP","MUX",
      "DCN-MEAS","HMP","PRM","XNS-IDP","TRUNK-1","TRUNK-2","LEAF-1","LEAF-2",
      "RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP","MERIT-INP","SEP"};


char *ICMP_type_3_code[6]=
        {"Net unreachable", "Host unreachable", "Protocol unreachable",
        "Port unreachable", "Fragmentation needed and DF set",
        "Source route failed"};
char *ICMP_type_5_code[4]=
        {"Redirect datagrams for the network",
        "Redirect datagrams for the host",
        "Redirect datagrams for the \'type of service\' and the network",
        "Redirect datagrams for the \'type of service\' and the host"};
char *ICMP_type_11_code[2]=
        {"Time-to-live exceeded in transmit",
        "Fragment reassembly time exceeded"};

/**** Global data (config) **************************************************/
struct cfg_file_contense *select_from_list;     /* pointers for cfg lists */
struct cfg_file_contense *select_to_list;
struct cfg_file_contense *deselect_from_list;
struct cfg_file_contense *deselect_to_list;

int select_from_length=0;                         /* length of cfg lists  */
int select_to_length=0;
int deselect_from_length=0;
int deselect_to_length=0;
int Priority=0;             /* The higher the priority, the more important */
char dot_notation[20];                            /* for easy working, Q&D */

/**** Global data (plugins) *************************************************/
char Plugin_Active[10];

/**** Global data (interactive) *********************************************/
#ifdef INCLUDE_INTERFACE

/**** shared memory pointers ************************************************/
char *SHARED, *connection_data, *timing, *running_connections,
						  *logged_connections;
int *LISTlength, *DATAlength, memory_id;
unsigned int  *TCP_nr_of_packets, *ICMP_nr_of_packets, *UDP_nr_of_packets;
unsigned int  *IP_nr_of_packets;
unsigned long *TCP_bytes_in_packets, *UDP_bytes_in_packets;
int *DESC_LEN;

/**** data structures *******************************************************/
struct snif_mask *mask;
struct shared_logged_conn *log_conn;
FILE *log_dev_stream;
struct stat log_dev_stat;

volatile int LOGGING=0, screen_busy=0;
char PACKET_INFO;
int POINTpos=0, LISTpos=0;
unsigned char COLOR_AVAIL=0;

/**** screen  **************************************************************/
int MASK_WINDOW_ROWS, MASK_WINDOW_COLS;
int MAIN_WINDOW_ROWS, MAIN_WINDOW_COLS;
int INFO_WINDOW_ROWS, INFO_WINDOW_COLS;
int DATA_WINDOW_ROWS, DATA_WINDOW_COLS;
int INFO_WINDOW_X, INFO_WINDOW_Y;
int MASK_WINDOW_X, MASK_WINDOW_Y;
int DATA_WINDOW_X, DATA_WINDOW_Y;

WINDOW *menu_window;
struct box_window data_box, main_box, mask_box, packets_box;
int Pid=0;
#endif

/* DEBUG section */
#ifdef DEBUG
FILE *debug_dev;
unsigned int debug_cnt=0;
#endif



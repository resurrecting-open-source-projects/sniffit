/* Sniffit Data File -- Brecht Claerhout                                */

/*** Sniffit data */
#ifdef INCLUDE_INTERFACE
typedef void (*sig_hand)(int );  /* sighandler_t gave errors, weird */
#endif

pcap_t *dev_desc;

struct file_info 
{
        char proto, filename[50];
        FILE *f;
        unsigned long bytes;
	struct file_info *next;
};
void *start_dynam;
int dynam_len;

unsigned long SNIFLEN;                            /* bytes we need to snif */
short DEST_PORT;                           /* destination port */
char SNIFMODE, DUMPMODE, PROTOCOLS, ASC;
char non_printable, *logging_device;

#ifdef INCLUDE_INTERFACE
/*** Interface Data */
/* shared memory pointers */
char *SHARED, *connection_data, *timing,*logged_connection, 
						*running_connections; 
int *LISTlength, *DATAlength, memory_id;
unsigned int *TCP_nr_of_packets, *ICMP_nr_of_packets, *UDP_nr_of_packets;
unsigned int *IP_nr_of_packets;
unsigned long *TCP_bytes_in_packets, *UDP_bytes_in_packets;

FILE *log_dev_stream;
struct stat log_dev_stat;
struct snif_mask
  {
  unsigned long source_ip, destination_ip;
  unsigned short source_port, destination_port;
  };
struct snif_mask *mask;

/* menu data */
volatile sig_atomic_t LOGGING=0, screen_busy=0;
char PACKET_INFO;
int POINTpos=0,LISTpos=0;
u_char COLOR_AVAIL=0;
WINDOW *menu_window;
struct box_window
  {WINDOW *main_window,*work_window;};
struct box_window data_box, main_box, mask_box, packets_box;

int Pid=0;
#endif
 
/*** Sniffit functions */ 
void quit (char *prog_name);
void reset_all (void);
void print_iphead (struct IP_header *iphead, char icmp_or_plain);
int check_packet(u_long ipaddr,
		const struct packetheader *p_header,
                const u_char *sp,
                char *file,
                struct unwrap *info,
		char *detail,
                int MODE);
pcap_handler packethandler(u_char *ipaddrpoint,
			const struct packetheader *p_header,
                        const u_char *sp);
static u_long getaddrbyname(char *name);

#ifdef INCLUDE_INTERFACE
/*** Interface functions */
void init_screen (void);
void child_exit (void);
void screen_exit (void);
void mem_exit (void);
void f_box_window (struct box_window *Win,
                 int num_lines, int num_cols, int begy,int begx,int col_mode);
void data_window (struct box_window *Win, struct box_window *P_Win,
                 int num_lines, int num_cols, int begy,int begx,
                 char *buffer, int listitem);
void data_device (char *buffer, int listitem);
void mask_status (struct box_window *Work_win);
void fill_box_window (struct box_window *Work_win, char *buffer,
                      int begin_item, int boxlen, int rowlen);
void point_item (struct box_window *Work_win, char *buffer,
                 int item, int begin_item, int boxlen, int rowlen);
void exec_mask (void);
void stop_logging (void);
void sig_blocking(char on_off, int sig);
void set_signal (int signum, sig_hand new_action);
int add_itemlist(char *buffer, char *string);
int del_itemlist(char *buffer, char *string);
void forced_refresh (void);
void interaction (int sig);
void menu_line (void);
char *input_field(char *string, char *input);
void clear_shared_mem(char mode);
void run_interface (void);
#endif

/* DEBUG section */
#ifdef DEBUG
FILE *debug_dev;
unsigned int debug_cnt=0;
#endif

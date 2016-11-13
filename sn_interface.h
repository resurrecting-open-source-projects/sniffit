/* Sniffit Data File                                                       */

#include "pcap.h"

typedef void (*sig_hand)(int );  /* sighandler_t gave errors, weird */

int add_itemlist(char *, char *);
void child_exit (void);
void clear_shared_mem(char);
void data_device (char *, int);
void data_window (struct box_window *, struct box_window *, int, int, int, 
						    	       int, char *, int);
int del_itemlist(char *, char *);
void exec_mask (void);
void f_box_window (struct box_window *, int, int, int, int, int);
void fill_box_window (struct box_window *, char *, int, int, int);
void forced_refresh (void);
void init_screen (void);
char *input_field(char *, char *, int);
void interaction (int);
void mask_status (struct box_window *);
void mem_exit (void);
void menu_line (void);
void point_item (struct box_window *, char *, int, int, int, int);
void run_interface (void);
void screen_exit (void);
void set_signal (int, sig_hand);
void sig_blocking(char, int);
void stop_logging (void);
int check_mask (const struct packetheader *,const unsigned char *, char *, 
					char *, struct unwrap *);
pcap_handler interactive_packethandler( char *, const struct packetheader *,
                 		        const unsigned char *);
void stop_packet_info (void);
void packet_info_handler (int);
void create_arguments(char *, char *, char *, char *, char *, int);

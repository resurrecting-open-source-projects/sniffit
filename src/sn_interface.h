/* Sniffit Data File                                                       */

#include "pcap.h"

typedef void (*sig_hand)(int );  /* sighandler_t gave errors, weird */

extern int add_itemlist(struct shared_conn_data *, char *, char *);
extern void child_exit (void);
extern void clear_shared_mem(char);
extern int del_itemlist(struct shared_conn_data *, char *);
extern void forced_refresh (void);
extern char *input_field(char *, char *, int);
extern void mem_exit (void);
extern void run_interface (void);

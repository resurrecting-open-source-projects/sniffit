/* Sniffit Data File                                                       */

/**** Sniffit functions *****************************************************/ 
int check_packet(unsigned long,
                const struct packetheader *,
                const unsigned char *,char *, char *,
                struct unwrap *,char *,int);          
pcap_handler packethandler(unsigned char *,const struct packetheader *,
							const unsigned char *);
int check_mask (const struct packetheader *,const unsigned char *, char *,
    	                                    char *,struct unwrap *);
pcap_handler interactive_packethandler( char *, const struct packetheader *,
                                        const unsigned char *);     
void print_iphead (struct IP_header *, char);
unsigned long getaddrbyname(char *);
void quit (char *);
void reset_all (void);
char *strlower (char *);
struct file_info *add_dynam (char *, char, char, unsigned long, int);
void delete_dynam (char *, char, char);  
void record_buf(struct file_info *, unsigned long, char *, int, int);
void sb_shift(struct file_info *); 
void sbuf_update(struct file_info *, unsigned long, char *, int);
struct file_info *search_dynam(char *, char);
void my_exit (void);

/**** Sniffit functions (plugins) *******************************************/ 
void start_plugin (int, struct Plugin_data *);



/* Sniffit main program file                                             */
/*  - by           : Brecht Claerhout                                    */

#include "sn_config.h"		/* Config header file */

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
/* #include <netdb.h> */
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
/* #include <arpa/inet.h> */		/*  for inet_addr() */
#ifdef INCLUDE_INTERFACE
#include <sys/ipc.h>
#include <sys/shm.h>
#endif
#include "pcap.h"

/************************ Own includes *************************************/
#include "sn_defines.h"		/* Various defines */
#include "sn_structs.h"		/* All structures */
#include "sn_global.h"		/* some global defs */
#include "sn_data.h"		/* data defs */
#include "sn_packets.h"		/* My own packet structs */
#include "sn_logfile.h"
#include "sn_cfgfile.h"		/* Config file handling */
#include "sn_resolv.h"          /* Host resolution */
#include "sn_plugins.h"		/* Sniffit Plugins file */

#ifdef INCLUDE_INTERFACE
#include "sn_interface.h"	/* all ncurses stuff  */
#endif
#ifdef GENERATION
#include "sn_generation.h"	/* Sniffit Packet generation */
#endif

#include "sniffit.h"		/* definition of functions  */

static char Copyright[] =
"Sniffit - Brecht Claerhout - Copyright 1996-98";

void quit (char *prog_name)		/* Learn to use the program */
{
  printf (
	   "usage: %s [-xdabvnN] [-P proto] [-A char] [-p port] [(-r|-R) recordfile]\n"
	   "       [-l sniflen] [-L logparam] [-F snifdevice] [-M plugin]\n"
#ifdef INCLUDE_INTERFACE
	   "       [-D tty]"
	   " (-t<Target IP> | -s<Source IP>)"
	   " | (-i|-I) | -c<config file>]\n",
#else
	   "       (-t<Target IP> | -s<Source IP>) | -c<config file>]\n",
#endif
	   prog_name);
  printf ("Plugins Available:\n");
#ifdef PLUGIN0_NAME
  printf ("    0 -- %s\n", PLUGIN0_NAME);
#endif
#ifdef PLUGIN1_NAME
  printf ("    1 -- %s\n", PLUGIN1_NAME);
#endif
#ifdef PLUGIN2_NAME
  printf ("    2 -- %s\n", PLUGIN2_NAME);
#endif
#ifdef PLUGIN3_NAME
  printf ("    3 -- %s\n", PLUGIN3_NAME);
#endif
#ifdef PLUGIN4_NAME
  printf ("    4 -- %s\n", PLUGIN4_NAME);
#endif
#ifdef PLUGIN5_NAME
  printf ("    5 -- %s\n", PLUGIN5_NAME);
#endif
#ifdef PLUGIN6_NAME
  printf ("    6 -- %s\n", PLUGIN6_NAME);
#endif
#ifdef PLUGIN7_NAME
  printf ("    7 -- %s\n", PLUGIN7_NAME);
#endif
#ifdef PLUGIN8_NAME
  printf ("    8 -- %s\n", PLUGIN8_NAME);
#endif
#ifdef PLUGIN9_NAME
  printf ("    9 -- %s\n", PLUGIN9_NAME);
#endif

  exit (0);
}


void close_dumpfile(void) {pcap_dump_close(dev_dump);};
void close_pcapdev(void) {pcap_close(dev_desc);};

void my_exit (void)
{
  fflush(NULL);
  printf("Gracefull shutdown...\n");
  exit (0);
};

/* DEBUGGING INFO */
#ifdef DEBUG
void close_debug_device (void)
{
  fclose (debug_dev);
}

void debug_msg (char *debug_text)
{
  fprintf (debug_dev, "%s (%d)\n", debug_text, debug_cnt);
  debug_cnt++;
}
#endif

char *strlower (char *string)
{
  int i;

  for (i = 0; i < strlen (string); i++)
    *(string + i) = (isupper (*(string + i)) ? tolower (*(string + i)) : *(string + i));
  return string;
}

void start_plugin (int PL_nr, struct Plugin_data *PL_d)
{
  switch (PL_nr)
    {
#ifdef PLUGIN0_NAME
    case 0:
      PLUGIN0 (PL_d);
      break;
#endif
#ifdef PLUGIN1_NAME
    case 1:
      PLUGIN1 (PL_d);
      break;
#endif
#ifdef PLUGIN2_NAME
    case 2:
      PLUGIN2 (PL_d);
      break;
#endif
#ifdef PLUGIN3_NAME
    case 3:
      PLUGIN3 (PL_d);
      break;
#endif
#ifdef PLUGIN4_NAME
    case 4:
      PLUGIN4 (PL_d);
      break;
#endif
#ifdef PLUGIN5_NAME
    case 5:
      PLUGIN5 (PL_d);
      break;
#endif
#ifdef PLUGIN5_NAME
    case 5:
      PLUGIN5 (PL_d);
      break;
#endif
#ifdef PLUGIN6_NAME
    case 6:
      PLUGIN6 (PL_d);
      break;
#endif
#ifdef PLUGIN7_NAME
    case 7:
      PLUGIN7 (PL_d);
      break;
#endif
#ifdef PLUGIN8_NAME
    case 8:
      PLUGIN8 (PL_d);
      break;
#endif
#ifdef PLUGIN9_NAME
    case 9:
      PLUGIN9 (PL_d);
      break;
#endif
    default:
      fprintf (stderr, "Plugin does not exist...\n");
      exit (1);
      break;
    }
}

void
reset_all (void)
{
  start_dynam = NULL;
  dynam_len = 0;
}

/* if do_file == 0, then don't handle the files */
/* this is for the global logfile option        */
struct file_info *
add_dynam (char *file, char ptype, char do_file,
	   _32_bit cur_seq, int len)
{
  int i;
  FILE *f;
  int last_time_out = 0;
  struct file_info *dummy_pointer;
  struct file_info *search_pointer;

  if (dynam_len >= MAXCOUNT)
    {
      /*
       * remove less effective connection from list 
       */
      search_pointer = start_dynam;
      dummy_pointer = start_dynam;
      do
	{
	  if (search_pointer->time_out > last_time_out)
	    {
	      last_time_out = search_pointer->time_out;
	      dummy_pointer = search_pointer;
	    }
	  search_pointer = search_pointer->next;
	}
      while (search_pointer != NULL);
#ifdef DEBUG
      debug_msg ("Auto timeout engaged (filename follows)");
      debug_msg (dummy_pointer->filename);
#endif
      if (dummy_pointer->f == NULL)
	delete_dynam (dummy_pointer->filename, dummy_pointer->proto, 0);
      else
	delete_dynam (dummy_pointer->filename, dummy_pointer->proto, 1);
      printf ("Too many connections... auto timeout\n");
    }
  if ((dummy_pointer = (struct file_info *) malloc (sizeof (struct file_info))) == NULL)
    {
      printf ("Couldn't allocate memory.\n");
      exit (0);
    };
  dummy_pointer->bytes = 0;
  dummy_pointer->proto = ptype;
  strcpy (dummy_pointer->filename, file);
  if (do_file != 0)
    {
      f = fopen (file, "a");
      if (f == NULL)
	perror ("Couldn't open logfile:"), exit (0);
      dummy_pointer->f = f;
    }
  else
    {
      dummy_pointer->f = NULL;
    }
  dummy_pointer->next = NULL;
  dummy_pointer->buffer = NULL;
  dummy_pointer->log = 0;
  dummy_pointer->exp_seq = cur_seq + len;
  for (i = 0; i < SCBUF; i++)
    dummy_pointer->scroll_buf[i] = ' ';
  dummy_pointer->scroll_buf[SCBUF] = 0;

  if (start_dynam == NULL)
    start_dynam = dummy_pointer;
  else
    {
      search_pointer = start_dynam;
      while (search_pointer->next != NULL)
	search_pointer = search_pointer->next;
      search_pointer->next = dummy_pointer;
    }
  dynam_len++;
  return dummy_pointer;
}

void
delete_dynam (char *file, char ptype, char do_file)
{
  struct file_info *search_pointer;
  struct file_info *dummy_pointer;

  if (start_dynam == NULL)
    return;
  search_pointer = start_dynam;
  if ((strcmp (search_pointer->filename, file) == 0) &&
      (search_pointer->proto == ptype))
    {
      if (do_file != 0)
	fclose (search_pointer->f);
      start_dynam = search_pointer->next;
      dynam_len--;
      return;
    }
  search_pointer = start_dynam;
  if (search_pointer->next == NULL)
    return;
  while (search_pointer->next != NULL)
    {
      if ((strcmp (search_pointer->next->filename, file) == 0) &&
	  (search_pointer->next->proto == ptype))
	{
	  if (do_file != 0)
	    fclose (search_pointer->next->f);
	  dummy_pointer = search_pointer->next;
	  search_pointer->next = search_pointer->next->next;
	  if (dummy_pointer->buffer != NULL)
	    free (dummy_pointer->buffer);
	  free (dummy_pointer);
	  dynam_len--;
	  return;
	}
      search_pointer = search_pointer->next;
    }
}

/* returns NULL on failure */
struct file_info *
search_dynam (char *file, char ptype)
{
  struct file_info *search_pointer;

  if (start_dynam == NULL)
    return NULL;

  search_pointer = start_dynam;	/* time_out add */
  do
    {
      search_pointer->time_out += 1;
      search_pointer = search_pointer->next;
    }
  while (search_pointer != NULL);

  search_pointer = start_dynam;	/* actual search */
  do
    {
      if ((strcmp (search_pointer->filename, file) == 0) &&
	  (search_pointer->proto == ptype))
	{
	  search_pointer->time_out = 0;		/* timeout reset */
	  return search_pointer;
	}
      search_pointer = search_pointer->next;
    }
  while (search_pointer != NULL);
  return NULL;
}

/* Type 0: TELNET  */
void
record_buf (struct file_info *dummy_pointer, _32_bit cur_seq_nr,
	    char *data, int len, int type)
{
  int i, j, noloop = 0;

  if (dummy_pointer->exp_seq != cur_seq_nr)
    {
      return;
    }
  noloop = 0;
  for (i = 0; i < len; i++)
    {
      j = dummy_pointer->bytes;
      switch (type)
	{
	case 0:
	  if (data[i] == TELNET_ENTER)	/* return found */
	    {
	      dummy_pointer->log++;
	      noloop = 1;
	    };
	  break;
	default:
	  break;
	}
      if (noloop == 1)
	break;
      if (j >= LOG_PASS_BUF)
	break;
      if (isprint (data[i]))
	{
	  dummy_pointer->buffer[j] = data[i];
	}
      else
	{
	  dummy_pointer->buffer[j] = '~';
	};
      dummy_pointer->buffer[j + 1] = 0;
      dummy_pointer->bytes += 1;
    }
#ifdef	DEBUG_ONSCREEN
  printf ("Record buffer: >%s<  (%d)\n", dummy_pointer->buffer, dummy_pointer->bytes);
#endif
}

void
sb_shift (struct file_info *dummy_pointer)
{
  int i, j;

  for (i = 1; i < SCBUF; i++)
    dummy_pointer->scroll_buf[i - 1] = dummy_pointer->scroll_buf[i];
}

void
sbuf_update (struct file_info *dummy_pointer, _32_bit cur_seq_nr,
	     char *data, int len)
{
  int i;

  if (dummy_pointer->exp_seq != cur_seq_nr)
    {
      return;
    }

  for (i = 0; i < len; i++)
    {
      sb_shift (dummy_pointer);
      if (data[i] != 0)		/*
				 * used to be 'isprint', not possible for ftp logging 
				 */
	{
	  dummy_pointer->scroll_buf[SCBUF - 1] = data[i];
	}
      else
	{
	  dummy_pointer->scroll_buf[SCBUF - 1] = '.';
	};
    }
#ifdef DEBUG_ONSCREEN
  printf ("scr_buf: %s\n", dummy_pointer->scroll_buf);
#endif
}

void
print_iphead (struct IP_header *iphead, char icmp_or_plain)
{
  int dummy;
  unsigned char *so, *dest;

  if (icmp_or_plain != 0)
    printf ("ICMP message concerned following IP packet:\n");
  so = (unsigned char *) &(iphead->source);
  dest = (unsigned char *) &(iphead->destination);
  printf ("from %u.%u.%u.%u to %u.%u.%u.%u\n",
	  so[0], so[1], so[2], so[3],
	  dest[0], dest[1], dest[2], dest[3]);
  dummy = iphead->type;
  dummy >>= 5;
  printf ("IP Packet precedence: %s   (%c%c%c)\n",
	  IP_TYPE_precedence[dummy],
	  (iphead->type & IP_DELAY) ? 'D' : '-',
	  (iphead->type & IP_THROUGHPUT) ? 'T' : '-',
	  (iphead->type & IP_RELIABILITY) ? 'R' : '-');
  dummy = ntohs (iphead->flag_offset);
  dummy >>= 13;
  printf ("ID: 0x%X  FLAGS: %s %s     Time to live (secs): %d\n",
          ntohs(iphead->ID),
	  (dummy & IP_DF) ? "DF" : "--",
	  (dummy & IP_MF) ? "MF" : "--",
	  iphead->TTL);
  if (iphead->protocol < 34)
    printf ("Protocol (%d): %s\n", iphead->protocol,
	    IP_PROTOCOL_number[iphead->protocol]);
  else
    printf ("Protocol (%d) not recognised\n", iphead->protocol);
  printf ("\n");
}

int
check_packet (_32_bit ipaddr,
	      const struct packetheader *p_header,
	      const unsigned char *sp,
	      char *file,
	      char *file2,
	      struct unwrap *info,
	      char *detail,
	      int MODE)
					  /* MODE 0: -t   MODE 1: -s */
					  /* MODE 2: -b              */
{
  unsigned char *so, *dest;
  char wc_so[20], wc_dest[20];
  struct IP_header iphead;
  struct TCP_header tcphead;
  struct ICMP_header icmphead;
  struct UDP_header udphead;
  int proto;
  unsigned int prior;
  char selected;
  int i;			/* Wildcard stuff */
  unsigned char *str_IP;
  unsigned int n_s;		/* strlen short notation for wc bugfix */

  proto = unwrap_packet (sp, info);
  if(proto == NOT_SUPPORTED)
    {
#ifdef DEBUG_ONSCREEN
    printf("unwrap: NOT_SUPPORTED\n");
#endif        
    return DROP_PACKET;} /* no use in trying */
  if(proto == NO_IP)
    {
#ifdef DEBUG_ONSCREEN
    printf("unwrap: NO_IP\n");
#endif        
    return DROP_PACKET;}	/* no use in trying */
  if(proto == NO_IP_4)
    {
#ifdef DEBUG_ONSCREEN
    printf("unwrap: NO_IP_4\n");
#endif    
    return DROP_PACKET;}	/* no use in trying */ 
  if(proto == CORRUPT_IP)
    {
#ifdef DEBUG_ONSCREEN
    printf("unwrap: CORRUPT_IP\n");
#endif        
     printf("Suspicious Packet detected... \n");
     return DROP_PACKET;}

  memcpy (&iphead, (sp + PROTO_HEAD), sizeof (struct IP_header));
  so = (unsigned char *) &(iphead.source);
  dest = (unsigned char *) &(iphead.destination);

  if ( ((proto == TCP)||(proto==TCP_FRAG_HEAD)) && (PROTOCOLS & F_TCP))
    {
#ifdef DEBUG_ONSCREEN
      printf ("TCP Packet\n");
#endif
      if((info->FRAG_nf==0)&&(proto!=TCP_FRAG_HEAD))
        {
        memcpy (&tcphead, (sp + PROTO_HEAD + info->IP_len),
	        sizeof (struct TCP_header));
        memcpy (detail, &tcphead, sizeof (struct TCP_header));
        }

      if ((WILDCARD == 0) && (CFG_FILE == 0))	/* Selection criteria */
	{
	  if (MODE == DEST && ipaddr != iphead.destination	/* -t */
	      ||
	      MODE == SOURCE && ipaddr != iphead.source		/* -s */
	      ||
	      MODE == BOTH && ipaddr != iphead.destination	/* -b */
	      && ipaddr != iphead.source
	     )
	     return DONT_EXAMINE;	/* Check destination/source IP */
	}
      else
	{
	  if (WILDCARD != 0)	/* Wildcards */
	    {
#ifdef DEBUG_ONSCREEN
	      printf ("WILDCARD\n");
#endif
	      sprintf (wc_so, "%u.%u.%u.%u", so[0], so[1], so[2], so[3]);
	      sprintf (wc_dest, "%u.%u.%u.%u", dest[0], dest[1], dest[2], dest[3]);
	      n_s = strlen (IP);
	      if (MODE == DEST && (strncmp (wc_dest, IP, n_s) != 0)	/* -t */
		  ||
		  MODE == SOURCE && (strncmp (wc_so, IP, n_s) != 0)	/* -s */
		  ||
		  MODE == BOTH && (strncmp (wc_dest, IP, n_s) != 0)	/* -b */
		               && (strncmp (wc_so, IP, n_s) != 0)
		)
		return DONT_EXAMINE;
	      /* Check destination/source IP */
	    }
	  else
	    {			/* We are using the config file (4*Check) */
	      prior = 0;
	      selected = 0;
	      sprintf (wc_so, "%u.%u.%u.%u", so[0], so[1], so[2], so[3]);
	      sprintf (wc_dest, "%u.%u.%u.%u", dest[0], dest[1], dest[2], dest[3]);
#ifdef DEBUG_ONSCREEN
if((info->FRAG_nf!=0)||(proto==TCP_FRAG_HEAD))
  printf ("CONCERNING: %s  %d - %s  %d\n", wc_so, ntohs (tcphead.source), wc_dest, ntohs (tcphead.destination)); 
#endif
	      /* Highest prior last (backward+break for speed)  */
	      for (i = (select_from_length - 1); i >= 0; i--)
		{
		  if (prior > select_from_list[i].priority)
		    break;
		  str_IP = select_from_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("SF: %s  %d   Prior:%d\n", str_IP, select_from_list[i].port, select_from_list[i].priority);
#endif
/* tcphead is reserved anyway (even when fragmented) */
		  if ((select_from_list[i].port == 0) ||
		      (select_from_list[i].port == ntohs (tcphead.source)) ||
                      (info->FRAG_nf!=0)||(proto==TCP_FRAG_HEAD)
                     )
		    {
		      if (select_from_list[i].wildcard == 0)
			{	/* NO wildcard */
			  if (strcmp (wc_so, str_IP) == 0)
			    {
			      selected = 1;
			      prior = select_from_list[i].priority;
			      break;
			    }
			}
		      else
			{	/* wildcard */
			  if (strncmp (wc_so, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 1;
			      prior = select_from_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 1;
			  break;
			};
		    }
		}

	      for (i = (select_to_length - 1); i >= 0; i--)
		{
		  if (prior > select_to_list[i].priority)
		    break;
		  str_IP = select_to_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("ST: %s  %d   Prior:%d\n", str_IP, select_to_list[i].port, select_to_list[i].priority);
#endif
		  if ((select_to_list[i].port == 0) ||
		      (select_to_list[i].port == ntohs (tcphead.destination))||
                      (info->FRAG_nf!=0)||(proto==TCP_FRAG_HEAD)
                     )
		    {
		      if (select_to_list[i].wildcard == 0)
			{	/* NO wildcard */
			  if (strcmp (wc_dest, str_IP) == 0)
			    {
			      selected = 1;
			      prior = select_to_list[i].priority;
			      break;
			    }
			}
		      else
			{	/* wildcard */
			  if (strncmp (wc_dest, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 1;
			      prior = select_to_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 1;
			  break;
			};
		    }
		}

	      for (i = (deselect_from_length - 1); i >= 0; i--)
		{
		  if (prior > deselect_from_list[i].priority)
		    break;
		  str_IP = deselect_from_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("DF: %s  %d   Prior:%d\n", str_IP, deselect_from_list[i].port, deselect_from_list[i].priority);
#endif
		  if ((deselect_from_list[i].port == 0) ||
		      (deselect_from_list[i].port == ntohs (tcphead.source))||
                      (info->FRAG_nf!=0)||(proto==TCP_FRAG_HEAD)
                     )
		    {
		      if (deselect_from_list[i].wildcard == 0)
			{	/* NO wildcard */
			  if (strcmp (wc_so, str_IP) == 0)
			    {
			      selected = 0;
			      prior = deselect_from_list[i].priority;
			      break;
			    }
			}
		      else
			{	/* wildcard */
			  if (strcmp (wc_so, str_IP) == 0)
			    {
			      selected = 0;
			      prior = deselect_from_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 0;
			  break;
			};

		    }
		}

	      for (i = (deselect_to_length - 1); i >= 0; i--)
		{
		  if (prior > deselect_to_list[i].priority)
		    break;
		  str_IP = deselect_to_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("DT: %s  %d   Prior:%d\n", str_IP, deselect_to_list[i].port, deselect_to_list[i].priority);
#endif
		  if ((deselect_to_list[i].port == 0) ||
		      (deselect_to_list[i].port == ntohs (tcphead.destination))||
                      (info->FRAG_nf!=0)||(proto==TCP_FRAG_HEAD)
                     )
		    {
		      if (deselect_to_list[i].wildcard == 0)
			{	/* NO wildcard */
			  if (strncmp (wc_dest, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 0;
			      prior = deselect_to_list[i].priority;
			      break;
			    }
			}
		      else
			{	/* wildcard */
			  if (strncmp (wc_dest, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 0;
			      prior = deselect_to_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 0;
			  break;
			};

		    }
		}

#ifdef DEBUG_ONSCREEN
	      printf ("Selected: %d\n", selected);
#endif
	      if (selected == 0)
		return DONT_EXAMINE;

	    }
	}

      if( (info->FRAG_nf==0)&&(proto!=TCP_FRAG_HEAD) )
        if( (MODE!=BOTH && DEST_PORT && ntohs (tcphead.destination)!=DEST_PORT) 
            ||
            (MODE!=BOTH && SRC_PORT && ntohs (tcphead.source)!=SRC_PORT)
            ||
            (MODE==BOTH && SRC_PORT && ntohs (tcphead.source)!=SRC_PORT
                                    && ntohs (tcphead.destination)!=SRC_PORT)
          ) /* with BOTH SRC_PORT&DEST_PORT should be the same!! */
            /* DEST/SRC do not depend on the SOURCE or DEST modes! */ 
          return DONT_EXAMINE;	/* Check dest. PORT */

#ifdef DEBUG_ONSCREEN
      printf ("Packet accepted\n");
#endif

     
      if( (info->FRAG_nf==0)&&(proto!=TCP_FRAG_HEAD) )
        {
        /* inet_ntoa gave wrong output sometimes */
        sprintf (file, "%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
	         so[0], so[1], so[2], so[3],
	         (unsigned short) ntohs (tcphead.source),
	         dest[0], dest[1], dest[2], dest[3],
	         (unsigned short) ntohs (tcphead.destination));
        sprintf (file2, "%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
  	         dest[0], dest[1], dest[2], dest[3],
	         (unsigned short) ntohs (tcphead.destination),
	         so[0], so[1], so[2], so[3],
	         (unsigned short) ntohs (tcphead.source));
        }
      else
        {
        /* inet_ntoa gave wrong output sometimes */
        sprintf (file, "%u.%u.%u.%u-%u.%u.%u.%u",
                 so[0], so[1], so[2], so[3],
                 dest[0], dest[1], dest[2], dest[3]);
        sprintf (file2, "%u.%u.%u.%u-%u.%u.%u.%u",
                 dest[0], dest[1], dest[2], dest[3],
                 so[0], so[1], so[2], so[3]);
        }

      if(info->FRAG_nf!=0)
	return TCP_EX_FRAG_NF;

      if(proto==TCP_FRAG_HEAD)
	return TCP_EX_FRAG_HEAD;

      if ((ntohs(tcphead.offset_flag) & FIN) != 0) /* check for reset conn. */
        return TCP_FINISH; /* packet is a FIN */

      if ((ntohs(tcphead.offset_flag) & RST) != 0) /* check for reset conn. */
        return TCP_FINISH; 

      /*
       * Used to be for speed, '-x' needs all info, so this too!
       * if (info->DATA_len == 0)
       * return DONT_EXAMINE;        
       */

      return TCP_EXAMINE;	/* interprete packet */
    };

/***** WARNING: Remove if later fragment handling is done *************/
  if(info->FRAG_nf!=0)
    {printf("Fragment Skipped...\n"); return DONT_EXAMINE; };


  if ((proto == ICMP) && (PROTOCOLS & F_ICMP))	/* ICMP packet checking */
    {
      memcpy (&icmphead, (sp + PROTO_HEAD + info->IP_len),
	      sizeof (struct ICMP_header));
      memcpy (detail, &icmphead, sizeof (struct ICMP_header));
      sprintf (file, "%u.%u.%u.%u > %u.%u.%u.%u",
	       so[0], so[1], so[2], so[3],
	       dest[0], dest[1], dest[2], dest[3]);
      return ICMP_EXAMINE;
    };
  if ((proto == UDP) && (PROTOCOLS & F_UDP))	/* UDP packet checking */
    {
#ifdef DEBUG_ONSCREEN
      printf ("UDP Packet\n");
#endif
      memcpy (&udphead, (sp + PROTO_HEAD + info->IP_len),
	      sizeof (struct UDP_header));
      memcpy (detail, &udphead, sizeof (struct UDP_header));

      if ((WILDCARD == 0) && (CFG_FILE == 0))	/* Selection criteria */
	{
	  if (MODE == DEST && ipaddr != iphead.destination	/* -t */
	      ||
	      MODE == SOURCE && ipaddr != iphead.source		/* -s */
	      ||
	      MODE == BOTH && ipaddr != iphead.destination	/* -b */
	      && ipaddr != iphead.source
	    )
	    return DONT_EXAMINE;	/* Check destination/source IP */
	}
      else
	{
	  if (WILDCARD != 0)	/* Wildcards */
	    {
	      sprintf (wc_so, "%u.%u.%u.%u", so[0], so[1], so[2], so[3]);
	      sprintf (wc_dest, "%u.%u.%u.%u", dest[0], dest[1], dest[2], dest[3]);
	      n_s = strlen (IP);
	      if (MODE == DEST && (strncmp (wc_dest, IP, n_s) != 0)	/* -t */
		  ||
		  MODE == SOURCE && (strncmp (wc_so, IP, n_s) != 0)	/* -s */
		  ||
		  MODE == BOTH && (strncmp (wc_dest, IP, n_s) != 0)	/* -b */
		  && (strncmp (wc_so, IP, n_s) != 0)
		)
		return DONT_EXAMINE;
	      /* Check destination/source IP */
	    }
	  else
	    {			/* We are using the config file (4*Check) */
	      prior = 0;
	      selected = 0;
	      sprintf (wc_so, "%u.%u.%u.%u", so[0], so[1], so[2], so[3]);
	      sprintf (wc_dest, "%u.%u.%u.%u", dest[0], dest[1], dest[2], dest[3]);
#ifdef DEBUG_ONSCREEN
	      printf ("CONCERNING: %s  %d - %s  %d\n", wc_so, ntohs (udphead.source), wc_dest, ntohs (udphead.destination));
#endif
	      /* Highest prior last (backward+break for speed) */
	      for (i = (select_from_length - 1); i >= 0; i--)
		{
		  if (prior > select_from_list[i].priority)
		    break;
		  str_IP = select_from_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("SF: %s  %d   Prior:%d\n", str_IP, select_from_list[i].port, select_from_list[i].priority);
#endif
		  if ((select_from_list[i].port == 0) ||
		      (select_from_list[i].port == ntohs (udphead.source)))
		    {
		      if (select_from_list[i].wildcard == 0)
			{	/*
				 * NO wildcard 
				 */
			  if (strcmp (wc_so, str_IP) == 0)
			    {
			      selected = 1;
			      prior = select_from_list[i].priority;
			      break;
			    }
			}
		      else
			{	/*
				 * wildcard 
				 */
			  if (strncmp (wc_so, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 1;
			      prior = select_from_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 1;
			  break;
			};
		    }
		}

	      for (i = (select_to_length - 1); i >= 0; i--)
		{
		  if (prior > select_to_list[i].priority)
		    break;
		  str_IP = select_to_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("ST: %s  %d   Prior:%d\n", str_IP, select_to_list[i].port, select_to_list[i].priority);
#endif
		  if ((select_to_list[i].port == 0) ||
		      (select_to_list[i].port == ntohs (udphead.destination)))
		    {
		      if (select_to_list[i].wildcard == 0)
			{	/*
				 * NO wildcard 
				 */
			  if (strcmp (wc_dest, str_IP) == 0)
			    {
			      selected = 1;
			      prior = select_to_list[i].priority;
			      break;
			    }
			}
		      else
			{	/*
				 * wildcard 
				 */
			  if (strncmp (wc_dest, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 1;
			      prior = select_to_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 1;
			  break;
			};
		    }
		}

	      for (i = (deselect_from_length - 1); i >= 0; i--)
		{
		  if (prior > deselect_from_list[i].priority)
		    break;
		  str_IP = deselect_from_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("DF: %s  %d   Prior:%d\n", str_IP, deselect_from_list[i].port, deselect_from_list[i].priority);
#endif
		  if ((deselect_from_list[i].port == 0) ||
		      (deselect_from_list[i].port == ntohs (udphead.source)))
		    {
		      if (deselect_from_list[i].wildcard == 0)
			{	/* NO wildcard */
			  if (strcmp (wc_so, str_IP) == 0)
			    {
			      selected = 0;
			      prior = deselect_from_list[i].priority;
			      break;
			    }
			}
		      else
			{	/* wildcard */
			  if (strcmp (wc_so, str_IP) == 0)
			    {
			      selected = 0;
			      prior = deselect_from_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 0;
			  break;
			};
		    }
		}

	      for (i = (deselect_to_length - 1); i >= 0; i--)
		{
		  if (prior > deselect_to_list[i].priority)
		    break;
		  str_IP = deselect_to_list[i].host;
#ifdef DEBUG_ONSCREEN
		  printf ("DT: %s  %d   Prior:%d\n", str_IP, deselect_to_list[i].port, deselect_to_list[i].priority);
#endif
		  if ((deselect_to_list[i].port == 0) ||
		      (deselect_to_list[i].port == ntohs (udphead.destination)))
		    {
		      if (deselect_to_list[i].wildcard == 0)
			{	/* NO wildcard */
			  if (strncmp (wc_dest, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 0;
			      prior = deselect_to_list[i].priority;
			      break;
			    }
			}
		      else
			{	/* wildcard */
			  if (strncmp (wc_dest, str_IP, strlen (str_IP)) == 0)
			    {
			      selected = 0;
			      prior = deselect_to_list[i].priority;
			      break;
			    }
			}
		      if (str_IP[0] == 0)
			{
			  selected = 0;
			  break;
			};
		    }
		}

#ifdef DEBUG_ONSCREEN
	      printf ("Selected: %d\n", selected);
#endif
	      if (selected == 0)
		return DONT_EXAMINE;

	    }
	}
        
      if( (MODE!=BOTH && DEST_PORT && ntohs (udphead.destination)!=DEST_PORT) 
          ||
          (MODE!=BOTH && SRC_PORT && ntohs (udphead.source)!=SRC_PORT)
          ||
          (MODE==BOTH && SRC_PORT && ntohs (udphead.source)!=SRC_PORT
                                  && ntohs (udphead.destination)!=SRC_PORT)
        ) /* with BOTH SRC_PORT&DEST_PORT should be the same!! */
          /* DEST/SRC do not depend on the SOURCE or DEST modes! */ 
        return DONT_EXAMINE;	/* Check dest. PORT */

      /* inet_ntoa gave wrong output sometimes */
      sprintf (file, "%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
	       so[0], so[1], so[2], so[3],
	       (unsigned short) ntohs (udphead.source),
	       dest[0], dest[1], dest[2], dest[3],
	       (unsigned short) ntohs (udphead.destination));
      sprintf (file2, "%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
	       dest[0], dest[1], dest[2], dest[3],
	       (unsigned short) ntohs (udphead.destination),
	       so[0], so[1], so[2], so[3],
	       (unsigned short) ntohs (udphead.source));
      return UDP_EXAMINE;	/* interprete packet */
    }
  return DONT_EXAMINE;
}

/* Default Processing of packets */
pcap_handler
packethandler (unsigned char *ipaddrpoint,
	       const struct packetheader * p_header,
	       const unsigned char *sp)
{
  char filename[50], filename2[50], header[SNAPLEN];
  FILE *f;
  struct file_info *dummy_pointer;
  unsigned char status = 0;
  char *help;
  int dummy, finish;		/* look out it's signed */
  unsigned long datalen, position, total_length, i, n;
  _32_bit ipaddr;
  struct unwrap info;
  struct IP_header iphead;
  struct TCP_header tcphead;
  struct ICMP_header icmphead;
  struct IP_header iphead_icmp;
  struct UDP_header udphead;
  struct Plugin_data PL_d, PL_dex;

  memcpy (&ipaddr, ipaddrpoint, sizeof (_32_bit));

  finish = check_packet (ipaddr, p_header, sp, filename, filename2, &info, header, SNIFMODE);

  if (finish == DROP_PACKET)
    return;			/* Packet is broken */

  if( (PROTOCOLS&F_IP)&&((PROTOCOLS&F_TCP)==0))
    memcpy (&iphead, (sp + PROTO_HEAD), sizeof (struct IP_header)),
      print_iphead (&iphead, 0);

  if (finish == DONT_EXAMINE)
    return;			/* Packet is not for us */

  if(DUMPMODE==8)               /* Recording */
    {
    pcap_dump((unsigned char *) dev_dump, p_header, sp);
    return;
    }

  if((PROTOCOLS & F_IP)&&(PROTOCOLS & F_TCP)&&(finish<10))
    memcpy (&iphead, (sp + PROTO_HEAD), sizeof (struct IP_header)),
      print_iphead (&iphead, 0);


#ifdef DEBUG_ONSCREEN
  printf ("Processing Packet (finish: %d)\n", finish);
#endif

  if ((finish < 10) || (finish >= 20 && finish < 30))	/* Start plugin */
    {
    if( (finish!=TCP_EX_FRAG_HEAD)&&(finish!=TCP_EX_FRAG_NF) )
     { /* no fragments to PLUGINS yet */
       /* fixing data structure */
      memcpy (&(PL_d.PL_info), &info, sizeof (struct unwrap));
      memcpy (&(PL_d.PL_iphead), (sp + PROTO_HEAD), sizeof (struct IP_header));
      memcpy (&(PL_d.PL_tcphead), (sp + PROTO_HEAD + info.IP_len), sizeof (struct TCP_header));
      memcpy (&(PL_d.PL_udphead), (sp + PROTO_HEAD + info.IP_len), sizeof (struct UDP_header));
      if (PL_d.PL_iphead.protocol == TCP)
	memcpy (PL_d.PL_data, (sp + PROTO_HEAD + info.IP_len + info.TCP_len), info.DATA_len);
      if (PL_d.PL_iphead.protocol == UDP)
	memcpy (PL_d.PL_data, (sp + PROTO_HEAD + info.IP_len + info.UDP_len), info.DATA_len);
      memcpy (PL_d.PL_packet, (sp + PROTO_HEAD),
	      info.IP_len + info.TCP_len + info.UDP_len + info.DATA_len);

      /*  starting all plugins */
      for (i = 0; i < 10; i++)
	if (Plugin_Active[i] == 1)
	  {
	    memcpy (&PL_dex, &PL_d, sizeof (struct Plugin_data));
	    start_plugin (i, &PL_dex);
	  }
     }
    }

  if ((DUMPMODE & 32) && (finish < 10))		/* extended info TCP only */
    {
    if( (finish!=TCP_EX_FRAG_HEAD)&&(finish!=TCP_EX_FRAG_NF) )
     {
      memcpy (&tcphead, header, sizeof (struct TCP_header));
      dummy = ntohs (tcphead.offset_flag);
      printf ("\n");
      printf ("TCP Packet ID (from_IP.port-to_IP.port): %s\n", filename);
      printf ("   SEQ (hex): %lX   ", ntohl (tcphead.seq_nr));
      if (dummy & ACK)
	printf ("ACK (hex): %lX\n", ntohl (tcphead.ACK_nr));
      printf ("   FLAGS: %c%c%c%c%c%c",
	      (dummy & URG) ? 'U' : '-', (dummy & ACK) ? 'A' : '-',
	      (dummy & PSH) ? 'P' : '-', (dummy & RST) ? 'R' : '-',
	      (dummy & SYN) ? 'S' : '-', (dummy & FIN) ? 'F' : '-');
      if (dummy & ACK)
	printf ("   Window: %X\n", ntohs (tcphead.window));
      else
	printf ("\n");
      }
    };

  if ((finish < 10) && (LOGPARAM == 0))		/* TCP packet */
    /* I didn't use flags for later extention, and they */
    /* don't come in pairs anyhow */
    /* use return instead of else {if}, for later extention */
    {
      if( (finish!=TCP_EX_FRAG_HEAD)&&(finish!=TCP_EX_FRAG_NF) )
        memcpy (&tcphead, header, sizeof (struct TCP_header));

      switch (DUMPMODE & 199)	/* without bit 3,4,5 (8,16,32) */
	{
	case 0:		/* LOG mode */
          if( (finish==TCP_EX_FRAG_HEAD)||(finish==TCP_EX_FRAG_NF) )
          	break; /* no FRAG handling in log mode yet */
	  status = 0;
	  dummy_pointer = search_dynam (filename, TCP);
	  if (dummy_pointer != NULL)
	    status = 1;
	  /* make a new entry unless it's reset */
	  if (status == 0)
	    {
	      if (finish == TCP_FINISH)
		return;
	      /* there was never data transmitted */
	      /* seq_nr & datalen not important here yet */
	      if ((dummy_pointer = add_dynam (filename, TCP, 1, 0, 0)) == NULL)
		return;
	    }
	  f = dummy_pointer->f;

	  if (dummy_pointer->bytes <= SNIFLEN)
	    {
	      const unsigned char *data=
                                sp + PROTO_HEAD + info.IP_len + info.TCP_len;
	      if (SNIFLEN != 0)
		dummy_pointer->bytes += info.DATA_len;
	      /* last packet is written */
	      /* don't care about length */
	      if (ASC == 0)
		{
		  for (i = 0; i < info.DATA_len; i++)
		    fprintf (f, "%c", data[i]);
		}
	      else
		{
		  for (i = 0; i < info.DATA_len; i++)
		    fprintf (f, "%c", isprint (data[i]) ? data[i] : non_printable);
		};
	      fflush (f);	/* write all */
	    }
	  if (finish == TCP_FINISH)	/* let's reset the connection */
	    delete_dynam (filename, TCP, 1);
	  break;

	case 1:		/* DUMP mode */
	case 2:
	case 3:
          memcpy (&iphead, (sp + PROTO_HEAD), sizeof (struct IP_header));
	  printf ("Packet ID (from_IP.port-to_IP.port): %s\n", filename);
	  total_length = info.IP_len + info.TCP_len + info.DATA_len;
          if(info.FRAG_f!=0)
            printf("The following packet is an IP Fragment (first/ID: %0X)...\n",
                                                             ntohs(iphead.ID));
          if( (finish==TCP_EX_FRAG_HEAD)||(finish==TCP_EX_FRAG_NF) )
  	    {
            total_length = info.IP_len + info.DATA_len;
            if(finish==TCP_EX_FRAG_HEAD)
              printf("WARNING: Fragmented TCP header... suspicious... (ID: %0X) \n",
							     ntohs(iphead.ID));
            if(finish==TCP_EX_FRAG_NF)
              printf("The following packet is a continued IP Fragment (ID: %0X)...\n",
                                                             ntohs(iphead.ID));
            };
	  n = 0;
	  for (i = 0; i < total_length; i++)
	    {
	      unsigned char c = sp[PROTO_HEAD + i];
	      if (n > 75)
		n = 0, printf ("\n");
	      if (DUMPMODE & 1)
		n += printf (" %02X", c);
	      if (DUMPMODE & 2)
		n += printf (" %c", isprint (c) ? c : '.');
	    }
	  printf ("\n\n");
	  break;
	case 128:
	  break;		/* NO LOGGING MODE */
	default:
	  printf ("\nYou mixed incompatible options!\n");
	  exit (1);
	}
      return;
    }

  if ((finish < 10) && (LOGPARAM != 0))		/*  TCP packet - logfile   */
    /* This mode will grow, so I just copied the other if() */
    /* instead of adding a dumpmode, I think this will keep */
    /* things more simpel. Also I use the smart dynam       */
    /* managment of connections                             */
    {
    if( (finish!=TCP_EX_FRAG_HEAD)&&(finish!=TCP_EX_FRAG_NF) )
      {  /* no FRAG handling in logfile mode yet */
#include "sn_analyse.c"		/* dirty, but it got too confusing */
      }
    }

  if (finish < 20)		/* ICMP packet */
    {
      memcpy (&icmphead, header, sizeof (struct ICMP_header));
      memcpy (&iphead_icmp,
	      (sp + PROTO_HEAD + info.IP_len + ICMP_HEADLENGTH + 4),
	      sizeof (struct IP_header));
      printf ("ICMP message id: %s\n", filename);
      printf ("  ICMP type: ");
      switch (icmphead.type)
	{
	case 0:
	  printf ("%s\n", ICMP_TYPE_0);
	  break;
	case 3:
	  printf ("%s\n", ICMP_TYPE_3);
	  printf ("  Error: %s\n",
		  ICMP_type_3_code[icmphead.code]);
	  print_iphead (&iphead_icmp, 1);
	  break;
	case 4:
	  printf ("%s\n", ICMP_TYPE_4);
	  print_iphead (&iphead_icmp, 1);
	  break;
	case 5:
	  printf ("%s\n", ICMP_TYPE_5);
	  printf ("  Error: %s\n",
		  ICMP_type_5_code[icmphead.code]);
	  print_iphead (&iphead_icmp, 1);
	  break;
	case 8:
	  printf ("%s\n", ICMP_TYPE_8);
	  break;
	case 11:
	  printf ("%s\n", ICMP_TYPE_11);
	  printf ("  Error: %s\n",
		  ICMP_type_11_code[icmphead.code]);
	  print_iphead (&iphead_icmp, 1);
	  break;
	case 12:
	  printf ("%s\n", ICMP_TYPE_12);
	  print_iphead (&iphead_icmp, 1);
	  break;
	case 13:
	  printf ("%s\n", ICMP_TYPE_13);
	  break;
	case 14:
	  printf ("%s\n", ICMP_TYPE_14);
	  break;
	case 15:
	  printf ("%s\n", ICMP_TYPE_15);
	  break;
	case 16:
	  printf ("%s\n", ICMP_TYPE_16);
	  break;
	case 17:
	  printf ("%s\n", ICMP_TYPE_17);
	  break;
	case 18:
	  printf ("%s\n", ICMP_TYPE_18);
	  break;
	default:
	  printf ("Unknown ICMP type!\n");
	  break;
	}
      printf ("\n");
      return;
    }
  if (finish < 30)		/* nothing yet */
    {
      memcpy (&udphead, header, sizeof (struct UDP_header));
      switch (DUMPMODE & 223)
	{
	case 0:
	  break;
	case 1:		/* DUMP mode */
	case 2:
	case 3:
	  printf ("UDP Packet ID (from_IP.port-to_IP.port): %s\n", filename);
	  total_length = info.IP_len + info.UDP_len + info.DATA_len;
	  n = 0;
	  for (i = 0; i < total_length; i++)
	    {
	      unsigned char c = sp[PROTO_HEAD + i];
	      if (n > 75)
		n = 0, printf ("\n");
	      if (DUMPMODE & 1)
		n += printf (" %02X", c);
	      if (DUMPMODE & 2)
		n += printf (" %c", isprint (c) ? c : '.');
	    }
	  printf ("\n\n");
	  break;
	case 128:
	  break;		/* NO LOGGING MODE */
	default:
	  printf ("\nImpossible error! Sniffer Hartattack!\n");
	  exit (0);
	}
      return;
    }
}


#ifdef INCLUDE_INTERFACE	/* Interactive packethandling */
int
check_mask (const struct packetheader *p_header,
	    const unsigned char *sp,
	    char *conn_name, char *conn_name2, char *desc_string,
	    struct unwrap *info)
					  /* return -1 : packet not for us */
					  /* else finish value             */
{
  char helpstr1[20], helpstr2[20];
  unsigned char *so, *dest;
  struct IP_header iphead;
  struct TCP_header tcphead;
  int proto, i,j;

  proto = unwrap_packet (sp, info);
  /* Interface, no output allowed to stdout */
  if(proto == NOT_SUPPORTED)
    return DROP_PACKET; /* no use in trying */
  if (proto == NO_IP)
    return DROP_PACKET;	/* no use in trying */
  if (proto == NO_IP_4)
    return DROP_PACKET;	/* no use in trying */
  if(proto == CORRUPT_IP) 
    return DROP_PACKET; /* no use in trying */

  if((info->FRAG_nf!=0)||(info->FRAG_f!=0))
    {return DONT_EXAMINE; };
  /* No fragments studied at all */


  (*IP_nr_of_packets)++;
  if (proto == ICMP)
    {
      (*ICMP_nr_of_packets)++;
      return DONT_EXAMINE;
    }
  if (proto == UDP)
    {
      (*UDP_nr_of_packets)++;
      (*UDP_bytes_in_packets) += (info->UDP_len + info->DATA_len + info->IP_len);
      return DONT_EXAMINE;
    }
  if (proto != TCP)
    return DONT_EXAMINE;
  /* Packet info */
  (*TCP_nr_of_packets)++;
  (*TCP_bytes_in_packets) += (info->TCP_len + info->DATA_len + info->IP_len);
  /* Not a TCP packet */
  memcpy (&iphead, (sp + PROTO_HEAD), sizeof (struct IP_header));
  memcpy (&tcphead, (sp + PROTO_HEAD + info->IP_len), sizeof (struct TCP_header));

  if (mask->source_ip != 0 && iphead.source != mask->source_ip)
    return DONT_EXAMINE;
  if (mask->destination_ip != 0 && iphead.destination != mask->destination_ip)
    return DONT_EXAMINE;
  if (mask->destination_port && ntohs (tcphead.destination) != mask->destination_port)
    return DONT_EXAMINE;
  if (mask->source_port && ntohs (tcphead.source) != mask->source_port)
    return DONT_EXAMINE;

  /* inet_ntoa gave wrong output sometimes */
  so = (unsigned char *) &(iphead.source);
  dest = (unsigned char *) &(iphead.destination);

  sprintf (helpstr1, "%u.%u.%u.%u", so[0], so[1], so[2], so[3]);
  sprintf (helpstr2, "%u.%u.%u.%u", dest[0], dest[1], dest[2], dest[3]);

  sprintf (conn_name, "%16s %5u  -> %16s %5u",
	   helpstr1,
	   ntohs (tcphead.source),
	   helpstr2,
	   ntohs (tcphead.destination));
  sprintf (conn_name2, "%16s %5u  -> %16s %5u",
	   helpstr2,
	   ntohs (tcphead.destination),
	   helpstr1,
	   ntohs (tcphead.source));

if(INTERACTIVE_EXTEND==1)
{
#include "sn_conn_desc.c" 	/* Some detection */
}

  if ((ntohs (tcphead.offset_flag) & FIN) != 0)		/* check for reset conn. */
    return TCP_FINISH;		/* packet is a FIN */
  if ((ntohs (tcphead.offset_flag) & RST) != 0)		/* check for reset conn. */
    return TCP_FINISH;		/* packet is a RST */
  if (info->DATA_len == 0)
    return DONT_EXAMINE;	/*packet not for us */
  return TCP_EXAMINE;		/* interprete packet */
}

pcap_handler
interactive_packethandler (char *dummy,
			   const struct packetheader * p_header,
			   const unsigned char *sp)
{
  char conn_name[CONN_NAMELEN], conn_name2[CONN_NAMELEN];
  char desc_string[DESC_BYTES];
  int finish;			/* look out it's signed */
  struct unwrap info;

  if(INTERACTIVE_EXTEND==1)
    strcpy (desc_string, "Unknown");

  finish = check_mask (p_header, sp, conn_name, conn_name2, desc_string, &info);
  if (finish == DROP_PACKET)
    return;			/* Packet is broken */
  if (finish == DONT_EXAMINE)
    return;			/* Packet is not for us */

  if (finish != TCP_FINISH)	/* finish: already logged, or to short to add */
    add_itemlist (running_connections, conn_name, desc_string);
  if (strcmp (log_conn->log_enter, conn_name) == 0)
    {
      const unsigned char *data = sp + PROTO_HEAD + info.IP_len + info.TCP_len;
      if (*DATAlength + info.DATA_len < LENGTH_OF_INTERPROC_DATA)
	{
	  memcpy ((connection_data + *DATAlength), data, info.DATA_len);
	  *DATAlength += info.DATA_len;
	}
    }
  if (finish == TCP_FINISH)
    {
      del_itemlist (running_connections, conn_name);
      del_itemlist (running_connections, conn_name2);
    }
  kill (getppid (), SIGUSR1);
}
#endif



int main (int argc, char *argv[])
{
  char *dev, forced_dev[20], buffer[SNAPLEN];
  char ebuf[PCAP_ERRBUF_SIZE];
  unsigned char *DUMPfile;           /* file used for packed logging */
  int c, i;
  unsigned long memsize;
  _32_bit ipaddr;
  int flag = 0, doboth = 0, FORCE_DEV = 0, SUPPORTED = 0;
  extern char *optarg;

  signal (SIGINT,  my_exit);	/* gracefull termination in different ways */
  signal (SIGHUP,  my_exit);	
  signal (SIGTERM, my_exit);
 
  SNIFLEN = 300;		/* Set defaults */
  DEST_PORT = SRC_PORT = 0;	/* dest & source Port    */
  INTERACTIVE_EXTEND=SNIFMODE = DUMPMODE = PROTOCOLS = ASC = WILDCARD = 
							   CFG_FILE = NO_CHKSUM = 0;
  LOGPARAM = 0;
  Logfile[0] = 0;
  logging_device = NULL;
  IP[0]=0;
  for (i = 0; i < 10; i++)
    Plugin_Active[i] = 0;	/* Active plugins */

#ifdef DEBUG
  if ((debug_dev = fopen (DEBUG_DEVICE, "a")) < 0)
    {
      printf ("Couldn't open DEBUG device!\n");
      exit (0);
    }
  else
    {
      fprintf (debug_dev, "\n\nDEVICE OPENED FOR SNIFFIT DEBUGGING\n\n");
      exit_func (close_debug_device);
    }
#endif

#ifdef INCLUDE_INTERFACE
  while ((c = getopt (argc, argv, "D:A:P:iIdp:l:xabt:s:F:c:nvL:M:Nr:R:")) != -1)
    {
#else
  while ((c = getopt (argc, argv, "A:P:dp:l:xabt:s:F:c:nvL:M:Nr:R:")) != -1)
    {
#endif
      /* Argument treating */
      switch (c)
	{
	case 'v':
	  printf ("Sniffit Version %s - Copyright 1996-98 Brecht Claerhout\n", VERSION);
#ifdef __DATE__
	  printf ("Binary build %s %s\n", __DATE__, __TIME__);
#endif
	  quit (argv[0]);
	  break;
	case 'd':
          if(DUMPMODE&8) quit(argv[0]);
	  DUMPMODE |= 1;
	  break;
	case 'a':
	  if(DUMPMODE&8) quit(argv[0]);
	  DUMPMODE |= 2;
	  break;
        case 'R':                    /* recording (not mixable) */
          if(DUMPMODE) quit(argv[0]);
          DUMPMODE=8;
          DUMPfile=(unsigned char *)optarg;
          break;
        case 'r':
          if(DUMPMODE&8) quit(argv[0]);
          DUMPMODE|=16;              /* reading (mixable) */
          DUMPfile=(unsigned char *)optarg;
          break;
        case 'x':
	  if(DUMPMODE&8) quit(argv[0]);
	  DUMPMODE |= 32;
	  break;
	case 'N':
	  if(DUMPMODE&8) quit(argv[0]);
	  DUMPMODE |= 128;
	  break;
	case 'p':
          if(DEST_PORT!=0)
            printf("Conflicting ports... (using %d as destination port)\n",
                                                               atoi(optarg));
          DEST_PORT = atoi(optarg);
          break;
	case 'l':
	  SNIFLEN = atol (optarg);
	  break;
	case 'L':
	  LOGPARAM |= LOGPARAM_LOG_ON;
	  strlower (optarg);
	  if (strstr (optarg, "raw"))
	    LOGPARAM |= LOGPARAM_RAW;
	  if (strstr (optarg, "norm"))
	    LOGPARAM |= LOGPARAM_NORM;
	  if (strstr (optarg, "telnet"))
	    LOGPARAM |= LOGPARAM_TELNET;
	  if (strstr (optarg, "ftp"))
	    LOGPARAM |= LOGPARAM_FTP;
	  if (strstr (optarg, "mail"))
	    LOGPARAM |= LOGPARAM_MAIL;
	  break;
	case 'b':
	  doboth = 1;
	  break;
	case 'A':
	  ASC = 1;
	  non_printable = *optarg;
	  break;
	case 'D':
	  logging_device = optarg;
	  break;
	case 'P':
	  strlower (optarg);
	  if (strstr (optarg, "tcp"))
	    PROTOCOLS |= F_TCP;
	  if (strstr (optarg, "icmp"))
	    PROTOCOLS |= F_ICMP;
	  if (strstr (optarg, "udp"))
	    PROTOCOLS |= F_UDP;
	  if (strstr (optarg, "ip"))
	    PROTOCOLS |= F_IP;
	  break;
	case 's':
	  {     
          char hlp[300], *hlp2;
                    
          flag++;
	  SNIFMODE = SOURCE;
          hlp[299]=0;
          strncpy(hlp,optarg,299); 
          hlp2=(char *)strtok(hlp,":");
          IP[255]=0;
          strncpy(IP,hlp2,255);          
          if((hlp2=(char *)strtok(NULL,":"))!=NULL) 
            SRC_PORT = atoi(hlp2);          
          break;          
          }
        case 't':
	  {     
          char hlp[300], *hlp2;
                    
          flag++;
	  SNIFMODE = DEST;
          hlp[299]=0;
          strncpy(hlp,optarg,299); 
          hlp2=(char *)strtok(hlp,":");
          IP[255]=0;
          strncpy(IP,hlp2,255);          
          if((hlp2=(char *)strtok(NULL,":"))!=NULL) 
            {
            if(DEST_PORT!=0)
            printf("Conflicting ports... (using %d as destination port)\n",
                                                               atoi(hlp2));
            DEST_PORT = atoi(hlp2);          
            }
          break;          
          }
	case 'i':
	  flag++;
	  SNIFMODE = INTERACTIVE;
          INTERACTIVE_EXTEND=0;
	  break;
	case 'I':
	  flag++;
	  SNIFMODE = INTERACTIVE;
          INTERACTIVE_EXTEND=1;
	  break;
	case 'n':
	  NO_CHKSUM = 1;
	  break;
	case 'M':
	  if ((atoi (optarg) >= 0) && (atoi (optarg) <= 9))
	    Plugin_Active[atoi (optarg)] = 1;
	  break;
	case 'F':
	  strcpy (forced_dev, optarg);
	  FORCE_DEV = 1;
	  break;
	case 'c':
	  flag++;
	  read_cfg_file (optarg);
#ifdef DEBUG_ONSCREEN
	  printf ("FINISHED INTERPRETING\n");
	  printf ("sf:%d st:%d df:%d dt:%d\n", select_from_length, select_to_length, deselect_from_length, deselect_to_length);
#endif
	  CFG_FILE = 1;
	  break;
        case '?':
          quit(argv[0]);
          break;
	default:
	  break;
	}
    }

#ifdef ALLOW_SUID
  if ((getuid () != 0) && (geteuid () != 0))
    printf ("You should be root to run this program!\n"), exit (1);
#else
  if (getuid () != 0)
    printf ("You should be root to run this program!\n"), exit (1);
#endif

  if (flag != 1)
    quit (argv[0]);
  if ((LOGPARAM != 0) && (CFG_FILE == 0))
    quit (argv[0]);

  if (LOGPARAM != 0)
    open_logfile ();
  if (PROTOCOLS == 0)
    PROTOCOLS |= F_TCP;
  if (doboth)
    {
    SNIFMODE = BOTH;
    if( DEST_PORT&&SRC_PORT&&(DEST_PORT!=SRC_PORT) )
      printf("Conflicting ports... (result might not be what you want!)\n");
    if(DEST_PORT==0) DEST_PORT=SRC_PORT;  
                                     /* ports should be the same for BOTH */
    else SRC_PORT=DEST_PORT;
    }
  if ((SNIFMODE != INTERACTIVE) && (CFG_FILE == 0))
    {
/* if(index(IP,'@')) For SunOS  */
      if (strchr (IP, '@'))
	{
	  printf ("Wildcard detected, IP nr. not checked...\n");
	  WILDCARD = 1;
/* strcpy(index(IP,'@'),"\0"); */
	  strcpy (strchr (IP, '@'), "\0");
	}
      else
	{
	  ipaddr = getaddrbyname (IP);
	  if (ipaddr == 0)
	    printf ("Non existing host!\n"), exit (1);
	}
    }
  reset_all ();			/* just to be sure */

  if(DUMPMODE&16)               /* read from a file */
    {
    if(FORCE_DEV==0) quit(argv[0]);
    if((dev_desc=pcap_open_offline(DUMPfile,ebuf))==NULL)
      fprintf (stderr,"%s\n",ebuf), exit (0);
    }                         /* real device */  

  if (FORCE_DEV != 0)           /* 0.3.6 core dump fix */
    {
      if((dev=malloc(strlen(forced_dev)+1))==NULL)
 	  fprintf(stderr,"Couldn't allocate memory...\n");
      strcpy (dev, forced_dev);
      printf ("Forcing device to %s (user requested)...\n", dev);
      printf ("Make sure you have read the docs carefully.\n");
      PROTO_HEAD = FORCED_HEAD_LENGTH;
    }
  else
    {
    if((dev = pcap_lookupdev (ebuf)) == NULL)
       fprintf (stderr,"%s\n",ebuf), exit (1);
    }  

  for (i = 0; i < NETDEV_NR; i++)
     if (strstr (dev, NETDEV[i]))	/* For expansion */
       {
       PROTO_HEAD = HEADSIZE[i];
       printf ("Supported Network device found. (%s)\n", dev);
       SUPPORTED = 1;
       break;
       }

  if ((SUPPORTED == 0) && (FORCE_DEV == 0))	/* not supported & not forced */
    {
    printf ("Network device found... BUT not known by Sniffit, use '-F <netw device>' option!\n");
    printf ("Read the README.FIRST on how to force network devices.\n");
    exit (1);
    }

  if(!(DUMPMODE&16))
    if ((dev_desc = pcap_open_live (dev, SNAPLEN, 1, MSDELAY, ebuf)) == NULL)
      fprintf (stderr,"%s\n",ebuf), exit (0);
    else
      exit_func(close_pcapdev);
  if(FORCE_DEV!=0) {free(dev);}  /* no longer needed  */    
  
#ifdef PLUGIN0_INIT()
if (Plugin_Active[0] == 1)
  PLUGIN0_INIT ();
#endif
#ifdef PLUGIN1_INIT()
if (Plugin_Active[1] == 1)
  PLUGIN1_INIT ();
#endif
#ifdef PLUGIN2_INIT()
if (Plugin_Active[2] == 1)
  PLUGIN2_INIT ();
#endif
#ifdef PLUGIN3_INIT()
if (Plugin_Active[3] == 1)
  PLUGIN3_INIT ();
#endif
#ifdef PLUGIN4_INIT()
if (Plugin_Active[4] == 1)
  PLUGIN4_INIT ();
#endif
#ifdef PLUGIN5_INIT()
if (Plugin_Active[5] == 1)
  PLUGIN5_INIT ();
#endif
#ifdef PLUGIN6_INIT()
if (Plugin_Active[6] == 1)
  PLUGIN6_INIT ();
#endif
#ifdef PLUGIN7_INIT()
if (Plugin_Active[7] == 1)
  PLUGIN7_INIT ();
#endif
#ifdef PLUGIN8_INIT()
if (Plugin_Active[8] == 1)
  PLUGIN8_INIT ();
#endif
#ifdef PLUGIN9_INIT()
if (Plugin_Active[9] == 1)
  PLUGIN9_INIT ();
#endif

#ifdef INCLUDE_INTERFACE
  if (SNIFMODE == INTERACTIVE)
    {
      memsize = sizeof (int) + sizeof (int) + LENGTH_OF_INTERPROC_DATA +
        sizeof (int) + sizeof (struct snif_mask) +
        sizeof (struct shared_logged_conn) +
        (CONNECTION_CAPACITY * sizeof (struct shared_conn_data)) +
        sizeof (int) +
        sizeof (unsigned long) + sizeof (int) + sizeof (int) + sizeof (unsigned long) +
        sizeof (int) + sizeof (int);
      memory_id = shmget (0, memsize, 0700);
      if (memory_id < 0)
	{
	  perror ("Interactive Sniffer Hartattack (No Shared mem avail!)");
	  exit (0);
	}
      exit_func (mem_exit);
      if ((SHARED = shmat (memory_id, 0, SHM_RND)) == NULL)
	{
	  perror ("Interactive Sniffer Hartattack (Wow something is wrong here)");
	  exit (0);
	};
      printf ("Entering Shared memory at %p\n", SHARED);
      printf ("Shared %d\n", memsize);

      timing = SHARED;		/* set all pointers */
      DATAlength = timing + sizeof (int);
      connection_data = DATAlength + sizeof (int);
      LISTlength = connection_data + LENGTH_OF_INTERPROC_DATA;
      mask = LISTlength + sizeof (int);
      logged_connections = mask + sizeof (struct snif_mask);
      log_conn = (struct shared_logged_conn *) logged_connections;
      running_connections = logged_connections + sizeof (struct shared_logged_conn);
      TCP_nr_of_packets = running_connections + (sizeof (struct shared_conn_data) * CONNECTION_CAPACITY);
      TCP_bytes_in_packets = TCP_nr_of_packets + sizeof (int);
      ICMP_nr_of_packets = TCP_bytes_in_packets + sizeof (unsigned long);
      UDP_nr_of_packets = ICMP_nr_of_packets + sizeof (int);
      UDP_bytes_in_packets = UDP_nr_of_packets + sizeof (int);
      IP_nr_of_packets = UDP_bytes_in_packets + sizeof (unsigned long);
      DESC_LEN = IP_nr_of_packets + sizeof (int);
      clear_shared_mem (0);

      *DESC_LEN = 10;             /* not necessary, but for security (eliminate very unlikely races) */

      if ((Pid = fork ()) < 0)
	{
	  perror ("Interactive Sniffer Hartattack (Couldn't fork)");
	  exit (0);
	};
      if (Pid == 0)
	{
	  sleep (4);
	  if (pcap_loop (dev_desc, CNT,
			       interactive_packethandler, NULL) < 0)
	      printf ("Capturing Packets Failed\n"), exit (0);
	}
      else
	{
	  exit_func (child_exit);
	  signal (SIGCHLD, SIG_IGN);
	  if (logging_device != NULL)
	    {
	      if (stat (logging_device, &log_dev_stat) < 0)
		perror ("\'-D\' option error"), exit (0);
	      if ((log_dev_stream = fopen (logging_device, "a"))
		  == NULL)
		printf ("Couldn't open device for logging output\n"), exit (0);
	    }
	  run_interface ();
	}
    }
  else
    {
#endif
      if (CFG_FILE == 0)
	printf ("Sniffit.%s is up and running.... (%s)\n\n", VERSION, IP);
      else
	printf ("Sniffit.%s is up and running.... (Config File Used)\n\n", VERSION);
      if(DUMPMODE&8)
        {
        if((dev_dump=pcap_dump_open(dev_desc, DUMPfile))==NULL)
           fprintf (stderr, "Capturing Packets Failed\n"), exit (0);
        exit_func(close_dumpfile);            
        }
      
    
      switch (pcap_loop (dev_desc, CNT, packethandler, (unsigned char *) &ipaddr))
        {
        case -1:	
          fprintf (stderr, "Capturing Packets Failed\n"), exit (0); break;
	case 0: 
	  exit(0);
	default:
	  break;  
	}    
#ifdef INCLUDE_INTERFACE
    }
#endif
}

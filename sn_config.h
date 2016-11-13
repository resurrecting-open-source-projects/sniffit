/* Sniffit Config File                                                   */ 
/*   - By: Brecht Claerhout                                              */

/* Because of the use of GNU autoconfig, this file manages pretty much   */
/* itself, you could however still add your personal touch in some parts */ 

#define INCLUDE_INTERFACE            /* By default */

#ifndef HAVE_SHMGET                                 /* No Shared memory  */
#undef INCLUDE_INTERFACE
#endif
#ifndef HAVE_LIBNCURSES                             /* ncurses not found */ 
#undef INCLUDE_INTERFACE
#endif
#ifndef HAVE_NCURSES_H                              /* ncurses not found */ 
#undef INCLUDE_INTERFACE
#endif
#ifdef IRIX                                      /* No interface on IRIX */
#undef INCLUDE_INTERFACE 
#endif

/* Not supported yet */
#ifdef BSDI
#undef INCLUDE_INTERFACE 
#endif

#ifdef HAVE_ATEXIT
#define exit_func(x)    atexit(x)
#else
#define exit_func(x)    on_exit (x,0)
#endif

/***************************************************************************/
/* If you want to allow the program to be used 'set user id'               */

/* #define ALLOW_SUID */
#undef ALLOW_SUID

/***************************************************************************/
/* Following parameters describe the connections that can be handled at    */ 
/* once, MAXCOUNT stands for connections handled in normal mode. As        */
/* memory in normal mode is now handled dynamically, you can pump this     */
/* number up without having to much trouble (Watch it, the machine         */
/* could be slowed down a lot, and packets could get missed)               */
/* CONNECTION_CAPACITY is the same, except in interactive mode, this is    */
/* more dangerous to change, if you machine goes to slow (when sniffing    */
/* in interactive mode), lower this number.                                */

#define MAXCOUNT  		100
#ifdef INCLUDE_INTERFACE
#define CONNECTION_CAPACITY  	50
#endif

/* This is the interval time for the netstatistics */

#define INFO_TIMER	3       /* In seconds */

/***************************************************************************/
/* Enable/Disable Packet generation function                               */

#undef GENERATION
#ifdef INCLUDE_INTERFACE
#define GENERATION
/* #undef GENERATION */
#endif

/***************************************************************************/
/* Read about forcing the sniff device in the README.FIRST file            */

#define FORCED_HEAD_LENGTH	ETHERHEAD

/* MTU: this could need a change on interfaces different from ethernet or on non-standard */
/*      configured systems. Get the info out of 'ifconfig'.                               */
/*      But 1500 is a standard.                                                           */

#define MTU	1500

/*************** Don't change anything below this line *********************/

#undef DEBUG                   /* Debugging (to tty) - sigh */
/* #define DEBUG */
#define DEBUG_DEVICE	"/dev/ttyp6"

#undef DEBUG_ONSCREEN                  /* Debugging (to screen) - sigh */
/* #define	DEBUG_ONSCREEN */

#ifdef DEBUG
void close_debug_device (void);
void debug_msg(char *);
#endif


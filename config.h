/* Sniffit Config File -- Brecht Claerhout                                */ 
/* it ain't big yet... heheheh                                            */

/* if this variable is defined, the '-i' will be available, if not, it    */ 
/* won't be available.                                                    */
/* If you don't need interactive sniffing (like logging when not there)   */
/* compile it with this value #undef, this will make the program over 3   */ 
/* times smaller and it doesn't allocate all that memory.                 */
/* If you 'define' INCLUDE_INTERFACE, your kernel should support          */
/* System V IPC (it probably does)                                        */

#ifdef LINUX
  /* #undef INCLUDE_INTERFACE  */  
  #define INCLUDE_INTERFACE 
#else
  #undef INCLUDE_INTERFACE       /* No interactive support yet for non linux*/
#endif     

/* Following parameters describe the connections that can be handled at */ 
/* once, MAXCOUNT stands for connections handled in normal mode. As     */
/* memory in normal mode is now handled dynamically, you can pump this  */
/* number up without having to much trouble (Watch it, the machine      */
/* could be slowed down a lot, and packets could get missed)            */
/* CONNECTION_CAPACITY is the same, except in interactive mode, this is */
/* more dangerous to change, if you machine goes to slow (when sniffing */
/* in interactive mode), lower this number.                             */

	#define MAXCOUNT  		30                    
#ifdef INCLUDE_INTERFACE
	#define CONNECTION_CAPACITY  	30
#endif

/* This is the interval time for the netstatistics */

#define INFO_TIMER	3       /* In seconds */

/*************** Don't change anything below this line *********************/

#undef DEBUG                   /* Debugging - sigh */
/* #define DEBUG */ 
#define DEBUG_DEVICE	"/dev/ttyp3"


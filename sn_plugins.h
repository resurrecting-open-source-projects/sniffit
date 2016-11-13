/* Sniffit Pluginfile include file - Brecht Claerhout */
 
/* You should install the plugins, by adding three lines.               */
/* You should define a Plugin name, an alias for the plugin function,   */
/* and include the source code of it.                                   */
/* Example:                                                             */
/* #define PLUGIN0_NAME "Dummy Plugin"                                  */
/* #define PLUGIN0(x)   PL_real_function_name(x)                        */
/* #include "plugin_include_filename.h"                                 */
/* PLUGIN0_NAME and PLUGIN0 are fixed names, numbers can go from 0 to 9 */ 

/* These to plugins come standard with the Sniffit package as examples. */
/* the "Dummy Plugin" is quite useless, but the "DNS Plugin" is going   */
/* to be appreciated by some of you. Read the PLUGIN-HOWTO file.        */ 

#define PLUGIN0_NAME 	"Dummy Plugin"
#define PLUGIN0(x)	PL_dummy_plugin(x)
#include "dummy_plugin.plug"

#define PLUGIN1_NAME 	"DNS Plugin"
#define PLUGIN1(x)	PL_DNS_plugin(x)
#include "dns_plugin.plug"


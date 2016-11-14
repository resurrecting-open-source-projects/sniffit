/* Sniffit Logfile include file                                           */
/*   - by: Brecht Claerhout                                               */

#include "sn_config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include "sn_defines.h"
#include "sn_structs.h"
#include "sn_logfile.h"

extern char Logfile[250];                                /* name of logfile */
extern FILE *LogFILE;                                     /* logfile stream */
extern char LOGPARAM;
extern char DUMPMODE;				   	 /* recorded or not */

void logfile_exit (void)         /* at/on_exit closing of logfile */
{
printf("Sniffit Logging session ended.\n");
print_logline("Sniffit session ended.");
fflush(LogFILE);
fclose(LogFILE);
}

char *gettime (void)
{
time_t t;
char *tm;
static char recorded[] = "Recorded";

time(&t);
tm=ctime(&t);
tm[24]=0;
return (DUMPMODE&16)?recorded:tm;
}

void print_logline (char *logline)
{
fprintf(LogFILE,"[%s] - %s\n",gettime(),logline);
fflush(LogFILE);
}

void print_ftp_user (char *conn, char *user)
{
char line[250];
snprintf(line,sizeof(line),"%s: USER [%s]",conn,user);
print_logline (line);
}

void print_ftp_pass(char *conn, char *pass)
{
char line[250];
snprintf(line,sizeof(line),"%s: PASS [%s]",conn,pass);
print_logline (line);
}

void print_login (char *conn, char *login)
{
char line[250];
snprintf(line,sizeof(line),"%s: login [%s]",conn,login);
print_logline (line);
}

void print_mail (char *conn, char *msg)
{
char line[250];
snprintf(line,sizeof(line),"%s: mail [%s]",conn,msg);
print_logline (line);
}

void print_pwd (char *conn, char *pwd)
{
char line[250];
snprintf(line,sizeof(line),"%s: password [%s]",conn,pwd);
print_logline (line);
}

void print_conn (char *conn, char *msg)
{
char line[250];
snprintf(line,sizeof(line),"%s: %s",conn,msg);
print_logline (line);
}

void open_logfile (void)
{
if(Logfile[0]==0)       strcpy(Logfile,"sniffit.log");
LogFILE=fopen(Logfile,"a");
if(LogFILE==NULL)
  printf("Sniffit hardattack.. couldn't create/open logfile...\n"), exit(1);
exit_func(logfile_exit);
fchmod(LogFILE,  S_IWUSR|S_IRUSR);
print_logline("Sniffit session started.");
printf("Sniffit Logging started.\n");
}


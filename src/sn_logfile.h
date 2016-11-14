/* Sniffit Data File                                                        */

#define	LOG_NO_DETECT		99
#define	LOG_NO_LOG		0
#define	LOG_LOGIN		1
#define	LOG_LOGIN_RECORDED	2
#define	LOG_PWD			3
#define	LOG_PWD_RECORDED	4

void logfile_exit (void);
char *gettime (void);
void print_logline (char *);
void print_ftp_user (char *, char *);
void print_ftp_pass(char *, char *);
void print_login (char *, char *);
void print_pwd (char *, char *);
void print_conn (char *, char *);
void print_mail (char *, char *);
void open_logfile (void);

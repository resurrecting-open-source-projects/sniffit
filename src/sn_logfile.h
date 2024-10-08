/* Sniffit Data File                                                        */

#define	LOG_NO_DETECT		99
#define	LOG_NO_LOG		0
#define	LOG_LOGIN		1
#define	LOG_LOGIN_RECORDED	2
#define	LOG_PWD			3
#define	LOG_PWD_RECORDED	4

extern void print_ftp_user (char *, char *);
extern void print_ftp_pass(char *, char *);
extern void print_login (char *, char *);
extern void print_pwd (char *, char *);
extern void print_conn (char *, char *);
extern void print_mail (char *, char *);
extern void open_logfile (void);

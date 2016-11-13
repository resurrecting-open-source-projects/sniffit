/* Analyse traffic for logging mode                                      */
/*   - by: Brecht Claerhout                                              */

const unsigned char *data;
memcpy(&tcphead,header,sizeof(struct TCP_header));
	  	
dummy_pointer=search_dynam(filename, TCP);
if(dummy_pointer!=NULL) status=1; 
if(status==0)                        /* make a new entry unless it's reset */
  {
  if(finish!=TCP_FINISH) 
    if((dummy_pointer=add_dynam(filename, TCP, 0,ntohl(tcphead.seq_nr),info.DATA_len))==NULL)
	return 1;
  };

if(finish==TCP_FINISH)                      /* let's reset the connection */
  {delete_dynam(filename, TCP, 0);}

/*** return before using any search or pointer!!!!!!!! ***/
/* Connections with FIN have deleted entries! */
 
dummy=ntohs(tcphead.offset_flag);
	
if(LOGPARAM & LOGPARAM_RAW)          /* Raw logging */
  {
  if(dummy&SYN)	print_conn(filename,"Connection initiated. (SYN)");
  if(dummy&FIN) print_conn(filename,"Connection ending. (FIN)");
  if(dummy&RST) print_conn(filename,"Connection reset. (RST)");
  return 1;
  };

data = sp+PROTO_HEAD+info.IP_len+info.TCP_len;
if(LOGPARAM & LOGPARAM_NORM)          /* NORM logging */
  {
  if(search_dynam(filename2, TCP)==NULL)
    {
    if(dummy&SYN) print_conn(filename,"Connection initiated.");
    if(dummy&FIN) print_conn(filename2,"Connection closed.");
    if(dummy&RST) print_conn(filename2,"Connection closed.");
    };
  };

if((dummy&FIN)||(dummy&RST)) return 1; /* needed, cauz entry don't exist  */

/*** TELNET *****************************************************************/
if(LOGPARAM & LOGPARAM_TELNET)         
{
dummy_pointer=search_dynam(filename, TCP);
                             /* don't forget to check dummy_pointer!!! */
    
if( (ntohs(tcphead.source) == 23)&&(dummy_pointer!=NULL))/* from telnet */
  {
  sbuf_update(dummy_pointer,ntohl(tcphead.seq_nr),data,info.DATA_len);
  /* detect login */
  strlower(dummy_pointer->scroll_buf);

  if((dummy_pointer->log!=LOG_NO_DETECT)&&
                           (strstr(dummy_pointer->scroll_buf,"login")!=NULL))
    {
    dummy_pointer->log=LOG_NO_DETECT;
    dummy_pointer=search_dynam(filename2, TCP);
    if(dummy_pointer!=NULL)
      {
      dummy_pointer->log=LOG_LOGIN; 
      dummy_pointer->bytes=0;
      dummy_pointer->buffer=malloc(LOG_PASS_BUF);
      if(dummy_pointer->buffer==NULL) exit(1);
      dummy_pointer->buffer[0]=0;
      }
    else	
      {print_conn(filename2,"Password missed due to overload.");};\

#ifdef DEBUG_ONSCREEN
    printf("Login detected, data initialised.\n");
#endif
    }
  }

if( (ntohs(tcphead.destination) == 23)&&(dummy_pointer!=NULL))/* TO telnet */
  {
  if(dummy_pointer->log==LOG_LOGIN)	/* log login */
    {
    record_buf(dummy_pointer,ntohl(tcphead.seq_nr),data,info.DATA_len,0);
    if(dummy_pointer->log==LOG_LOGIN_RECORDED) /* login recorded */ 
      {
      print_login(filename,dummy_pointer->buffer);
      dummy_pointer->log=LOG_PWD; dummy_pointer->bytes=0;
      dummy_pointer->buffer[0]=0;
      }	 
    }
  else
    {
    if(dummy_pointer->log==LOG_PWD)	/* log pwd */
      {
      record_buf(dummy_pointer,ntohl(tcphead.seq_nr),data,info.DATA_len,0);
      if(dummy_pointer->log==LOG_PWD_RECORDED) /* passwd recorded */ 
        {
        print_pwd(filename,dummy_pointer->buffer);
	dummy_pointer->log=LOG_NO_LOG; dummy_pointer->bytes=0;
	dummy_pointer->buffer[0]=0;
	}	
      }
    }
  }
}
/*** END TELNET - LOGIN  ***************************************************/

/*** FTP *******************************************************************/
if(LOGPARAM & LOGPARAM_FTP)            /* loglevel 12 */
{
dummy_pointer=search_dynam(filename, TCP);
                             /* don't forget to check dummy_pointer!!! */

if( (ntohs(tcphead.destination) == 21) &&
				         (dummy_pointer!=NULL))/* to FTP */
  {
  sbuf_update(dummy_pointer,ntohl(tcphead.seq_nr),data,info.DATA_len);
  /* detect USER en PASS  */
  if((help=strstr(dummy_pointer->scroll_buf,"USER"))!=NULL)
    {	
    help+=strlen("USER ");
    for(i=0;i<SCBUF;i++)
      if(dummy_pointer->scroll_buf[i]==FTP_ENTER) 
        dummy_pointer->scroll_buf[i]=0;
    print_ftp_user(filename,help);
    for(i=0;i<SCBUF;i++)	dummy_pointer->scroll_buf[i]=' ';       
    }
		      
  if((help=strstr(dummy_pointer->scroll_buf,"PASS"))!=NULL)
    {
    help+=strlen("PASS ");
    for(i=0;i<SCBUF;i++)
      if(dummy_pointer->scroll_buf[i]==FTP_ENTER)
	dummy_pointer->scroll_buf[i]=0;
    print_ftp_pass(filename,help);
    for(i=0;i<SCBUF;i++)	dummy_pointer->scroll_buf[i]=' ';       
    }
  }
}
/*** END FTP ***************************************************************/

/*** MAIL ******************************************************************/
if(LOGPARAM & LOGPARAM_MAIL)            /* loglevel 12 */
{
/* dummy_pointer=search_dynam(filename, TCP); */
                             /* don't forget to check dummy_pointer!!! */

if( (ntohs(tcphead.destination) == 25) ) /* to MAIL */
  {
  if(info.DATA_len!=0)
    {
    char workbuf1[MTU];
    char *wb_dummy;
    char *p;
    size_t len = info.DATA_len <= MTU-1 ? info.DATA_len : MTU-1;

    strncpy(workbuf1,data,len);
    workbuf1[len]=0;
    strlower(workbuf1);

    if((p=strstr(workbuf1,"mail from"))!=NULL)
      {
      char workbuf2[MTU];

      strcpy(workbuf2, p);
      if(strchr(workbuf2,13)!=NULL)                   /* remove trailing enter */    
     	{wb_dummy=strchr(workbuf2,13); *wb_dummy=0;}    
      if(strchr(workbuf2,10)!=NULL)    
     	{wb_dummy=strchr(workbuf2,10); *wb_dummy=0;}    
      print_mail(filename,workbuf2);
      }

    if((p=strstr(workbuf1,"rcpt to"))!=NULL)
      {
      char workbuf2[MTU];

      strcpy(workbuf2, p);
      if(strchr(workbuf2,13)!=NULL)                          /* remove trailing enter */    
     	{wb_dummy=strchr(workbuf2,13); *wb_dummy=0;}    
      if(strchr(workbuf2,10)!=NULL)    
     	{wb_dummy=strchr(workbuf2,10); *wb_dummy=0;}    
      print_mail(filename,workbuf2);
      }
    }
  }
}
/*** END MAIL **************************************************************/


if( (dummy_pointer=search_dynam(filename, TCP)) !=NULL)
  {
  if(ntohl(tcphead.seq_nr)==dummy_pointer->exp_seq)
		       		dummy_pointer->exp_seq+=info.DATA_len;
  /* if we miss a packet... no probs seq nr's get updated */
  /* cauz' we can't rely on ACK's from other side         */
  /* it's pretty good this way                            */
  if(ntohl(tcphead.seq_nr)>dummy_pointer->exp_seq)
    dummy_pointer->exp_seq=ntohl(tcphead.seq_nr)+info.DATA_len;
  }
return 1;
return 1;  /* DON'T FORGET THEM!!!! */

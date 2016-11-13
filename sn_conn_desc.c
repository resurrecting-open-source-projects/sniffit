/* Connection description detection file                                 */
/*   - by: Brecht Claerhout                                              */


/* Simple PORT BASED detection */

/*** FTP sessions ********************************************************/
if( 
(ntohs(tcphead.source)==FTP_DATA_1)||(ntohs(tcphead.destination)==FTP_DATA_1) )
  {strcpy(desc_string, "FTP DATA");}

if( (ntohs(tcphead.source)==FTP_1)||(ntohs(tcphead.destination)==FTP_1) )
  {
  if(info->DATA_len==0)
    strcpy(desc_string, "FTP");
  if(info->DATA_len>5)
    {
    const unsigned char *data= sp+PROTO_HEAD+info->IP_len+info->TCP_len;

    strcpy(desc_string,"FTP: ");
    j=5;                                                 /* 5 = "FTP: " */
    for(i=0;i<info->DATA_len;i++)
      {
      if( (isalnum(data[i]) || ispunct(data[i]) || data[i]==' ')&&(j<(*DESC_LEN)-1) )
        {desc_string[j]=data[i]; desc_string[j+1]=0; j++; }
      else
        {if( (isspace(data[i]) && data[i]!=' ')&&(j<(*DESC_LEN)-1) )
           {desc_string[j]=' '; desc_string[j+1]=0; j++; }
        }
      }
    }
  }

/*** TELNET sessions *****************************************************/
if( (ntohs(tcphead.source)==TELNET_1)||(ntohs(tcphead.destination)==TELNET_1) )
  {strcpy(desc_string, "TELNET");}

/*** SSH sessions ********************************************************/
if( (ntohs(tcphead.source)==SSH_1)||(ntohs(tcphead.destination)==SSH_1) )
  {strcpy(desc_string, "Secure Shell");}

/*** MAIL sessions *****************************************************/
if( (ntohs(tcphead.source)==MAIL_1)||(ntohs(tcphead.destination)==MAIL_1) )
  {strcpy(desc_string, "MAIL");}

/*** IDENT **************************************************************/
if( (ntohs(tcphead.source)==IDENT_1)||(ntohs(tcphead.destination)==IDENT_1) )
  {strcpy(desc_string, "IDENT");}

/*** IRC ***************************************************************/
if( (ntohs(tcphead.source)==IRC_1)||(ntohs(tcphead.destination)==IRC_1) )
  {strcpy(desc_string, "IRC");}

/*** X11 sessions *******************************************************/
if( (ntohs(tcphead.source)==X11_1)||(ntohs(tcphead.destination)==X11_1) )
  {strcpy(desc_string, "X-Windows");}

/*** HTTP ***************************************************************/
if( (ntohs(tcphead.source)==HTTP_1)||(ntohs(tcphead.source)==HTTP_2)||
    (ntohs(tcphead.source)==HTTP_3)||(ntohs(tcphead.source)==HTTP_4)
  )
  {
  strcpy(desc_string, "HTTP");
  }

if( (ntohs(tcphead.destination)==HTTP_1)||(ntohs(tcphead.destination)==HTTP_2) || 
    (ntohs(tcphead.destination)==HTTP_3)||(ntohs(tcphead.destination)==HTTP_4) 
  )
  {
  if(info->DATA_len==0)
    strcpy(desc_string, "HTTP");
  if(info->DATA_len>5)
    {
    const unsigned char *data= sp+PROTO_HEAD+info->IP_len+info->TCP_len;

    strcpy(desc_string,"HTTP: ");
    j=6;                                                 /* 5 = "HTTP: " */
    for(i=0;i<info->DATA_len;i++)
      if( (isalnum(data[i]) || ispunct(data[i]) || data[i]==' ')&&(j<(*DESC_LEN)-1) )
        {desc_string[j]=data[i]; desc_string[j+1]=0; j++; }
      else
        {if( (isspace(data[i]) && data[i]!=' ')&&(j<(*DESC_LEN)-1) )
           {desc_string[j]=' '; desc_string[j+1]=0; j++; }
        }
    }
  }



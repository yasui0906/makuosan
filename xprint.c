/*
 * xprint.c
 * Copyright (C) 2008 KLab Inc.
 */
#include "makuosan.h"

char *opcodestrlist[]={"PING ",
                       "EXIT ",
                       "SEND ",
                       "MD5  ",
                       "DSYNC",
                       "DEL  ",
                       "UNKNOWN"};

uint8_t opcodenumlist[]={MAKUO_OP_PING,
                         MAKUO_OP_EXIT,
                         MAKUO_OP_SEND,
                         MAKUO_OP_MD5,
                         MAKUO_OP_DSYNC,
                         MAKUO_OP_DEL,
                         MAKUO_OPCODE_MAX};

char *sstatestrlist[]={"SEND_STAT   ",
                       "SEND_OPEN   ",
                       "SEND_DATA   ",
                       "SEND_MARK   ",
                       "SEND_CLOSE  ",
                       "SEND_LAST   ",
                       "SEND_ERROR  ",
                       "SEND_BREAK  ",
                       "SEND_WAIT   ",
                       "SEND_UNKNOWN"};

uint8_t sstatenumlist[]={MAKUO_SENDSTATE_STAT,
                         MAKUO_SENDSTATE_OPEN,
                         MAKUO_SENDSTATE_DATA,
                         MAKUO_SENDSTATE_MARK,
                         MAKUO_SENDSTATE_CLOSE,
                         MAKUO_SENDSTATE_LAST,
                         MAKUO_SENDSTATE_ERROR,
                         MAKUO_SENDSTATE_BREAK,
                         MAKUO_SENDSTATE_WAIT,
                         MAKUO_STATE_MAX};

char *rstatestrlist[] = {"RECV_NONE    ",
                         "RECV_UPDATE  ",
                         "RECV_SKIP    ",
                         "RECV_OPEN    ",
                         "RECV_MARK    ",
                         "RECV_CLOSE   ",
                         "RECV_IGNORE  ",
                         "RECV_READONLY",
                         "RECV_BREAK   ",
                         "RECV_LAST    ",
                         "RECV_MD5OK   ",
                         "RECV_MD5NG   ",
                         "RECV_DELETEOK",
                         "RECV_DELETENG",
                         "RECV_OPENERR ",
                         "RECV_READERR ", 
                         "RECV_WRITEERR", 
                         "RECV_CLOSEERR", 
                         "RECV_UNKNOWN"};

uint8_t rstatenumlist[]={MAKUO_RECVSTATE_NONE,
                         MAKUO_RECVSTATE_UPDATE,
                         MAKUO_RECVSTATE_SKIP,
                         MAKUO_RECVSTATE_OPEN,
                         MAKUO_RECVSTATE_MARK,
                         MAKUO_RECVSTATE_CLOSE,
                         MAKUO_RECVSTATE_IGNORE,
                         MAKUO_RECVSTATE_READONLY,
                         MAKUO_RECVSTATE_BREAK,
                         MAKUO_RECVSTATE_LAST,
                         MAKUO_RECVSTATE_MD5OK,
                         MAKUO_RECVSTATE_MD5NG,
                         MAKUO_RECVSTATE_DELETEOK,
                         MAKUO_RECVSTATE_DELETENG,
                         MAKUO_RECVSTATE_OPENERROR,
                         MAKUO_RECVSTATE_READERROR,
                         MAKUO_RECVSTATE_WRITEERROR,
                         MAKUO_RECVSTATE_CLOSEERROR,
                         MAKUO_STATE_MAX};

char *strsstate(uint8_t n)
{
  int i;
  for(i=0;sstatenumlist[i] != MAKUO_STATE_MAX;i++){
    if(sstatenumlist[i] == n){
      break;
    }
  }
  return(sstatestrlist[i]);
}

char *strrstate(uint8_t n)
{
  int i;
  for(i=0;rstatenumlist[i] != MAKUO_STATE_MAX;i++){
    if(rstatenumlist[i] == n){
      break;
    }
  }
  return(rstatestrlist[i]);
}

char *strmstate(mdata *data)
{
  if(data->head.flags & MAKUO_FLAG_ACK){
    return(strrstate(data->head.nstate));
  }
  return(strsstate(data->head.nstate));
}

char *stropcode(mdata *data)
{
  int i;
  for(i=0;opcodenumlist[i] != MAKUO_STATE_MAX;i++){
    if(opcodenumlist[i] == data->head.opcode){
      break;
    }
  }
  return(opcodestrlist[i]);
}

char *strackreq(mdata *data)
{
  char *ack = "ack";
  char *req = "req";
  if(data->head.flags & MAKUO_FLAG_ACK){
    return(ack);
  }
  return(req);
}

void fdprintf(int s, char *fmt, ...)
{
  char m[2048];
  va_list arg;
  if(s != -1){
    va_start(arg, fmt);
    vsnprintf(m, sizeof(m), fmt, arg);
    va_end(arg);
    m[sizeof(m) - 1] = 0;
    write(s, m, strlen(m));
  }
}

void lprintf(int l, char *fmt, ...)
{
  va_list arg;
  struct timeval tv;
  char b[1024];
  char d[2048];
  static char m[2048];
  if(moption.loglevel < l){
    return;
  }
  strcpy(d, m);
  va_start(arg, fmt);
  vsnprintf(b, sizeof(b), fmt, arg);
  va_end(arg);
  b[sizeof(b) - 1] = 0;
  snprintf(m, sizeof(m), "%s%s", d, b);
  m[sizeof(m) - 1] = 0;
  m[sizeof(m) - 2] = '\n';
  if(!strchr(m, '\n')){
    return;
  }
#ifdef MAKUO_DEBUG
  gettimeofday(&tv, NULL);
  fprintf(stderr, "%02d.%06d %s", tv.tv_sec % 60, tv.tv_usec, m);
#else
  fprintf(stderr, "%s", m);
#endif
  syslog(LOG_ERR, "%s: %s", moption.user_name, m);
  m[0] = 0;
}

int cprintf(int l, mcomm *c, char *fmt, ...)
{
  int r;
  int n;
  char m[2048];
  va_list arg;
  if(!c){
    return(0);
  }
  if(c->fd[0] == -1){
    return(0);
  }
  if(c->loglevel < l){
    return(0);
  }
  va_start(arg, fmt);
  vsnprintf(m, sizeof(m), fmt, arg);
  va_end(arg);
  m[sizeof(m) - 1] = 0;
  n = strlen(m);
  if(write(c->fd[0], m, n) == n){
    fsync(c->fd[0]);
  }else{
    c->logover++;
    lprintf(0, "[error] %s: Resource temporarily unavailable: %s", __func__, m);
    return(-1);
  }
  return(0);
}

void mprintf(int l, const char *func, mfile *m)
{
  if(!m)
    return;
  lprintf(l, "%s: rc=%d id=%d init=%d wait=%d flag=%d %s %s %s %s\n",
    func, 
    m->retrycnt,
    m->mdata.head.reqid, 
    m->initstate, 
    m->sendwait, 
    m->mdata.head.flags,
    inet_ntoa(m->addr.sin_addr), 
    stropcode(&(m->mdata)),
    strmstate(&(m->mdata)),
    m->fn);
}


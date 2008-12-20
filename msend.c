/*
 * msend.c
 * Copyright (C) 2008 KLab Inc. 
 */
#include "makuosan.h"

/******************************************************************
*
* send common functions (private)
*
*******************************************************************/
static mfile *msend_mfdel(mfile *m)
{
  mfile *r;
  if(!m){
    return(NULL);
  }
  r = m->next;
  if(m->fd != -1){
    close(m->fd);
  }
  if(m->pipe != -1){
    close(m->pipe);
  }
  if(m->pid){
    kill(m->pid, SIGTERM);
    waitpid(m->pid, NULL, 0);
  }
  while(m->mark = delmark(m->mark));
  clr_hoststate(m);
  mfdel(m);
  return(r);
}

static int msend_encrypt(mdata *data)
{
  int  szdata;
  MD5_CTX ctx;

  szdata = data->head.szdata;
  if(moption.cryptena){
    data->head.flags |= MAKUO_FLAG_CRYPT;
    if(data->head.szdata){
      MD5_Init(&ctx);
      MD5_Update(&ctx, data->data, data->head.szdata);
      MD5_Final(data->head.hash, &ctx);
      for(szdata=0;szdata<data->head.szdata;szdata+=8){
        BF_encrypt((BF_LONG *)(data->data + szdata), &EncKey);
      }
    }
  }
  return(szdata);
}

static int msend_packet(int s, mdata *data, struct sockaddr_in *addr)
{
  int r;
  int szdata;
  mdata senddata;
  fd_set fds;
  struct timeval tv;

  memcpy(&senddata, data, sizeof(senddata));
  szdata = msend_encrypt(&senddata);

  senddata.head.szdata = htons(senddata.head.szdata);
  senddata.head.flags  = htons(senddata.head.flags);
  senddata.head.reqid  = htonl(senddata.head.reqid);
  senddata.head.seqno  = htonl(senddata.head.seqno);
  senddata.head.maddr  = htonl(senddata.head.maddr);
  senddata.head.mport  = htons(senddata.head.mport);
  senddata.head.error  = htonl(senddata.head.error);
  szdata += sizeof(mhead);
 
  while(1){ 
    FD_ZERO(&fds);
    FD_SET(moption.mcsocket, &fds);
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    if(select(1024, NULL, &fds, NULL, &tv) != 1){
      if(!loop_flag){
        return(-1);
      }
      continue;
    }
    r = sendto(s, &senddata, szdata, 0, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
    if(r == szdata){
      return(1);
    }
    if(r == -1){
      if(errno == EAGAIN){
        lprintf(0,"%s: EAGAIN\n", __func__);
        return(-1);
      }
      if(errno == EINTR){
        continue;
      }else{
        break;
      }
    }
  }
  if(r != -1){
    lprintf(0, "%s: send size error %s %s rid=%d datasize=%d sendsize=%d seqno=%d\n",
      __func__,
      stropcode(data), 
      strmstate(data),
      data->head.reqid,
      szdata, 
      r, 
      data->head.seqno);
    return(0);
  }
  lprintf(0,"%s: send error (%s) %s %s rid=%d size=%d seqno=%d\n",
    __func__,
    strerror(errno), 
    stropcode(data), 
    strmstate(data),
    data->head.reqid, 
    szdata, 
    data->head.seqno);
  return(-1);
}

/* retry */
static int msend_retry(mfile *m)
{
  uint8_t *r;
  mhost   *t;

  if(!m){
    return(-1);
  }
  if(!m->sendwait){
    m->retrycnt = MAKUO_SEND_RETRYCNT;
    return(0);
  }
  if(m->mdata.head.opcode == MAKUO_OP_DSYNC){
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_CLOSE){
      return(0);
    }
  }
  lprintf(2, "%s: send retry count=%02d rid=%06d op=%s state=%s %s\n", 
    __func__,
    m->retrycnt, 
    m->mdata.head.reqid, 
    stropcode(&(m->mdata)),
    strmstate(&(m->mdata)), 
    m->fn);
  for(t=members;t;t=t->next){
    r = get_hoststate(t, m);
    if(!r){
      lprintf(0, "%s: can't alloc state area %s\n",
        __func__, 
        t->hostname);
      continue;
    }
    switch(moption.loglevel){
      case 3:
        if(*r == MAKUO_RECVSTATE_NONE){
          lprintf(0, "%s:   %s %s(%s)\n", 
            __func__, 
           strrstate(*r), 
           inet_ntoa(t->ad), 
           t->hostname);
        }
        break;
      default:
        lprintf(4, "%s:   %s %s(%s)\n", 
          __func__, 
          strrstate(*r), 
          inet_ntoa(t->ad), 
          t->hostname);
        break;
    }
  }
  m->retrycnt--;
  return(0);
}

/* send & free */
static void msend_shot(int s, mfile *m)
{
  if(msend_packet(s, &(m->mdata), &(m->addr)) == 1){
    msend_mfdel(m);
  }
}

/******************************************************************
*
* ack send functions (for destination node tasks)
*
*******************************************************************/
static void msend_ack_ping(int s, mfile *m)
{
  msend_shot(s, m);
}

static void msend_ack_send(int s, mfile *m)
{
  msend_shot(s, m);
}

static void msend_ack_md5(int s, mfile *m)
{
  msend_shot(s, m);
}

static void msend_ack_dsync(int s, mfile *m)
{
  msend_shot(s, m);
}

static void msend_ack_del(int s, mfile *m)
{
  msend_shot(s, m);
}

static void msend_ack(int s, mfile *m)
{
  switch(m->mdata.head.opcode){
    case MAKUO_OP_PING:
      msend_ack_ping(s, m);
      break;
    case MAKUO_OP_EXIT:
      break;
    case MAKUO_OP_SEND:
      msend_ack_send(s, m);
      break;
    case MAKUO_OP_MD5:
      msend_ack_md5(s, m);
      break;
    case MAKUO_OP_DSYNC:
      msend_ack_dsync(s, m);
      break;
    case MAKUO_OP_DEL:
      msend_ack_del(s, m);
      break;
    /* 機能追加はここ */
  }
}

/******************************************************************
*
* req send functions (for source node tasks)
*
*******************************************************************/
static void msend_req_send_break_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_send_break(int s, mfile *m)
{
  lprintf(9, "%s: BREAK %s\n", __func__, m->fn);
  if(m->initstate){
    msend_req_send_break_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  msend_mfdel(m);
}

static void msend_req_send_stat_init(int s, mfile *m)
{
  mstat    fs;
  uint64_t dev;

  if(!m->comm){
    msend_mfdel(m);
    m = NULL;
    return;
  }

  m->mdata.p = m->mdata.data;
  m->mdata.head.szdata  = sizeof(fs);
  m->mdata.head.szdata += strlen(m->fn);
  m->mdata.head.szdata += strlen(m->ln);
  m->mdata.head.szdata += sizeof(uint64_t);
  if(m->mdata.head.szdata > MAKUO_BUFFER_SIZE){
    lprintf(0, "%s: buffer size over size=%d file=%s\n",   __func__, m->mdata.head.szdata, m->fn);
    cprintf(0, m->comm, "error: buffer size over size=%d file=%s\n", m->mdata.head.szdata, m->fn);
    return;
  }
  fs.mode  = htonl(m->fs.st_mode);
  fs.uid   = htons(m->fs.st_uid);
  fs.gid   = htons(m->fs.st_gid);
  fs.sizel = htonl((uint32_t)(m->fs.st_size & 0xFFFFFFFF));
  fs.sizeh = htonl((uint32_t)(m->fs.st_size >> 32));
  fs.mtime = htonl(m->fs.st_mtime);
  fs.ctime = htonl(m->fs.st_ctime);
  fs.fnlen = htons(strlen(m->fn));
  fs.lnlen = htons(strlen(m->ln));
  dev = (uint64_t)(m->fs.st_rdev);

  m->mdata.head.szdata = 0;
  data_safeset(&(m->mdata), &fs, sizeof(fs));
  data_safeset(&(m->mdata), m->fn, strlen(m->fn));
  data_safeset(&(m->mdata), m->ln, strlen(m->ln));
  data_safeset32(&(m->mdata), (uint32_t)(dev >> 32));
  data_safeset32(&(m->mdata), (uint32_t)(dev & 0xFFFFFFFF));
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_send_stat_delete_report(mfile *m)
{
  mhost   *t;
  uint8_t *r;
  char *dryrun = "";

  if(m->dryrun){
    dryrun = "(dryrun) ";
    if(ack_check(m, MAKUO_RECVSTATE_DELETEOK) == 1){
      if(m->comm){
        if(m->comm->loglevel == 0){
          cprintf(0, m->comm, "%s[delete:%s]\n", dryrun, m->fn);
        }
      }
    }
  }

  for(t=members;t;t=t->next){
    if(m->sendto){
      if(t != member_get(&(m->addr.sin_addr))){
        continue;
      }
    }
    if(r = get_hoststate(t, m)){
      if(*r == MAKUO_RECVSTATE_DELETEOK){
        cprintf(1, m->comm, "%sdelete %s:%s\n", dryrun, t->hostname, m->fn);
        lprintf(1, "%sdelete %s:%s\n", dryrun, t->hostname, m->fn);
      }
    }
  }
}

static void msend_req_send_stat_update_report(mfile *m)
{
  uint8_t *r;
  mhost   *t;
  char *dryrun = "";

  if(m->dryrun){
    dryrun = "(dryrun) ";
    if(ack_check(m, MAKUO_RECVSTATE_UPDATE) == 1){
      if(m->comm){
        if(m->comm->loglevel == 0){
          cprintf(0, m->comm, "%s[update:%s]\n", dryrun, m->fn);
        }
      }
    }
  }

  for(t=members;t;t=t->next){
    if(m->sendto){
      if(t != member_get(&(m->addr.sin_addr))){
        continue;
      }
    }
    if(r = get_hoststate(t, m)){
      if(*r == MAKUO_RECVSTATE_UPDATE){
        cprintf(1, m->comm, "%supdate %s:%s\r\n", dryrun, t->hostname, m->fn);
        lprintf(1, "%supdate %s:%s\n", dryrun, t->hostname, m->fn);
      }
      if(*r == MAKUO_RECVSTATE_SKIP){
        cprintf(2, m->comm, "%sskip   %s:%s\r\n", dryrun, t->hostname, m->fn);
        lprintf(2, "%sskip   %s:%s\n", dryrun, t->hostname, m->fn);
      }
      if(*r == MAKUO_RECVSTATE_READONLY){
        cprintf(2, m->comm, "%sskipro %s:%s\r\n", dryrun, t->hostname, m->fn);
        lprintf(2, "%sskipro %s:%s\n", dryrun, t->hostname, m->fn);
      }
    }
  }
}

static void msend_req_send_stat(int s, mfile *m)
{
  if(m->initstate){
    msend_req_send_stat_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"%s: STAT %s\n", __func__, m->fn);
  if(m->mdata.head.flags & MAKUO_FLAG_SYNC){
    msend_req_send_stat_delete_report(m);
    m->initstate = 1;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_SENDSTATE_LAST;
  }else{
    msend_req_send_stat_update_report(m);
    m->initstate = 1;
    m->mdata.head.ostate = m->mdata.head.nstate;
    if(m->dryrun){
      m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    }else{
      if(ack_check(m, MAKUO_RECVSTATE_UPDATE) == 1){
        m->mdata.head.nstate = MAKUO_SENDSTATE_OPEN;
      }else{
        m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
      }
    }
  }
}

static void msend_req_send_open_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_UPDATE);

  /*----- symlink -----*/
  if(S_ISLNK(m->fs.st_mode) || !S_ISREG(m->fs.st_mode)){
    msend_packet(s, &(m->mdata), &(m->addr));
  }else{
    m->fd = open(m->fn, O_RDONLY, 0);
    if(m->fd != -1){
      msend_packet(s, &(m->mdata), &(m->addr));
    }else{
      m->sendwait  = 0;
      m->initstate = 1;
      m->mdata.head.ostate = m->mdata.head.nstate;
      m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
      cprintf(0, m->comm, "error: can't open (%s) %s\n", strerror(errno), m->fn);
      lprintf(0, "%s: can't open (%s) %s\n", __func__,   strerror(errno), m->fn);
    }
  }
}

static void msend_req_send_open(int s, mfile *m)
{
  lprintf(9,"%s: %s\n", __func__, m->fn);
  if(m->initstate){
    msend_req_send_open_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9, "%s: OPEN %s\n", __func__, m->fn);
  if(ack_check(m, MAKUO_RECVSTATE_UPDATE) == 1){
    m->sendwait = 1;
    ack_clear(m, MAKUO_RECVSTATE_UPDATE);
    return;
  }
  if(S_ISLNK(m->fs.st_mode) || !S_ISREG(m->fs.st_mode)){
    m->initstate = 1;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
  }else{
    m->mdata.head.seqno  = 0;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_SENDSTATE_DATA;
  }
}

static void msend_req_send_markdata(int s, mfile *m)
{
  int   r;
  off_t offset;
  if(!m->mark){
    /* close */
    m->initstate = 1;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    return;
  }
  m->mdata.head.seqno = seq_getmark(m);
  offset = m->mdata.head.seqno;
  offset *= MAKUO_BUFFER_SIZE;
  lprintf(9, "%s: block send retry seqno=%u count=%u\n", __func__, m->mdata.head.seqno, m->markcount);
  lseek(m->fd, offset, SEEK_SET);
  r = read(m->fd, m->mdata.data, MAKUO_BUFFER_SIZE);
  if(r>0){
    m->mdata.head.szdata = r;
    msend_packet(s, &(m->mdata), &(m->addr));
  }else{
    if(!r){
      lprintf(0, "%s: read eof? seqno=%d\n", __func__, m->mdata.head.seqno);
    }else{
      lprintf(0, "%s: can't read (%s) seqno=%d %s\n",   __func__, strerror(errno), m->mdata.head.seqno, m->fn);
      cprintf(0, m->comm, "error: can't read (%s) seqno=%d %s\n", strerror(errno), m->mdata.head.seqno, m->fn);
    }
  }
  if(!m->mark){
    m->initstate = 1;
    m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
  }
}

static void msend_req_send_filedata(int s, mfile *m)
{
  off_t offset;
  int readsize;
  if(m->mark){
    m->mdata.head.seqno = seq_getmark(m);
  }else{
    m->mdata.head.seqno = m->seqnonow++;
  }
  offset  = m->mdata.head.seqno;
  offset *= MAKUO_BUFFER_SIZE;
  lseek(m->fd, offset, SEEK_SET);
  readsize = read(m->fd, m->mdata.data, MAKUO_BUFFER_SIZE);
  if(readsize > 0){
    m->mdata.head.szdata = readsize;
    msend_packet(s, &(m->mdata), &(m->addr));
  }else{
    if(readsize == -1){
      /* err */
      lprintf(0, "%s: can't read (%s) seqno=%d %s\n",   __func__, strerror(errno), m->mdata.head.seqno, m->fn);
      cprintf(0, m->comm, "error: can't read (%s) seqno=%d %s\n", strerror(errno), m->mdata.head.seqno, m->fn);
    }else{
      /* eof */
      lprintf(4, "%s: block send count=%d %s\n", __func__, m->mdata.head.seqno, m->fn);
      m->mdata.head.seqno  = 0;
      m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
      m->initstate = 1;
      m->lickflag  = 1;
    }
  }
}

static void msend_req_send_data(int s, mfile *m)
{
  if(m->lickflag){
    msend_req_send_markdata(s, m); /* send retry */
  }else{
    msend_req_send_filedata(s, m); /* send data  */
  }
}

static void msend_req_send_mark_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_UPDATE);
  ack_clear(m, MAKUO_RECVSTATE_OPEN);
  ack_clear(m, MAKUO_RECVSTATE_MARK);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_send_mark(int s, mfile *m)
{
  if(m->initstate){
    msend_req_send_mark_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(ack_check(m, MAKUO_RECVSTATE_UPDATE) == 1){
    msend_req_send_mark_init(s, m);
    return;
  }
  if(ack_check(m, MAKUO_RECVSTATE_OPEN) == 1){
    msend_req_send_mark_init(s, m);
    return;
  }
  lprintf(9, "%s: MARK mark=%d %s\n", __func__, m->markcount, m->fn);
  m->mdata.head.nstate = MAKUO_SENDSTATE_DATA;
}

static void msend_req_send_close_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_UPDATE);
  ack_clear(m, MAKUO_RECVSTATE_OPEN);
  ack_clear(m, MAKUO_RECVSTATE_MARK);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_send_close(int s, mfile *m)
{
  if(m->initstate){
    msend_req_send_close_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(ack_check(m, MAKUO_RECVSTATE_UPDATE) == 1){
    msend_req_send_close_init(s, m);
    return;
  }
  if(ack_check(m, MAKUO_RECVSTATE_OPEN) == 1){
    msend_req_send_close_init(s, m);
    return;
  }
  if(ack_check(m, MAKUO_RECVSTATE_MARK) == 1){
    msend_req_send_close_init(s, m);
    return;
  }
  if(m->mdata.head.ostate == MAKUO_SENDSTATE_MARK || 
     m->mdata.head.ostate == MAKUO_SENDSTATE_DATA ||
     m->mdata.head.ostate == MAKUO_SENDSTATE_OPEN){
    lprintf(6,"%s: update complate %s \n", __func__, m->fn);
  }
  m->initstate = 1;
  m->mdata.head.nstate = MAKUO_SENDSTATE_LAST;
}

static void msend_req_send_last_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_send_last(int s, mfile *m)
{
  if(m->initstate){
    msend_req_send_last_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  msend_mfdel(m);
}

/*----- send -----*/
static void msend_req_send(int s, mfile *m)
{
  if(!m->comm){
    if(m->mdata.head.nstate != MAKUO_SENDSTATE_BREAK){
      m->initstate = 1;
      m->mdata.head.nstate = MAKUO_SENDSTATE_BREAK;
    }
  }
  switch(m->mdata.head.nstate){
    case MAKUO_SENDSTATE_STAT:
      msend_req_send_stat(s, m);
      break;
    case MAKUO_SENDSTATE_OPEN:
      msend_req_send_open(s, m);
      break;
    case MAKUO_SENDSTATE_DATA:
      msend_req_send_data(s, m);
      break;
    case MAKUO_SENDSTATE_MARK:
      msend_req_send_mark(s, m);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      msend_req_send_close(s, m);
      break;
    case MAKUO_SENDSTATE_LAST:
      msend_req_send_last(s, m);
      break;
    case MAKUO_SENDSTATE_BREAK:
      msend_req_send_break(s, m);
      break;
  }
}

static void msend_req_md5_open_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  m->mdata.head.nstate = MAKUO_SENDSTATE_OPEN;
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_md5_open(int s, mfile *m)
{
  if(m->initstate){
    lprintf(9,"%s: %s\n", __func__, m->fn);
    msend_req_md5_open_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->initstate = 1;
  m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
}

static void msend_req_md5_close_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_MD5OK);
  ack_clear(m, MAKUO_RECVSTATE_MD5NG);
  m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_md5_close(int s, mfile *m)
{
  if(m->initstate){
    msend_req_md5_close_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"%s: %s\n", __func__, m->fn);
  msend_mfdel(m);
}

/*----- md5 -----*/
static void msend_req_md5(int s, mfile *m)
{
  switch(m->mdata.head.nstate){
    case MAKUO_SENDSTATE_OPEN:
      msend_req_md5_open(s, m);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      msend_req_md5_close(s, m);
      break;
  }
}

static void msend_req_dsync_open(int s, mfile *m)
{
  lprintf(9, "%s: init=%d wait=%d\n", __func__, m->initstate, m->sendwait);
  if(m->initstate){
    m->initstate = 0;
    m->sendwait  = 1;
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->initstate = 1;
  m->mdata.head.nstate = MAKUO_SENDSTATE_DATA;
}

static void msend_req_dsync_data_init(int s, mfile *m)
{
  uint16_t len;
  int excludecnt = 0;
  excludeitem *e = NULL;

  m->sendwait  = 1;
  m->initstate = 0;
  for(e=m->comm->exclude;e;e=e->next){
    if(excludecnt == m->mdata.head.seqno){
      break;
    }
    excludecnt++;
  }
  m->mdata.head.szdata = 0;
  while(e){
    len = strlen(e->pattern);
    if(m->mdata.head.szdata + sizeof(uint16_t) + len > MAKUO_BUFFER_SIZE){
      break;
    }
    data_safeset16(&(m->mdata), len);
    data_safeset(&(m->mdata), e->pattern, len);
    lprintf(9, "%s: exclude add %s\n", __func__, e->pattern);
    m->mdata.head.seqno++;
    e = e->next;
  }
  if(m->mdata.head.szdata == 0){
    m->mdata.head.seqno++;
  }
  lprintf(9,"%s: rid=%d seqno=%d size=%d\n", __func__, m->mdata.head.reqid, m->mdata.head.seqno, m->mdata.head.szdata);
}

static void msend_req_dsync_data(int s, mfile *m)
{
  lprintf(9, "%s: init=%d wait=%d\n", __func__, m->initstate, m->sendwait);
  if(m->initstate){
    msend_req_dsync_data_init(s, m);
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->initstate = 1;
  if(m->mdata.head.szdata == 0){
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
  }
}

static void msend_req_dsync_close(int s, mfile *m)
{
  lprintf(9, "%s: init=%d wait=%d\n", __func__, m->initstate, m->sendwait);
  if(m->initstate){
    m->sendwait  = 1;
    m->initstate = 0;
    ack_clear(m, MAKUO_RECVSTATE_OPEN);
    return;
  }
  if(m->sendwait){
    return;
  }
  msend_mfdel(m);
}

static void msend_req_dsync_break(int s, mfile *m)
{
  lprintf(9, "%s: init=%d wait=%d\n", __func__, m->initstate, m->sendwait);
  if(m->initstate){
    m->initstate = 0;
    m->sendwait  = 1;
    ack_clear(m, -1);
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  msend_mfdel(m);
}

/*----- dsync -----*/
static void msend_req_dsync(int s, mfile *m)
{
  lprintf(9, "%s: rid=%d %s %s\n", __func__, m->mdata.head.reqid, stropcode(&(m->mdata)), strmstate(&(m->mdata)));
  if(m->mdata.head.nstate != MAKUO_SENDSTATE_LAST){
    if(!m->comm){
      if(m->mdata.head.nstate != MAKUO_SENDSTATE_BREAK){
        m->initstate = 1;
        m->mdata.head.nstate = MAKUO_SENDSTATE_BREAK;
      }
    }
  }
  switch(m->mdata.head.nstate){
    case MAKUO_SENDSTATE_OPEN:
      msend_req_dsync_open(s, m);
      break;
    case MAKUO_SENDSTATE_DATA:
      msend_req_dsync_data(s, m);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      msend_req_dsync_close(s, m);
      break;
    case MAKUO_SENDSTATE_BREAK:
      msend_req_dsync_break(s, m);
      break;
    case MAKUO_SENDSTATE_LAST:
      msend_shot(s, m);
      break;
  }
}

static void msend_req_del_mark(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  mfile *d = m->link; /* dsync object */
  if(m->initstate){
    m->initstate = 0;
    m->sendwait  = 1;
    ack_clear(m, -1);
    if(member_get(&(d->addr.sin_addr))){
      mkack(&(d->mdata), &(d->addr), MAKUO_RECVSTATE_CLOSE);
    }else{
      d->lastrecv.tv_sec = 1;
    }
    return;
  }
  if(m->sendwait){
    if(member_get(&(d->addr.sin_addr))){
      mkack(&(d->mdata), &(d->addr), MAKUO_RECVSTATE_CLOSE);
    }else{
      d->lastrecv.tv_sec = 1;
    }
    return;
  }
}

static void msend_req_del_stat(int s, mfile *m)
{
  int    r;
  mfile *a;
  mfile *d;
  static uint16_t len = 0;
  static char path[PATH_MAX + sizeof(uint32_t)];

  if(m->pid == 0){
    for(d=mftop[0];d;d=d->next){
      if((d->mdata.head.opcode == MAKUO_OP_DEL) && (d->link == m)){
        m->sendwait = 1;
        return;
      }
    }
    m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
    m->initstate = 1;
    m->sendwait  = 0;
    ack_clear(m, -1);
    return;
  }

  if(m->pipe == -1){
    if(waitpid(m->pid, NULL, WNOHANG) == m->pid){
      m->pid = 0;
    }else{
      m->sendwait = 1;
    }
    return;
  }

  lprintf(9, "%s:\n", __func__);
  d = mkreq(&(m->mdata), &(m->addr), MAKUO_SENDSTATE_OPEN);
  d->mdata.head.flags = m->mdata.head.flags;
  d->mdata.head.reqid = getrid();
  d->initstate = 1;
  d->sendwait  = 0;
  d->sendto = 1;
  d->dryrun = m->dryrun;
  d->recurs = m->recurs;
  d->link   = m;
  d->mdata.p = d->mdata.data;

  if(len){
    data_safeset16(&(d->mdata), len);
    data_safeset(&(d->mdata), path, len);
    lprintf(9, "%s: rid=%d %s\n", __func__, d->mdata.head.reqid, path + sizeof(uint32_t));
  }

  while(1){
    if(atomic_read(m->pipe, &len, sizeof(len))){
      close(m->pipe);
      m->pipe = -1;
      m->initstate = 1;
      m->sendwait  = 0;
      break;
    }
    if(atomic_read(m->pipe, path, len)){
      lprintf(0, "%s: pipe read error\n", __func__);
      close(m->pipe);
      m->pipe = -1;
      m->initstate = 1;
      m->sendwait  = 0;
      break;
    }
    path[len] = 0;

    for(a=mftop[1];a;a=a->next){
      if(!strcmp(a->tn, path + sizeof(uint32_t))){
        break;
      }
    }
    if(a){
      continue;
    }
    if(d->mdata.head.szdata + sizeof(len) + len > MAKUO_BUFFER_SIZE){
      break;
    }
    data_safeset16(&(d->mdata), len);
    data_safeset(&(d->mdata), path, len);
    lprintf(9, "%s: rid=%d %s\n", __func__, d->mdata.head.reqid, path + sizeof(uint32_t));
  }
}

static void msend_req_del_last(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  msend_mfdel(m);
}

static void msend_req_del_break(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  if(m->link){
    m->link->lastrecv.tv_sec = 1;
  }
  msend_mfdel(m);
}

static void msend_req_del_open(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  if(m->initstate){
    m->initstate = 0;
    m->sendwait  = 1;
    ack_clear(m, -1);
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->initstate = 1;
}

static void msend_req_del_data(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  if(m->initstate){
    m->initstate = 0;
    m->sendwait  = 1;
    ack_clear(m, -1);
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->initstate = 1;
  m->sendwait  = 0;
  m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
}

static void msend_req_del_close(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  if(m->initstate){
    m->initstate = 0;
    m->sendwait  = 1;
    ack_clear(m, -1);
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->link->sendwait = 0;
  msend_mfdel(m);
}

/*----- del -----*/
static void msend_req_del(int s, mfile *m)
{
  switch(m->mdata.head.nstate){
    case MAKUO_SENDSTATE_STAT:
      msend_req_del_stat(s, m);
      break;
    case MAKUO_SENDSTATE_MARK:
      msend_req_del_mark(s, m);
      break;
    case MAKUO_SENDSTATE_LAST:
      msend_req_del_last(s, m);
      break;
    case MAKUO_SENDSTATE_BREAK:
      msend_req_del_break(s, m);
      break;
    case MAKUO_SENDSTATE_OPEN:
      msend_req_del_open(s, m);
      break;
    case MAKUO_SENDSTATE_DATA:
      msend_req_del_data(s, m);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      msend_req_del_close(s, m);
      break;
  }
}

/*----- exit -----*/
static void msend_req_exit(int s, mfile *m)
{
  msend_shot(s, m);
}

/*----- ping -----*/
static void msend_req_ping(int s, mfile *m)
{
  msend_shot(s, m);
}

/*----- send request -----*/
static void msend_req(int s, mfile *m)
{
  lprintf(9, "%s: rid=%d %s %s init=%d wait=%d\n",
    __func__, 
    m->mdata.head.reqid, 
    stropcode(&(m->mdata)), 
    strmstate(&(m->mdata)), 
    m->initstate, 
    m->sendwait);
  switch(m->mdata.head.opcode){
    case MAKUO_OP_PING:
      msend_req_ping(s, m);
      break;
    case MAKUO_OP_EXIT:
      msend_req_exit(s, m);
      break;
    case MAKUO_OP_SEND:
      msend_req_send(s, m);
      break;
    case MAKUO_OP_MD5:
      msend_req_md5(s, m);
      break;
    case MAKUO_OP_DSYNC:
      msend_req_dsync(s, m);
      break;
    case MAKUO_OP_DEL:
      msend_req_del(s, m);
      break;
    /* 機能追加はここ */
  }
}

/******************************************************************
*
* send common functions (public)
*
*******************************************************************/
void msend(int s, mfile *m)
{
  if(msend_retry(m)){
    return;
  }
  lprintf(9, "%s: %s %s %s rid=%d seq=%d\n", 
    __func__, 
    strackreq(&(m->mdata)),
    stropcode(&(m->mdata)), 
    strmstate(&(m->mdata)),
    m->mdata.head.reqid, 
    m->mdata.head.seqno); 
  mtimeget(&m->lastsend);
  if(m->mdata.head.flags & MAKUO_FLAG_ACK){
    msend_ack(s, m); /* source node task */
  }else{
    msend_req(s, m); /* destination node task */
  }
}

void msend_clean()
{
  mfile *m = mftop[0];
  while(m=msend_mfdel(m));
}


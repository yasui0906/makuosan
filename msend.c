/*
 * msend.c
 * Copyright (C) 2008 KLab Inc. 
 */
#include "makuosan.h"

static void msend_ack(int s, mfile *m);
static void msend_req(int s, mfile *m);

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
  if(m->mark){
    free(m->mark);
  }
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

  memcpy(&senddata, data, sizeof(senddata));
  szdata = msend_encrypt(&senddata);

  senddata.head.szdata = htons(senddata.head.szdata);
  senddata.head.flags  = htons(senddata.head.flags);
  senddata.head.reqid  = htonl(senddata.head.reqid);
  senddata.head.seqno  = htonl(senddata.head.seqno);
 
  while(1){ 
    r = sendto(s, &senddata, sizeof(mhead) + szdata, 0, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
    if(r == sizeof(mhead) + szdata){
      break;
    }else{
      if(r != -1){
        lprintf(0,"%s: size error sock=%d op=%d rid=%d state=%s size=%d send=%d seqno=%d\n", __func__,
          s, data->head.opcode, data->head.reqid, SSTATE(data->head.nstate), sizeof(mhead) + szdata, r, data->head.seqno);
        return(0);
      }else{
        if(errno == EINTR){
          continue;
        }else{
          lprintf(0,"%s: send error (%s) sock=%d op=%d rid=%d state=%s size=%d seqno=%d\n", __func__,
            strerror(errno), s, data->head.opcode, data->head.reqid, SSTATE(data->head.nstate), sizeof(mhead) + szdata, data->head.seqno);
          return(-1);
        }
      }
    }
  }
  return(1);
}

/* retry */
static void msend_retry(mfile *m)
{
  uint8_t *r;
  mhost   *t;

  if(!m->sendwait){
    m->retrycnt = MAKUO_SEND_RETRYCNT;
    return;
  }
  if(m->mdata.head.opcode == MAKUO_OP_DSYNC){
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_CLOSE){
      return;
    }
  }
  lprintf(2, "%s: send retry count=%02d rid=%06d op=%s state=%s %s\n", 
    __func__,
    m->retrycnt, 
    m->mdata.head.reqid, 
    OPCODE(m->mdata.head.opcode), 
    SSTATE(m->mdata.head.nstate), 
    m->fn);
  for(t=members;t;t=t->next){
    r = get_hoststate(t, m);
    if(!r){
      lprintf(0, "%s:   can't alloc state area\n", __func__);
      continue;
    }
    switch(moption.loglevel){
      case 3:
        if(*r == MAKUO_RECVSTATE_NONE){
          lprintf(0, "%s:   %s %s(%s)\n", 
            __func__, 
           RSTATE(*r), 
           inet_ntoa(t->ad), 
           t->hostname);
        }
        break;
      default:
        lprintf(4, "%s:   %s %s(%s)\n", 
          __func__, 
          RSTATE(*r), 
          inet_ntoa(t->ad), 
          t->hostname);
        break;
    }
  }
  m->retrycnt--;
}

/* send & free */
static void msend_shot(int s, mfile *m)
{
  msend_packet(s, &(m->mdata), &(m->addr));
  msend_mfdel(m);
}

/******************************************************************
*
* send common functions (public)
*
*******************************************************************/
void msend(int s, mfile *m)
{
  if(!m){
    return;
  }
  msend_retry(m);
  mtimeget(&m->lastsend);
  if(m->mdata.head.flags & MAKUO_FLAG_ACK){
    msend_ack(s, m); /* source node task */
  }else{
    msend_req(s, m); /* destination node task */
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
  if(m->markcount){
    m->mdata.head.szdata = m->marksize * sizeof(uint32_t);
    memcpy(m->mdata.data, m->mark, m->marksize * sizeof(uint32_t));
  }
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
  lprintf(9, "%s:\n", __func__);
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
static void msend_req_send_break(int s, mfile *m)
{
  lprintf(9, "%s: BREAK %s\n", __func__, m->fn);
  msend_packet(s, &(m->mdata), &(m->addr));
  msend_mfdel(m);
}

static void msend_req_send_stat_init(int s, mfile *m)
{
  mstat    fs;
  uint64_t rdev;
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
    lprintf(0, "%s: buffer size over size=%d file=%s\n", __func__, m->mdata.head.szdata, m->fn);
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
  memcpy(m->mdata.p, &fs, sizeof(fs));
  m->mdata.p += sizeof(fs);
  strcpy(m->mdata.p, m->fn);
  m->mdata.p += strlen(m->fn);
  strcpy(m->mdata.p, m->ln);
  m->mdata.p += strlen(m->ln);

  rdev = (uint64_t)(m->fs.st_rdev);
  *(uint32_t *)(m->mdata.p) = htonl((uint32_t)(rdev >> 32));
  m->mdata.p += sizeof(uint32_t);
  *(uint32_t *)(m->mdata.p) = htonl((uint32_t)(rdev & 0xFFFFFFFF));
  m->mdata.p += sizeof(uint32_t);
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_send_stat(int s, mfile *m)
{
  uint8_t *r;
  mhost   *t;

  if(m->initstate){
    msend_req_send_stat_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"%s: STAT %s\n", __func__, m->fn);
  if(m->dryrun){
    if(ack_check(m, MAKUO_RECVSTATE_UPDATE) != 1){
      cprintf(5, m->comm, "(%s)\r\n", m->fn);
    }else{
      cprintf(0, m->comm, "[%s]\r\n", m->fn);
      if(!m->sendto){
        for(t=members;t;t=t->next){
          r = get_hoststate(t, m);
          if(*r == MAKUO_RECVSTATE_UPDATE)
            cprintf(1, m->comm, "%s: update\r\n", t->hostname);
          if(*r == MAKUO_RECVSTATE_SKIP)
            cprintf(2, m->comm, "%s: skip\r\n", t->hostname);
          if(*r == MAKUO_RECVSTATE_READONLY)
            cprintf(2, m->comm, "%s: skip(read only)\r\n", t->hostname);
        }
      }
    }
    m->initstate = 1;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
  }else{
    if(ack_check(m, MAKUO_RECVSTATE_UPDATE) != 1){
      cprintf(5, m->comm, "(%s)\r\n", m->fn);
      m->initstate = 1;
      m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    }else{
      lprintf(1, "%s: update %s\n", __func__, m->fn);
      cprintf(1, m->comm, "[%s]\r\n", m->fn);
      if(!m->sendto){
        for(t=members;t;t=t->next){
          r = get_hoststate(t, m);
          if(*r == MAKUO_RECVSTATE_UPDATE)
            cprintf(2, m->comm, "%s: update\r\n", t->hostname);
          if(*r == MAKUO_RECVSTATE_SKIP)
            cprintf(3, m->comm, "%s: skip\r\n", t->hostname);
          if(*r == MAKUO_RECVSTATE_READONLY)
            cprintf(3, m->comm, "%s: skip(read only)\r\n", t->hostname);
        }
      }
      m->initstate = 1;
      m->mdata.head.ostate = m->mdata.head.nstate;
      m->mdata.head.nstate = MAKUO_SENDSTATE_OPEN;
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
      cprintf(0, m->comm, "error: file open error errno=%d %s\n", errno, m->fn);
      lprintf(0, "%s: open error errno=%d %s\n", __func__, errno, m->fn);
    }
  }
}

static void msend_req_send_open(int s, mfile *m)
{
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
  int r;
  if(!m->markcount){
    /* close */
    m->initstate = 1;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    return;
  }
  m->markcount--;
  lprintf(4, "%s: block send retry seqno=%u count=%u\n", __func__, m->mark[m->markcount], m->markcount);
  m->mdata.head.seqno = m->mark[m->markcount];
  lseek(m->fd, m->mdata.head.seqno * MAKUO_BUFFER_SIZE, SEEK_SET);
  r = read(m->fd, m->mdata.data, MAKUO_BUFFER_SIZE);
  if(r>0){
    m->mdata.head.szdata = r;
    msend_packet(s, &(m->mdata), &(m->addr));
  }else{
    if(!r){
      lprintf(0, "%s: read eof? seqno=%d\n", __func__, m->mdata.head.seqno);
    }else{
      lprintf(0, "%s: read err! seqno=%d errno=%d\n", __func__, m->mdata.head.seqno, errno);
    }
  }
  if(m->markcount == 0){
    m->initstate = 1;
    m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
  }
}

static void msend_req_send_filedata(int s, mfile *m)
{
  int readsize;
  if(m->markcount){
    m->markcount--;
    m->mdata.head.seqno = m->mark[m->markcount];
  }else{
    if(m->seqnonow == 0){
      m->waitspan  = 1024;
      m->waitcount = m->waitspan;
    }
    m->mdata.head.seqno = m->seqnonow++;
  }
  lseek(m->fd, m->mdata.head.seqno * MAKUO_BUFFER_SIZE, SEEK_SET);
  readsize = read(m->fd, m->mdata.data, MAKUO_BUFFER_SIZE);
  if(readsize > 0){
    m->mdata.head.szdata = readsize;
    msend_packet(s, &(m->mdata), &(m->addr));
  }else{
    if(readsize == -1){
      /* err */
      lprintf(0, "%s: read error! seqno=%d errno=%d %s\n", __func__, m->mdata.head.seqno, errno, m->fn);
    }else{
      /* eof */
      lprintf(4, "%s: block send count=%d %s\n", __func__, m->mdata.head.seqno, m->fn);
      m->mdata.head.seqno  = 0;
      m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
      m->initstate = 1;
      m->lickflag  = 1;
    }
  }
  if(m->waitcount){
    m->waitcount--;
  }else{
    m->sendwait = 1;
    ack_clear(m, MAKUO_RECVSTATE_UPDATE);
    ack_clear(m, MAKUO_RECVSTATE_OPEN);
  }
}

static void msend_req_send_data(int s, mfile *m)
{
  if(!m->comm){
    m->mdata.head.seqno  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_BREAK;
    return;
  }
  if(m->sendwait){
    m->mdata.head.seqno  = 0;
    m->mdata.head.szdata = 0;
    m->mdata.head.flags |= MAKUO_FLAG_WAIT;
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->mdata.head.flags & MAKUO_FLAG_WAIT){
    uint32_t wp = m->markcount * 100 / m->waitspan;
    m->mdata.head.flags &= ~MAKUO_FLAG_WAIT;
    /* slow */
    if(m->waitspan > 16){
      if(wp > 50){
        m->waitspan /= 2;
      }
    }
    /* fast */
    if(wp < 10){
      m->waitspan *= 2;
    }
    m->waitcount = m->waitspan;
    lprintf(0,"%s: waitspan=%u markcount=%d\n", __func__, m->waitspan, m->markcount);    
  }
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
    lprintf(1,"%s: update complate %s \n", __func__, m->fn);
  }
  m->mdata.head.nstate = MAKUO_SENDSTATE_LAST;
}

static void msend_req_send_last(int s, mfile *m)
{
  lprintf(9, "%s: LAST %s\n", __func__, m->fn);
  msend_packet(s, &(m->mdata), &(m->addr));
  msend_mfdel(m);
}

/*----- send -----*/
static void msend_req_send(int s, mfile *m)
{
  if(!m->comm){
    msend_mfdel(m);
    return;
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
  m = NULL;
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

static void msend_req_dsync_open_init(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  m->sendwait  = 1;
  m->initstate = 0;
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_dsync_open(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  if(m->initstate){
    msend_req_dsync_open_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->initstate = 1;
  m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
}

static void msend_req_dsync_close_init(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_OPEN);
}

static void msend_req_dsync_close(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  if(m->initstate){
    msend_req_dsync_close_init(s, m);
    return;
  }
  if(m->sendwait){
    return;
  }
  lprintf(9,"%s: %s\n", __func__, m->fn);
  msend_mfdel(m);
}

static void msend_req_dsync_break_init(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_dsync_break(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
  if(m->initstate){
    msend_req_dsync_break_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"%s: m=%p\n", __func__, m);
  msend_mfdel(m);
}

/*----- dsync -----*/
static void msend_req_dsync(int s, mfile *m)
{
  lprintf(9, "%s:\n", __func__);
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
  mkack(&(d->mdata), &(d->addr), MAKUO_RECVSTATE_CLOSE);
}

static void msend_req_del_stat(int s, mfile *m)
{
  int r;
  mfile *d;
  uint8_t stat;
  uint16_t len;
  uint32_t mod;

  lprintf(9, "%s:\n", __func__);
  r = read(m->pipe, &stat, sizeof(stat));
  if(r <= 0){
    /* eof */
    if(waitpid(m->pid, NULL, WNOHANG) == m->pid){
      close(m->pipe);
      m->pipe = -1;
      m->pid  =  0;
    }
    m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
    m->initstate = 1;
    m->sendwait  = 0;
    ack_clear(m, -1);
    return;
  }

  d = mkreq(&(m->mdata), &(m->addr), MAKUO_SENDSTATE_OPEN);
  read(m->pipe, &mod, sizeof(mod));
  read(m->pipe, &len, sizeof(len));
  read(m->pipe, d->fn, len);
  d->fn[len] = 0;
  d->mdata.p = d->mdata.data;
  *(uint32_t *)(d->mdata.p) = htonl(mod);
  d->mdata.p += sizeof(mod);
  *(uint16_t *)(d->mdata.p) = htons(len);
  d->mdata.p += sizeof(len);
  memcpy(d->mdata.p, d->fn, len);
  d->mdata.head.flags  = m->mdata.head.flags;
  d->mdata.head.szdata = sizeof(mod) + sizeof(len) + len;
  d->mdata.head.reqid  = getrid();
  d->initstate = 1;
  d->sendwait  = 0;
  d->dryrun = m->dryrun;
  d->recurs = m->recurs;
  lprintf(9, "%s: fn=%s rid=%d\n", __func__, d->fn, d->mdata.head.reqid);
}

/*----- del -----*/
static void msend_req_del(int s, mfile *m)
{
  if(m->mdata.head.nstate == MAKUO_SENDSTATE_BREAK){
    msend_mfdel(m);
    return;
  }
  if(m->mdata.head.nstate == MAKUO_SENDSTATE_LAST){
    msend_mfdel(m);
    return;
  }
  if(m->mdata.head.nstate == MAKUO_SENDSTATE_STAT){
    msend_req_del_stat(s, m);
    return;
  }
  if(m->initstate){
    m->initstate = 0;
    m->sendwait  = 1;
    ack_clear(m, -1);
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_MARK){
      msend_req_del_mark(s, m);
      return;
    }
    lprintf(9, "%s: SEND_PACKET %s\n", __func__, SSTATE(m->mdata.head.nstate));
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  if(m->sendwait){
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_MARK){
      msend_req_del_mark(s, m);
    }else{
      msend_packet(s, &(m->mdata), &(m->addr));
    }
    return;
  }
  m->initstate = 1;
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


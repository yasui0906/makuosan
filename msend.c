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
  if(!m)
    return(NULL);
  r = m->next;
  if(m->fd != -1)
    close(m->fd);   
  if(m->mark)
    free(m->mark);
  mfdel(m);
  return(r);
}

static int msend_encrypt(mdata *data)
{
  int  szdata;
  MD5_CTX ctx;

  szdata = data->head.szdata;
  if(moption.cryptena && data->head.szdata){
    MD5_Init(&ctx);
    MD5_Update(&ctx, data->data, data->head.szdata);
    MD5_Final(data->head.hash, &ctx);
    for(szdata=0;szdata<data->head.szdata;szdata+=8){
      BF_encrypt((BF_LONG *)(data->data + szdata), &EncKey);
    }
    data->head.flags |= MAKUO_FLAG_CRYPT;
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
        lprintf(0,"%s: size error sock=%d op=%d rid=%d state=%d size=%d send=%d seqno=%d\n", __func__,
          s, data->head.opcode, data->head.reqid, data->head.nstate, sizeof(mhead) + szdata, r, data->head.seqno);
        return(0);
      }else{
        if(errno == EINTR){
          continue;
        }else{
          lprintf(0,"%s: send error errno=%d sock=%d op=%d rid=%d state=%d size=%d seqno=%d\n", __func__,
            errno, s, data->head.opcode, data->head.reqid, data->head.nstate, sizeof(mhead) + szdata, data->head.seqno);
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
  if(!m->sendwait){
    m->retrycnt = MAKUO_SEND_RETRYCNT;
    return;
  }

  mhost *t;
  lprintf(2, "%s: send retry count=%02d rid=%06d state=%d %s\n", __func__,
    m->retrycnt, m->mdata.head.reqid, m->mdata.head.nstate, m->fn);
  for(t=members;t;t=t->next){
    switch(moption.loglevel){
      case 3:
        if(t->state == MAKUO_RECVSTATE_NONE){
          lprintf(0, "%s:   state=%d %s(%s)\n", __func__, t->state, inet_ntoa(t->ad), t->hostname);
        }
        break;
      default:
        lprintf(4, "%s:   state=%d %s(%s)\n", __func__, t->state, inet_ntoa(t->ad), t->hostname);
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
    msend_ack(s, m);  /* source node task */
  }else{
    msend_req(s, m);  /* destination node task */
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

static void msend_req_send_markdata(int s, mfile *m)
{
  int i;
  int r;
  if(!m->markcount){
    /* close */
    m->initstate = 1;
    m->mdata.head.seqno  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    lprintf(4, "%s: file send complate! %s\n", __func__, m->fn);
    return;
  }
  lprintf(4, "%s: block send retry %d\n", __func__, m->markcount);
  for(i=0;i<m->markcount;i++){
    m->mdata.head.seqno = m->mark[i];
    lseek(m->fd, (m->mdata.head.seqno - 1) * MAKUO_BUFFER_SIZE, SEEK_SET);
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
  }
  /* eof */
  m->markcount = 0;
  m->initstate = 1;
  m->mdata.head.seqno  = 0;
  m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
}

static void msend_req_send_filedata(int s, mfile *m)
{
  int readsize;
  lseek(m->fd, (m->mdata.head.seqno - 1) * MAKUO_BUFFER_SIZE, SEEK_SET);
  readsize = read(m->fd, m->mdata.data, MAKUO_BUFFER_SIZE);
  if(readsize > 0){
    m->mdata.head.szdata = readsize;
    if(msend_packet(s, &(m->mdata), &(m->addr)) == 1){
      m->mdata.head.seqno++;
    }
  }else{
    if(readsize == -1){
      /* err */
      lprintf(0, "%s: read error! seqno=%d errno=%d\n", __func__, m->mdata.head.seqno, errno);
    }else{
      /* eof */
      lprintf(4, "%s: block send count=%d\n", __func__, m->mdata.head.seqno);
      m->mdata.head.seqno = 0;
      m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
      m->initstate = 1;
      m->lickflag  = 1;
    }
  }
}

static void msend_req_send_stat_init(int s, mfile *m)
{
  mstat fs;
  if(!m->comm){
    msend_mfdel(m);
    m = NULL;
    return;
  }
  m->mdata.p = m->mdata.data;
  m->mdata.head.szdata  = sizeof(fs);
  m->mdata.head.szdata += strlen(m->fn);
  m->mdata.head.szdata += strlen(m->ln);
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
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_req_send_stat(int s, mfile *m)
{
  mhost *h;

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
        for(h=members;h;h=h->next){
          if(h->state == MAKUO_RECVSTATE_UPDATE)
            cprintf(1, m->comm, "%s: update\r\n", h->hostname);
          if(h->state == MAKUO_RECVSTATE_SKIP)
            cprintf(2, m->comm, "%s: skip\r\n", h->hostname);
          if(h->state == MAKUO_RECVSTATE_READONLY)
            cprintf(2, m->comm, "%s: skip(read only)\r\n", h->hostname);
        }
      }
    }
    m->initstate = 1;
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
        for(h=members;h;h=h->next){
          if(h->state == MAKUO_RECVSTATE_UPDATE)
            cprintf(2, m->comm, "%s: update\r\n", h->hostname);
          if(h->state == MAKUO_RECVSTATE_SKIP)
            cprintf(3, m->comm, "%s: skip\r\n", h->hostname);
          if(h->state == MAKUO_RECVSTATE_READONLY)
            cprintf(3, m->comm, "%s: skip(read only)\r\n", h->hostname);
        }
      }
      m->initstate = 1;
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
  if(S_ISLNK(m->fs.st_mode)){
    msend_packet(s, &(m->mdata), &(m->addr));
  }else{
    /*----- dir -----*/
    if(S_ISDIR(m->fs.st_mode)){
      msend_packet(s, &(m->mdata), &(m->addr));
    }
    /*----- file -----*/
    if(S_ISREG(m->fs.st_mode)){
      m->fd = open(m->fn, O_RDONLY, 0);
      if(m->fd != -1){
        msend_packet(s, &(m->mdata), &(m->addr));
      }else{
        m->sendwait  = 0;
        m->initstate = 1;
        m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
        cprintf(0, m->comm, "error: file open error errno=%d %s\n", errno, m->fn);
        lprintf(0,          "%s: open error errno=%d %s\n", __func__, errno, m->fn);
      }
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
  lprintf(9,"%s: %s\n", __func__, m->fn);
  if(ack_check(m, MAKUO_RECVSTATE_OPEN) != 1){
    m->initstate = 1;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
  }else{
    if(S_ISLNK(m->fs.st_mode)){
      m->initstate = 1;
      m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    }else{
      if(S_ISDIR(m->fs.st_mode)){
        m->initstate = 1;
        m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
      }
      if(S_ISREG(m->fs.st_mode)){
        m->mdata.head.seqno  = 1;
        m->mdata.head.nstate = MAKUO_SENDSTATE_DATA;
      }
    }
  }
}

static void msend_req_send_data(int s, mfile *m)
{
  if(!m->comm){
    m->mdata.head.seqno  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_BREAK;
    return;
  }
  if(m->lickflag){
    msend_req_send_markdata(s, m); /* send rery */
  }else{
    msend_req_send_filedata(s, m); /* send data */
  }
}

static void msend_req_send_mark_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_OPEN);
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
  m->mdata.head.seqno  = 1;
  m->mdata.head.nstate = MAKUO_SENDSTATE_DATA;
}

static void msend_req_send_close_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_OPEN);
  ack_clear(m, MAKUO_RECVSTATE_UPDATE);
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
  lprintf(9,"%s: %s\n", __func__, m->fn);
  msend_mfdel(m);
  m = NULL;
}

static void msend_req_send_last(int s, mfile *m)
{
  m->mdata.head.nstate = MAKUO_SENDSTATE_LAST;
  msend_packet(s, &(m->mdata), &(m->addr));
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
    /* 機能追加はここ */
  }
}


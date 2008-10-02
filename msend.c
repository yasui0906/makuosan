#include "makuosan.h"

/*
 * mfileを開放する
 */
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

/*
 *  パケットを送出する
 */
static int msend_packet(int s, mdata *data, struct sockaddr_in *addr)
{
  int r;
  int szdata;
  mdata senddata;

  memcpy(&senddata, data, sizeof(senddata));
  szdata = msend_encrypt(&senddata);

  /* ヘッダをネットワークバイトオーダへ変換 */
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
        lprintf(0,"msend_packet: size error sock=%d op=%d rid=%d state=%d size=%d send=%d seqno=%d\n", 
          s, data->head.opcode, data->head.reqid, data->head.nstate, sizeof(mhead) + szdata, r, data->head.seqno);
        return(0);
      }else{
        if(errno == EINTR){
          continue;
        }else{
          lprintf(0,"msend_packet: send error errno=%d sock=%d op=%d rid=%d state=%d size=%d seqno=%d\n", 
            errno, s, data->head.opcode, data->head.reqid, data->head.nstate, sizeof(mhead) + szdata, data->head.seqno);
          return(-1);
        }
      }
    }
  }
  return(1);
}

static void msend_shot(int s, mfile *m)
{
  msend_packet(s, &(m->mdata), &(m->addr));
  msend_mfdel(m);
}

static void msend_ack(int s, mfile *m)
{
  if(m->markcount){
    m->mdata.head.szdata = m->marksize * sizeof(uint32_t);
    memcpy(m->mdata.data, m->mark, m->marksize * sizeof(uint32_t));
  }
  msend_packet(s, &(m->mdata), &(m->addr));
  msend_mfdel(m);
  m = NULL;
}

static void msend_file_break(int s, mfile *m)
{
  lprintf(9, "msend_file: BREAK %s\n", m->fn);
  msend_packet(s, &(m->mdata), &(m->addr));
  msend_mfdel(m);
}

static void msend_mark(int s, mfile *m)
{
  int i;
  int r;
  if(!m->markcount){
    /* close */
    m->initstate = 1;
    m->mdata.head.seqno  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    lprintf(4, "msend_file_mark: file send complate! %s\n",m->fn);
  }else{
    lprintf(4, "msend_file_mark: block send retry %d\n",m->markcount);
    for(i=0;i<m->markcount;i++){
      m->mdata.head.seqno = m->mark[i];
      lseek(m->fd, (m->mdata.head.seqno - 1) * MAKUO_BUFFER_SIZE, SEEK_SET);
      r = read(m->fd, m->mdata.data, MAKUO_BUFFER_SIZE);
      if(r>0){
        m->mdata.head.szdata = r;
        msend_packet(s, &(m->mdata), &(m->addr));
      }else{
        if(!r){
          lprintf(0, "msend_mark: read eof? seqno=%d\n", m->mdata.head.seqno);
        }else{
          lprintf(0, "msend_mark: read err! seqno=%d errno=%d\n", m->mdata.head.seqno, errno);
        }
      }
    }
    /* eof */
    m->markcount = 0;
    m->initstate = 1;
    m->mdata.head.seqno  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
  }
}

static void msend_data(int s, mfile *m)
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
      lprintf(0, "msend_data: read error! seqno=%d errno=%d\n", m->mdata.head.seqno, errno);
    }else{
      /* eof */
      lprintf(4, "msend_data: block send count=%d\n", m->mdata.head.seqno);
      m->mdata.head.seqno = 0;
      m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
      m->initstate = 1;
      m->lickflag  = 1;
    }
  }
}

static void msend_file_stat_init(int s, mfile *m)
{
  if(!m->comm){
    lprintf(9, "msend_file: STATINIT %s (CANCEL)\n", m->fn);
    msend_mfdel(m);
    m = NULL;
  }else{
    lprintf(9, "msend_file: STATINIT %s\n", m->fn);
    m->sendwait  = 1;
    m->initstate = 0;
    ack_clear(m, -1);
    msend_packet(s, &(m->mdata), &(m->addr));
  }
}

static void msend_file_stat(int s, mfile *m)
{
  mhost *h;

  if(m->initstate){
    msend_file_stat_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"msend_file: STAT %s\n", m->fn);
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
      lprintf(1, "msend_file_stat: update %s\n", m->fn);
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

static void msend_file_open_init(int s, mfile *m)
{
  lprintf(9,"msend_file: OPENINIT %s\n", m->fn);
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_UPDATE);
  m->mdata.head.nstate = MAKUO_SENDSTATE_OPEN;
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
        lprintf(4, "msend_file: open fd=%d %s\n", m->fd, m->fn);
      }else{
        m->sendwait  = 0;
        m->initstate = 1;
        m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
        cprintf(0, m->comm, "msend_file: open error errno=%d %s\n", errno, m->fn);
        lprintf(0,          "msend_file: open error errno=%d %s\n", errno, m->fn);
      }
    }
  }
}

static void msend_file_open(int s, mfile *m)
{
  if(m->initstate){
    msend_file_open_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"msend_file: OPEN %s\n", m->fn);
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
        m->mdata.head.seqno = 1;
      }
    }
  }
}

static void msend_file_close_init(int s, mfile *m)
{
  lprintf(9,"msend_file: CLOSEINIT %s\n", m->fn);
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_OPEN);
  ack_clear(m, MAKUO_RECVSTATE_UPDATE);
  m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_file_close(int s, mfile *m)
{
  if(m->initstate){
    msend_file_close_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"msend_file: CLOSE %s\n",m->fn);
  msend_mfdel(m);
  m = NULL;
}

static void msend_file_mark_init(int s, mfile *m)
{
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_OPEN);
  m->mdata.head.nstate = MAKUO_SENDSTATE_MARK;
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_file_mark(int s, mfile *m)
{
  if(m->initstate){
    msend_file_mark_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  m->mdata.head.seqno = 1;
}

/*----------------------------------------------------------------------------
 *
 *  send
 *
 */
static void msend_file(int s, mfile *m)
{
  mstat fs;
  if(m->mdata.head.seqno){
    if(!m->comm){
      m->mdata.head.seqno = 0;
      m->mdata.head.nstate = MAKUO_SENDSTATE_BREAK;
    }else{
      if(m->lickflag){
        msend_mark(s, m); /* send rery */
      }else{
        msend_data(s, m); /* send data */
      }
    }
  }else{
    if(!m->comm){
      msend_mfdel(m);
      return;
    }
    m->mdata.p = m->mdata.data;
    m->mdata.head.szdata  = sizeof(fs);
    m->mdata.head.szdata += strlen(m->fn) + 1;
    m->mdata.head.szdata += strlen(m->ln) + 1;
    if(m->mdata.head.szdata > MAKUO_BUFFER_SIZE){
      lprintf(0, "msend_file: buffer size over size=%d file=%s\n", m->mdata.head.szdata, m->fn);
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

    switch(m->mdata.head.nstate){
      case MAKUO_SENDSTATE_BREAK:
        msend_file_break(s, m);
        break;
      case MAKUO_SENDSTATE_STAT:
        msend_file_stat(s, m);
        break;
      case MAKUO_SENDSTATE_OPEN:
        msend_file_open(s, m);
        break;
      case MAKUO_SENDSTATE_CLOSE:
        msend_file_close(s, m);
        break;
      case MAKUO_SENDSTATE_MARK:
        msend_file_mark(s, m);
        break;
    }
  }
}

/*----------------------------------------------------------------------------
 *
 *  md5
 *
 */
static void msend_md5_open_init(int s, mfile *m)
{
  lprintf(9,"msend_md5: OPENINIT %s\n", m->fn);
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, -1);
  m->mdata.head.nstate = MAKUO_SENDSTATE_OPEN;
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_md5_open(int s, mfile *m)
{
  if(m->initstate){
    msend_md5_open_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"msend_md5: OPEN %s\n", m->fn);
  m->initstate = 1;
  m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
}

static void msend_md5_close_init(int s, mfile *m)
{
  lprintf(9,"msend_md5: CLOSEINIT %s\n", m->fn);
  m->sendwait  = 1;
  m->initstate = 0;
  ack_clear(m, MAKUO_RECVSTATE_MD5OK);
  ack_clear(m, MAKUO_RECVSTATE_MD5NG);
  m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
  msend_packet(s, &(m->mdata), &(m->addr));
}

static void msend_md5_close(int s, mfile *m)
{
  if(m->initstate){
    msend_md5_close_init(s, m);
    return;
  }
  if(m->sendwait){
    msend_packet(s, &(m->mdata), &(m->addr));
    return;
  }
  lprintf(9,"msend_md5: CLOSE %s\n",m->fn);
  msend_mfdel(m);
  m = NULL;
}

static void msend_md5(int s, mfile *m)
{
  switch(m->mdata.head.nstate){
    case MAKUO_SENDSTATE_OPEN:
      msend_md5_open(s, m);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      msend_md5_close(s, m);
      break;
  }
}

static void msend_retry(mfile *m)
{
  if(!m->sendwait){
    m->retrycnt = MAKUO_SEND_RETRYCNT;
  }else{
    mhost *t;
    lprintf(2, "msend_retry: send retry count=%02d rid=%06d state=%d %s\n", m->retrycnt, m->mdata.head.reqid, m->mdata.head.nstate, m->fn);
    for(t=members;t;t=t->next){
      switch(moption.loglevel){
        case 3:
          if(t->state == MAKUO_RECVSTATE_NONE){
            lprintf(0, "msend_retry:   state=%d %s(%s)\n", t->state, inet_ntoa(t->ad), t->hostname);
          }
          break;
        default:
          lprintf(4, "msend_retry:   state=%d %s(%s)\n", t->state, inet_ntoa(t->ad), t->hostname);
          break;
      }
    }
    m->retrycnt--;
  }
}

/*
 *  mfile オブジェクトを送信する関数
 *  実際の送信処理は別の関数でやる
 *  オペコードを見てどの関数を使うか決める
 */
void msend(int s, mfile *m)
{
  if(!m)
    return;
  msend_retry(m);
  mtimeget(&m->lastsend);
  switch(m->mdata.head.opcode){
    case MAKUO_OP_PING:
    case MAKUO_OP_PONG:
    case MAKUO_OP_EXIT:
      msend_shot(s, m);
      break;
    case MAKUO_OP_ACK:
      msend_ack(s, m);
      break;
    case MAKUO_OP_FILE:
      msend_file(s, m);
      break;
    case MAKUO_OP_MD5:
      msend_md5(s, m);
      break;
  }
}


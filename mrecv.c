/*
 * mrecv.c
 * Copyright (C) 2008 KLab Inc.
 */
#include "makuosan.h"

static void mrecv_req(mdata *data, struct sockaddr_in *addr);
static void mrecv_ack(mdata *data, struct sockaddr_in *addr);

/******************************************************************
*
* Receive common functions (private)
*
*******************************************************************/
static mfile *mrecv_mfdel(mfile *m)
{
  mfile *r;
  if(!m)
    return(NULL);
  r = m->next;
  if(m->fd != -1){
    close(m->fd);
    m->fd = -1;
    if(S_ISREG(m->fs.st_mode)){
      mremove(moption.base_dir, m->tn);
    }
  }
  if(m->mark){
    free(m->mark);
    m->mark = NULL;
  }
  mfdel(m);
  return(r);
}

static int mrecv_decrypt(mdata *data, struct sockaddr_in *addr)
{
  int i;
  MD5_CTX ctx;
  uint8_t hash[16];

  if(data->head.flags & MAKUO_FLAG_CRYPT){
    if(!moption.cryptena){
      lprintf(0, "%s: recv encrypt packet from %s. I have not key!", __func__, inet_ntoa(addr->sin_addr));
      return(-1);
    }
    if(data->head.szdata){
      for(i=0;i<data->head.szdata;i+=8){
        BF_decrypt((BF_LONG *)(data->data + i), &EncKey);
      }
      MD5_Init(&ctx);
      MD5_Update(&ctx, data->data, data->head.szdata);
      MD5_Final(hash, &ctx);
      if(memcmp(hash,data->head.hash,16)){
        lprintf(0, "%s: protocol checksum error from %s\n", __func__, inet_ntoa(addr->sin_addr));
        return(-1);
      }
    }
  }
  return(0);
}

static int mrecv_packet(int s, mdata *data, struct sockaddr_in *addr)
{
  int recvsize;
  socklen_t addr_len;

  while(1){
    addr_len = sizeof(struct sockaddr_in);
    recvsize = recvfrom(s, data, sizeof(mdata), 0, (struct sockaddr *)addr, &addr_len);
    if(recvsize != -1){
      break;
    }else{
      if(errno == EAGAIN || errno == EINTR){
        continue;
      }else{
        lprintf(0, "%s: recv error from %s\n", __func__, inet_ntoa(addr->sin_addr));
        return(-1);
      }
    }
  }
  if(recvsize < sizeof(data->head)){
    lprintf(0, "%s: recv head size error\n", __func__);
    return(-1);
  }

  data->head.szdata = ntohs(data->head.szdata);
  data->head.flags  = ntohs(data->head.flags);
  data->head.reqid  = ntohl(data->head.reqid);
  data->head.seqno  = ntohl(data->head.seqno);

  if(data->head.vproto != PROTOCOL_VERSION){
    lprintf(0, "%s: protocol version error(%d != %d) from %s\n", __func__,
       data->head.vproto, PROTOCOL_VERSION, inet_ntoa(addr->sin_addr));
    return(-1);
  }

  return(mrecv_decrypt(data, addr));
}

/******************************************************************
*
* Receive common functions (public)
*
*******************************************************************/
void mrecv(int s)
{
  mdata  data;
  struct sockaddr_in addr;
  if(mrecv_packet(s, &data, &addr) == -1){
    return;
  }
  if(data.head.flags & MAKUO_FLAG_ACK){
    mrecv_ack(&data, &addr);
  }else{
    mrecv_req(&data, &addr);
  }
}

void mrecv_gc()
{
  mhost *t = members;
  mfile *m = mftop[1]; 

  /* file timeout */
  while(m){
    if(mtimeout(&(m->lastrecv), MAKUO_RECV_GCWAIT)){
      if(MAKUO_RECVSTATE_CLOSE != m->mdata.head.nstate){
        lprintf(0,"%s: mfile object GC state=%s %s\n", __func__, RSTATE(m->mdata.head.nstate), m->fn);
      }
      m = mrecv_mfdel(m);
      continue;
    }
    m = m->next;
  }

  /* pong timeout */
  while(t){
    if(!mtimeout(&(t->lastrecv), MAKUO_PONG_TIMEOUT)){
      t = t->next;
    }else{
      lprintf(0,"%s: pong timeout %s\n", __func__, t->hostname);
      if(t->next){
        t = t->next;
        member_del(t->prev);
      }else{
        member_del(t);
        t = NULL;
     } 
    }      
  }
}

/******************************************************************
*
* ack receive functions (for source node tasks)
*
*******************************************************************/
static int mrecv_ack_search(mhost **lpt, mfile **lpm, mdata *data, struct sockaddr_in *addr)
{
  mhost *t;
  mfile *m;
  *lpt = NULL;
  *lpm = NULL;
  t = member_add(&addr->sin_addr, NULL);
  if(!t){
    lprintf(0, "%s: member not found %s\n", __func__, inet_ntoa(addr->sin_addr));
    return(-1);
  }
  for(m=mftop[0];m;m=m->next){
    if(m->mdata.head.reqid == data->head.reqid){
      break;
    }
  }
  if(!m){
    return(-1);
  }
  *lpt = t;
  *lpm = m;
  return(0);
}

static void mrecv_ack_report(mfile *m, mhost *h, mdata *data)
{
  if(data->head.nstate == MAKUO_RECVSTATE_OPENERROR){
    cprintf(0, m->comm, "%s: file open error %s\n", h->hostname, m->fn);
    lprintf(0,          "%s: file open error rid=%06d state=%s %s(%s) %s\n", __func__,
      data->head.reqid, RSTATE(data->head.nstate), inet_ntoa(h->ad), h->hostname, m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_WRITEERROR){
    cprintf(0, m->comm, "%s: file write error %s\n", h->hostname, m->fn);
    lprintf(0,          "%s: file write error rid=%06d state=%s %s(%s) %s\n", __func__,
     data->head.reqid, RSTATE(data->head.nstate), inet_ntoa(h->ad), h->hostname, m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_CLOSEERROR){
    cprintf(0, m->comm, "%s: file close error %s\n", h->hostname, m->fn);
    lprintf(0,          "%s: file close error rid=%06d state=%s %s(%s) %s\n", __func__,
      data->head.reqid, RSTATE(data->head.nstate), inet_ntoa(h->ad), h->hostname, m->fn);
  }
}

static void mrecv_ack_ping(mdata *data, struct sockaddr_in *addr)
{
  member_add(&addr->sin_addr, data);
}

static void mrecv_ack_send(mdata *data, struct sockaddr_in *addr)
{
  uint8_t *r;
  mhost   *t;
  mfile   *m;
  if(mrecv_ack_search(&t, &m, data, addr)){
    return;
  }
  mtimeget(&m->lastrecv);
  if(data->head.nstate == MAKUO_RECVSTATE_IGNORE){
    cprintf(4, m->comm, "%s: file update ignore %s\n", t->hostname, m->fn);
    lprintf(0,          "%s: file update ignore rid=%06d state=%s %s(%s) %s\n", __func__, 
      data->head.reqid, RSTATE(data->head.nstate), inet_ntoa(t->ad), t->hostname, m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_MARK){
    uint32_t *d = (uint32_t *)(data->data);
    while(d < (uint32_t *)&data->data[data->head.szdata]){
      if(*d >= m->seqnomax){
        lprintf(0, "%s: mark seqno error seq=%d max=%d %s from %s\n", __func__,
           *d, m->seqnomax, m->fn, t->hostname);
        break;
      }
      seq_addmark(m, *d, (*d) + 1);
      d++;
    }
  }
  if(data->head.nstate == MAKUO_RECVSTATE_RETRY){
    lprintf(0, "%s: send retry %s from %s\n", __func__, m->fn, t->hostname);
    m->sendwait   = 0;
    m->lickflag   = 0;
    m->senddelay += MAKUO_SEND_DELAYSTP;
    m->mdata.head.seqno  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_DATA;
  }else{
    if(r = get_hoststate(t, m)){
      *r = data->head.nstate;
    }else{
      lprintf(0, "%s: hoststate error\n", __func__);
    }
  }
  mrecv_ack_report(m, t, data);
}

static void mrecv_ack_md5(mdata *data, struct sockaddr_in *addr)
{
  uint8_t *s;
  mhost   *t;
  mfile   *m;
  mrecv_ack_search(&t, &m, data, addr);
  if(!t || !m){
    return;
  }
  mtimeget(&m->lastrecv);
  s = get_hoststate(t,m);
  if(!s){
    lprintf(0, "%s: not allocate state area\n", __func__);
    return;
  }
  if(*s != data->head.nstate){
    if(data->head.nstate == MAKUO_RECVSTATE_MD5OK){
      cprintf(1, m->comm, "%s: OK %s\r\n", t->hostname, m->fn);
      lprintf(8,          "%s: OK %s:%s\n", __func__, t->hostname, m->fn);
    }
    if(data->head.nstate == MAKUO_RECVSTATE_MD5NG){
      cprintf(0, m->comm, "%s: NG %s\r\n", t->hostname, m->fn);
      lprintf(0,          "%s: NG %s:%s\n", __func__, t->hostname, m->fn);
    }
  }
  *s = data->head.nstate;
  mrecv_ack_report(m, t, data);
}

static void mrecv_ack(mdata *data, struct sockaddr_in *addr)
{
  switch(data->head.opcode){
    case MAKUO_OP_PING:
      mrecv_ack_ping(data, addr);
      break;
    case MAKUO_OP_SEND:
      mrecv_ack_send(data, addr);
      break;
    case MAKUO_OP_MD5:
      mrecv_ack_md5(data, addr);
      break;
    /* 機能追加はここへ */
  }
}

/******************************************************************
*
* Request receive functions (for destination node tasks)
*
*******************************************************************/
static void mrecv_req_ping(mdata *data, struct sockaddr_in *addr)
{
  mping *p;
  mfile *m;
  char buff[MAKUO_HOSTNAME_MAX + 1];
  member_add(&addr->sin_addr, data);
  m = mfadd(0);
  if(!m){
    lprintf(0,"%s: out of memory\n", __func__);
    return;
  }
  m->mdata.head.opcode = MAKUO_OP_PING;
  m->mdata.head.flags |= MAKUO_FLAG_ACK;
  m->mdata.head.reqid  = data->head.reqid;
  m->mdata.head.seqno  = 0;
  m->mdata.head.szdata = 0;
  memcpy(&(m->addr), addr, sizeof(m->addr));
  if(gethostname(buff, sizeof(buff)) == -1){
    buff[0] = 0;
  }
  p = (mping *)(m->mdata.data);
  p->hostnamelen = strlen(buff);
  p->versionlen  = strlen(MAKUOSAN_VERSION);
  m->mdata.head.szdata = sizeof(mping) + p->hostnamelen + p->versionlen;
  m->mdata.p = p->data;
  memcpy(m->mdata.p, buff, p->hostnamelen);
  m->mdata.p += p->hostnamelen;
  memcpy(m->mdata.p, MAKUOSAN_VERSION, p->versionlen);
  m->mdata.p += p->versionlen;
  p->hostnamelen = htons(p->hostnamelen);
  p->versionlen  = htons(p->versionlen);
}

static void mrecv_req_exit(mdata *data, struct sockaddr_in *addr)
{
  mhost *t;
  for(t=members;t;t=t->next)
    if(!memcmp(&(t->ad), &(addr->sin_addr), sizeof(t->ad)))
      break;
  member_del(t);
}

static void mrecv_req_send_break(mfile *m, mdata *r)
{
  mrecv_mfdel(m);
}

static void mrecv_req_send_stat(mfile *m, mdata *r)
{
  mfile  *a;
  struct stat fs;
  struct utimbuf mftime;

  if(moption.dontrecv){
    m->mdata.head.nstate = MAKUO_RECVSTATE_READONLY;
  }else{
    if(S_ISLNK(m->fs.st_mode)){
      m->mdata.head.nstate = linkcmp(m);
    }else{
      if(lstat(m->fn, &fs) == -1){
        m->mdata.head.nstate = MAKUO_RECVSTATE_UPDATE;
      }else{
        m->mdata.head.nstate = statcmp(&(m->fs), &fs);
      }
    }
  }
  a = mfins(0);
  if(!a){
    lprintf(0, "%s: out of momory\n", __func__);
    return;
  }
  a->mdata.head.flags |= MAKUO_FLAG_ACK;
  a->mdata.head.opcode = m->mdata.head.opcode;
  a->mdata.head.reqid  = m->mdata.head.reqid;
  a->mdata.head.seqno  = m->mdata.head.seqno;
  a->mdata.head.nstate = m->mdata.head.nstate;
  memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
}

static void mrecv_req_send_open(mfile *m, mdata *r)
{
  char fpath[PATH_MAX];
  char tpath[PATH_MAX];

  if(m->mdata.head.nstate != MAKUO_RECVSTATE_UPDATE)
    return;

  sprintf(fpath, "%s/%s", moption.base_dir, m->fn);
  sprintf(tpath, "%s/%s", moption.base_dir, m->tn);
  m->mdata.head.ostate = m->mdata.head.nstate;
  m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
  if(S_ISLNK(m->fs.st_mode)){
    mtempname(moption.base_dir, m->fn, m->tn);
    sprintf(tpath, "%s/%s", moption.base_dir, m->tn);
    if(!mcreatelink(moption.base_dir, m->tn, m->ln)){
    }else{
      lprintf(0, "%s: symlink error %s -> %s\n", __func__, m->ln, m->fn);
      m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
    }
  }else{
    if(S_ISDIR(m->fs.st_mode)){
      if(!is_dir(fpath)){
        mcreatedir(moption.base_dir, m->fn, m->fs.st_mode & 0xFFF);
        mkdir(fpath, m->fs.st_mode & 0xFFF);
      }else{
        chmod(fpath, m->fs.st_mode & 0xFFF);
      }
      if(!is_dir(fpath)){
        lprintf(0,"%s: mkdir error %s\n", __func__, m->fn);
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
      }
    }
    if(S_ISREG(m->fs.st_mode)){
      mtempname(moption.base_dir, m->fn, m->tn);
      sprintf(tpath, "%s/%s", moption.base_dir, m->tn);
      m->fd = mcreatefile(moption.base_dir, m->tn, m->fs.st_mode);
      if(m->fd == -1){
        lprintf(0, "%s: open error %s\n", __func__, m->fn);
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
      }
    }
  }
  mfile *a = mfins(0);
  if(!a){
    lprintf(0, "%s: out of momory\n", __func__);
    return;
  }
  a->mdata.head.flags |= MAKUO_FLAG_ACK;
  a->mdata.head.opcode = r->head.opcode;
  a->mdata.head.reqid  = r->head.reqid;
  a->mdata.head.seqno  = r->head.seqno;
  a->mdata.head.ostate = m->mdata.head.ostate;
  a->mdata.head.nstate = m->mdata.head.nstate;
  memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
}

static void mrecv_req_send_data(mfile *m,  mdata *r)
{
  if(m->mdata.head.nstate != MAKUO_RECVSTATE_OPEN)
    return;

  if(m->lickflag){
    if(!seq_delmark(m, r->head.seqno)){
      return;
    }
  }else{
    if(m->mdata.head.seqno > r->head.seqno){
      seq_delmark(m, r->head.seqno);
    }else{
      if(m->mdata.head.seqno < r->head.seqno){
        seq_addmark(m, m->mdata.head.seqno, r->head.seqno);
        m->mdata.head.seqno = r->head.seqno;
      }
      m->mdata.head.seqno++;
    }
  }
  if(lseek(m->fd, r->head.seqno * MAKUO_BUFFER_SIZE, SEEK_SET) == -1){
    lprintf(0, "%s: seek error seq=%d size=%d fd=%d err=%d\n", __func__, (int)r->head.seqno, r->head.szdata, m->fd, errno);
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_RECVSTATE_WRITEERROR;
  }else{
    if(write(m->fd, r->data, r->head.szdata) != -1){
      m->recvcount++;
    }else{
      lprintf(0, "%s: write error seqno=%d size=%d fd=%d err=%d\n", __func__, (int)r->head.seqno, r->head.szdata, m->fd, errno);
      m->mdata.head.ostate = m->mdata.head.nstate;
      m->mdata.head.nstate = MAKUO_RECVSTATE_WRITEERROR;
    }
  }
  if(m->mdata.head.nstate == MAKUO_RECVSTATE_OPEN){
    return;
  }

  /*----- write error notlfy -----*/
  mfile *a = mfins(0);
  if(!a){
    lprintf(0, "%s: out of momory\n", __func__);
    return;
  }
  a->mdata.head.flags |= MAKUO_FLAG_ACK;
  a->mdata.head.opcode = r->head.opcode;
  a->mdata.head.reqid  = r->head.reqid;
  a->mdata.head.seqno  = r->head.seqno;
  a->mdata.head.ostate = m->mdata.head.ostate;
  a->mdata.head.nstate = m->mdata.head.nstate;
  a->mdata.head.szdata = 0;
  memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
}

static void mrecv_req_send_mark(mfile *m, mdata *r)
{
  if(m->mdata.head.nstate != MAKUO_RECVSTATE_OPEN)
    return;

  mfile *a = mfins(0);
  if(!a){
    lprintf(0, "%s: out of momory\n", __func__);
    return;
  }
  a->mdata.head.flags |= MAKUO_FLAG_ACK;
  a->mdata.head.opcode = r->head.opcode;
  a->mdata.head.reqid  = r->head.reqid;
  a->mdata.head.seqno  = r->head.seqno;
  a->mdata.head.ostate = m->mdata.head.nstate;
  a->mdata.head.nstate = MAKUO_RECVSTATE_MARK;
  a->mdata.head.szdata = 0;

  memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
  m->lickflag = 1;
  if(m->mdata.head.seqno < m->seqnomax){
    seq_addmark(m, m->mdata.head.seqno, m->seqnomax);
    m->mdata.head.seqno = m->seqnomax;
  }
  if(m->markcount){
    if(MAKUO_BUFFER_SIZE < m->markcount * sizeof(uint32_t)){
      a->marksize = MAKUO_BUFFER_SIZE / sizeof(uint32_t);
    }else{
      a->marksize = m->markcount;
    }
    a->markcount = a->marksize;
    a->mark = malloc(a->marksize * sizeof(uint32_t));
    memcpy(a->mark, m->mark, a->marksize * sizeof(uint32_t));
    lprintf(3, "%s: repeat mark=%04d reqest=%03d recv=%06d size=%06d %s\n", __func__,
      m->markcount, a->markcount, m->recvcount, m->seqnomax,  m->fn);
  }
}

static void mrecv_req_send_close(mfile *m, mdata *r)
{
  mfile  *a;
  struct stat fs;
  struct utimbuf mftime;
  char  fpath[PATH_MAX];
  char  tpath[PATH_MAX];
  sprintf(fpath, "%s/%s", moption.base_dir, m->fn);
  sprintf(tpath, "%s/%s", moption.base_dir, m->tn);

  if(m->mdata.head.nstate == MAKUO_RECVSTATE_OPEN){
    if(m->fd != -1){
      fstat(m->fd, &fs);
      close(m->fd);
      m->fd = -1;
    }
    mftime.actime  = m->fs.st_ctime; 
    mftime.modtime = m->fs.st_mtime;
    if(S_ISLNK(m->fs.st_mode)){
      if(!mrename(moption.base_dir, m->tn, m->fn)){
      }else{
        m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
        lprintf(0, "%s: close error %s -> %s\n", __func__, m->ln, m->fn);
        mremove(moption.base_dir, m->tn);
      }
    }else{
      if(S_ISDIR(m->fs.st_mode)){
        utime(fpath, &mftime);
      }
      if(S_ISREG(m->fs.st_mode)){
        utime(tpath, &mftime);
        if(fs.st_size != m->fs.st_size){
          m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
          lprintf(0, "%s: close error %s (file size mismatch %d != %d)\n", __func__, m->fn, (int)(fs.st_size), (int)(m->fs.st_size));
          lprintf(0, "%s: seq=%d max=%d mark=%d recv=%d\n", __func__, m->mdata.head.seqno, m->seqnomax, m->markcount, m->recvcount);
          mremove(moption.base_dir, m->tn);
        }else{
          if(!mrename(moption.base_dir, m->tn, m->fn)){
          }else{
            m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
            lprintf(0, "%s: close error %s\n", __func__, m->fn);
            mremove(moption.base_dir, m->tn);
          }
        }
      }
      if(!geteuid()){
        chown(fpath, m->fs.st_uid, m->fs.st_gid);
      }
    }
  }

  switch(m->mdata.head.nstate){
    case MAKUO_RECVSTATE_OPEN:
    case MAKUO_RECVSTATE_UPDATE:
    case MAKUO_RECVSTATE_MARK:
      m->mdata.head.ostate = m->mdata.head.nstate;
      m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
      break;
    case MAKUO_RECVSTATE_CLOSE:
    case MAKUO_RECVSTATE_CLOSEERROR:
      break;
    default:
      return;
  }

  a = mfins(0);
  if(!a){
    lprintf(0, "%s: out of memory\n", __func__);
  }else{
    a->mdata.head.flags |= MAKUO_FLAG_ACK;
    a->mdata.head.opcode = r->head.opcode;
    a->mdata.head.reqid  = r->head.reqid;
    a->mdata.head.seqno  = r->head.seqno;
    a->mdata.head.ostate = m->mdata.head.ostate;
    a->mdata.head.nstate = m->mdata.head.nstate;
    memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
  }
}

static void mrecv_req_send_last(mfile *m, mdata *r)
{
  mrecv_mfdel(m);
}

static void mrecv_req_send_next(mfile *m, mdata *r)
{
  switch(r->head.nstate){
    case MAKUO_SENDSTATE_STAT:
      lprintf(9,"%s: %s/%s %s\n", __func__, SSTATE(r->head.nstate), RSTATE(m->mdata.head.nstate), m->fn);
      mrecv_req_send_stat(m, r);
      break;

    case MAKUO_SENDSTATE_OPEN:
      lprintf(9,"%s: %s/%s %s\n", __func__, SSTATE(r->head.nstate), RSTATE(m->mdata.head.nstate), m->fn);
      mrecv_req_send_open(m, r);
      break;

    case MAKUO_SENDSTATE_DATA:
      mrecv_req_send_data(m, r);
      break;

    case MAKUO_SENDSTATE_MARK:
      lprintf(9,"%s: %s/%s seqno=%d max=%d cnt=%d %s\n", __func__,
        SSTATE(r->head.nstate), RSTATE(m->mdata.head.nstate), m->mdata.head.seqno, m->seqnomax, m->markcount, m->fn);
      mrecv_req_send_mark(m, r);
      break;

    case MAKUO_SENDSTATE_CLOSE:
      lprintf(9,"%s: %s/%s %s\n", __func__, SSTATE(r->head.nstate), RSTATE(m->mdata.head.nstate), m->fn);
      mrecv_req_send_close(m, r);
      break;

    case MAKUO_SENDSTATE_LAST:
      lprintf(9,"%s: %s/%s %s\n", __func__, SSTATE(r->head.nstate), RSTATE(m->mdata.head.nstate), m->fn);
      mrecv_req_send_last(m, r);
      break;

    case MAKUO_SENDSTATE_BREAK:
      lprintf(9,"%s: %s/%s %s\n", __func__, SSTATE(r->head.nstate), RSTATE(m->mdata.head.nstate), m->fn);
      mrecv_req_send_break(m, r);
      break;
  }
}

static mfile *mrecv_req_send_create(mdata *data, struct sockaddr_in *addr)
{
  mstat fs;
  mfile *m;
  uint16_t fnlen;
  uint16_t lnlen;

  if(data->head.nstate != MAKUO_SENDSTATE_STAT){
    return(NULL);
  }

  /* create object */
  if(!(m = mfadd(1))){
    return(NULL);
  }

  /* copy header */
  memcpy(&(m->addr), addr, sizeof(m->addr));
  memcpy(&(m->mdata.head), &(data->head), sizeof(m->mdata.head));
  data->p = data->data;

  /* read mstat */
  memcpy(&fs, data->p, sizeof(fs));
  data->p += sizeof(fs);

  /* stat = mstat */
  m->fs.st_mode  = ntohl(fs.mode);
  m->fs.st_uid   = ntohs(fs.uid);
  m->fs.st_gid   = ntohs(fs.gid);
  m->fs.st_size  = ((off_t)ntohl(fs.sizeh) << 32) + (off_t)ntohl(fs.sizel);
  m->fs.st_mtime = ntohl(fs.mtime);
  m->fs.st_ctime = ntohl(fs.ctime);
  fnlen = ntohs(fs.fnlen);
  lnlen = ntohs(fs.lnlen);

  /* read filename */
  memcpy(m->fn, data->p, fnlen);
  m->fn[fnlen] = 0;
  data->p += fnlen;

  /* read linkname */
  memcpy(m->ln, data->p, lnlen);    
  m->ln[lnlen] = 0;
  data->p += lnlen;

  /* Number of blocks */
  m->seqnomax = m->fs.st_size / MAKUO_BUFFER_SIZE;
  if(m->fs.st_size % MAKUO_BUFFER_SIZE){
    m->seqnomax++; 
  }

  return(m);
}

static void mrecv_req_send(mdata *data, struct sockaddr_in *addr)
{
  mfile *a; 
  mfile *m; 
  for(m=mftop[1];m;m=m->next){
    if(!memcmp(&m->addr, addr, sizeof(m->addr)) && m->mdata.head.reqid == data->head.reqid){
      break;
    }
  }
  if(!m){
    m = mrecv_req_send_create(data, addr);
  }
  if(m){
    mtimeget(&(m->lastrecv));
    mrecv_req_send_next(m, data);
  }else{
    if(data->head.nstate != MAKUO_SENDSTATE_DATA){
      a = mfins(0);
      if(!a){
        lprintf(0,"%s: out of memory\n", __func__);
      }else{
        a->mdata.head.flags |= MAKUO_FLAG_ACK;
        a->mdata.head.opcode = data->head.opcode;
        a->mdata.head.reqid  = data->head.reqid;
        a->mdata.head.seqno  = data->head.seqno;
        a->mdata.head.nstate = MAKUO_RECVSTATE_IGNORE;
        memcpy(&(a->addr), addr, sizeof(a->addr));
      }
    }
  }
}

static void mrecv_req_md5_open(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  int    r;
  int    l;
  mfile *a;
  mhash *h;

  if(!m){
    m = mfadd(1);
    memcpy(&(m->addr), addr, sizeof(m->addr));
    memcpy(&(m->mdata.head), &(data->head), sizeof(m->mdata.head));
    h = (mhash *)(data->data);
    l = ntohs(h->fnlen);
    memcpy(m->fn, h->filename, l);
    m->fn[l] = 0;
    m->fd = open(m->fn, O_RDONLY);
    if(m->fd == -1){
      m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
    }else{
      r = md5sum(m->fd, m->mdata.data);
      close(m->fd);
      m->fd = -1;
      if(r == -1){
	      lprintf(0, "%s: file read error %s\n", __func__, m->fn);
        m->mdata.head.nstate = MAKUO_RECVSTATE_READERROR;
      }else{
        if(!memcmp(m->mdata.data, data->data, 16)){
          m->mdata.head.nstate = MAKUO_RECVSTATE_MD5OK;
        }else{
          m->mdata.head.nstate = MAKUO_RECVSTATE_MD5NG;
        }
      }
    }
  }
  a=mfadd(0);
  a->mdata.head.flags |= MAKUO_FLAG_ACK;
  a->mdata.head.opcode = m->mdata.head.opcode;
  a->mdata.head.reqid  = m->mdata.head.reqid;
  a->mdata.head.seqno  = 0;
  a->mdata.head.szdata = 0;
  a->mdata.head.nstate = m->mdata.head.nstate;
  memcpy(&(a->addr), addr, sizeof(a->addr));
  mtimeget(&(m->lastrecv));
}

static void mrecv_req_md5_close(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  mfile *a = mfadd(0);
  a->mdata.head.flags |= MAKUO_FLAG_ACK;
  a->mdata.head.opcode = data->head.opcode;
  a->mdata.head.reqid  = data->head.reqid;
  a->mdata.head.szdata = 0;
  a->mdata.head.seqno  = 0;
  a->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
  memcpy(&(a->addr), addr, sizeof(a->addr));
  mrecv_mfdel(m);
}

/*
 * md5チェック要求を受け取ったときの処理
 * mfileオブジェクトを生成して
 * 対象ファイルのmd5を取得する
 */
static void mrecv_req_md5(mdata *data, struct sockaddr_in *addr)
{
  mfile *m = mftop[1];
  while(m){
    if(!memcmp(&m->addr, addr, sizeof(m->addr)) && m->mdata.head.reqid == data->head.reqid){
      mtimeget(&m->lastrecv);
      break;
    }
    m = m->next;
  }
  switch(data->head.nstate){
    case MAKUO_SENDSTATE_OPEN:
      mrecv_req_md5_open(m, data, addr);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      mrecv_req_md5_close(m, data, addr);
      break;
  }
}

static void mrecv_req(mdata *data, struct sockaddr_in *addr)
{
  switch(data->head.opcode){
    case MAKUO_OP_PING:
      mrecv_req_ping(data, addr);
      break;
    case MAKUO_OP_EXIT:
      mrecv_req_exit(data, addr);
      break;
    case MAKUO_OP_SEND:
      mrecv_req_send(data, addr);
      break;
    case MAKUO_OP_MD5:
      mrecv_req_md5(data, addr);
      break;
    /* 機能追加はここへ */
  }
}


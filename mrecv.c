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
  if(!m){
    return(NULL);
  }
  r = m->next;
  if(m->fd != -1){
    close(m->fd);
    m->fd = -1;
    if(!S_ISLNK(m->fs.st_mode) && S_ISREG(m->fs.st_mode)){
      mremove(moption.base_dir, m->tn);
    }
  }
  while(m->mark = delmark(m->mark));
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
      lprintf(0, "%s: [warn] encrypt packet from %s. I have not key!\n", __func__, inet_ntoa(addr->sin_addr));
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
        lprintf(0, "[error] %s: protocol checksum error from %s\n", __func__, inet_ntoa(addr->sin_addr));
        return(-1);
      }
    }
  }else{
    if(moption.cryptena){
      lprintf(0, "%s: [warn] not encrypt packet from %s. I have key!\n", __func__, inet_ntoa(addr->sin_addr));
      return(-1);
    }
  }
  return(0);
}

static int mrecv_packet(int s, mdata *data, struct sockaddr_in *addr)
{
  int recvsize;
  socklen_t addr_len;

  while(1){
    if(!loop_flag){
      return(-1);
    }
    addr_len = sizeof(struct sockaddr_in);
    recvsize = recvfrom(s, data, sizeof(mdata), 0, (struct sockaddr *)addr, &addr_len);
    if(recvsize == -1){
      if(errno == EAGAIN){
        return(-1);
      }
      if(errno == EINTR){
        continue;
      }else{
        lprintf(0, "[error] %s: %s recv error\n", __func__, strerror(errno));
        return(-1);
      }
    }
    if(recvsize < sizeof(data->head)){
      lprintf(0, "[error] %s: recv head size error from %s\n", __func__, inet_ntoa(addr->sin_addr));
      return(-1);
    }
    data->head.szdata = ntohs(data->head.szdata);
    data->head.flags  = ntohs(data->head.flags);
    data->head.reqid  = ntohl(data->head.reqid);
    data->head.seqno  = ntohl(data->head.seqno);
    data->head.maddr  = ntohl(data->head.maddr);
    data->head.mport  = ntohs(data->head.mport);
    data->head.error  = ntohl(data->head.error);
    if(data->head.maddr != moption.maddr.sin_addr.s_addr){
      continue; /* other group packet */
    }
    if(data->head.mport != moption.maddr.sin_port){
      continue; /* other group packet */
    }
    if(data->head.vproto != PROTOCOL_VERSION){
      continue; /* other protocol */
    }
    if(!mrecv_decrypt(data, addr)){
      break;
    }
  }
  return(0);
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
  mtimeget(&m->lastrecv);
  return(0);
}

static void mrecv_ack_report(mfile *m, mhost *t, mdata *data)
{
  if(data->head.nstate == MAKUO_RECVSTATE_OPENERROR){
    cprintf(0, m->comm, "error: %s %s:%s\n", strerror(data->head.error), t->hostname, m->fn);
    lprintf(0, "[error] %s: %s rid=%06d %s %s:%s\n", 
      __func__,
      strerror(data->head.error),
      data->head.reqid, 
      strrstate(data->head.nstate), 
      t->hostname, 
      m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_WRITEERROR){
    cprintf(0, m->comm, "error: %s %s:%s\n", strerror(data->head.error), t->hostname, m->fn);
    lprintf(0, "[error] %s: %s rid=%06d %s %s:%s\n", 
      __func__,
      strerror(data->head.error),
      data->head.reqid, 
      strrstate(data->head.nstate), 
      t->hostname, 
      m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_CLOSEERROR){
    cprintf(0, m->comm, "error: close error %s:%s\n", t->hostname, m->fn);
    lprintf(0, "[error] %s: close error rid=%06d %s %s:%s\n", 
      __func__,
      data->head.reqid, 
      strrstate(data->head.nstate), 
      t->hostname, 
      m->fn);
  }
}

static void mrecv_ack_ping(mdata *data, struct sockaddr_in *addr)
{
  member_add(&addr->sin_addr, data);
}

static void mrecv_ack_send_mark(mdata *data, mfile *m, mhost *t)
{
  uint32_t l;
  uint32_t h;
  data->p = data->data;
  while(!data_safeget32(data, &l)){
    if(data_safeget32(data, &h)){
      break;
    }
    seq_setmark(m, l, h);
  }
}

static void mrecv_ack_send(mdata *data, struct sockaddr_in *addr)
{
  mhost *t;
  mfile *m;
  if(mrecv_ack_search(&t, &m, data, addr)){
    return;
  }
  if(data->head.nstate == MAKUO_RECVSTATE_MARK){
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_MARK){
      mrecv_ack_send_mark(data, m, t);
    }
  }
  if(data->head.nstate == MAKUO_RECVSTATE_OPEN){
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_DATA){
      mrecv_ack_send_mark(data, m, t);
      return;
    }
  }
  if(!set_hoststate(t, m, data->head.nstate)){
    lprintf(0, "%s: hoststate error\n", __func__);
  }
  mrecv_ack_report(m, t, data);
}

static void mrecv_ack_md5(mdata *data, struct sockaddr_in *addr)
{
  uint8_t *s;
  mhost   *t;
  mfile   *m;
  if(mrecv_ack_search(&t, &m, data, addr)){
    return;
  }
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

static void mrecv_ack_dsync(mdata *data, struct sockaddr_in *addr)
{
  mhost *t;
  mfile *m;

  if(data->head.nstate == MAKUO_RECVSTATE_CLOSE){
    mkreq(data, addr, MAKUO_SENDSTATE_LAST);
  }
  if(mrecv_ack_search(&t, &m, data, addr)){
    return;
  }
  for(m=mftop[0];m;m=m->next){
    if(m->mdata.head.reqid == data->head.reqid){
      if(m->comm){
        break;
      }
      if(m->mdata.head.nstate == MAKUO_SENDSTATE_BREAK){
        break;
      }
    }
  }
  if(!m){
    return;
  }

  if(data->head.nstate == MAKUO_RECVSTATE_OPEN){
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_OPEN){
      if(!set_hoststate(t, m, data->head.nstate)){
        lprintf(0, "%s: not allocate state area\n", __func__);
      }
      return;
    }
    if(m->mdata.head.nstate == MAKUO_SENDSTATE_DATA){
      if(data->head.seqno == m->mdata.head.seqno){
        if(!set_hoststate(t, m, data->head.nstate)){
          lprintf(0, "%s: not allocate state area\n", __func__);
        }
      }
    }
    return;
  }

  if(!set_hoststate(t, m, data->head.nstate)){
    lprintf(0, "%s: not allocate state area\n", __func__);
  }
}

static void mrecv_ack_del(mdata *data, struct sockaddr_in *addr)
{
  mhost     *t;
  mfile     *m;
  uint32_t err;
  uint32_t res;
  uint16_t len;
  char path[PATH_MAX];

  if(mrecv_ack_search(&t, &m, data, addr)){
    return;
  }
  if(!set_hoststate(t, m, data->head.nstate)){
    lprintf(0, "%s: not allocate state area\n", __func__);
    return;
  }
  if(m->mdata.head.nstate == MAKUO_SENDSTATE_OPEN){
    m->initstate = 1;
    m->sendwait  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_CLOSE;
    if(data->head.nstate == MAKUO_RECVSTATE_OPEN){
      data->p=data->data;
      m->mdata.p=m->mdata.data;
      m->mdata.head.szdata = 0;
      while(!data_safeget16(data, &len)){
        m->mdata.head.nstate = MAKUO_SENDSTATE_DATA;
        data_safeget32(data, &res);
        len -= sizeof(uint32_t);
        data_safeget(data, path, len);
        path[len] =  0;

        err = 0;
        if(m->dryrun){
          lprintf(1, "%s: (dryrun) delete %s\n", __func__, path);
        }else{
          if(!mremove(NULL,path)){
            lprintf(1, "%s: delete %s\n", __func__, path);
          }else{
            err = errno;
            lprintf(0, "%s: delete error %s (%s)\n", __func__, path, strerror(errno));
          }
        }
        data_safeset16(&(m->mdata), len + sizeof(uint32_t));
        data_safeset32(&(m->mdata), err);
        data_safeset(&(m->mdata), path, len);
      }
    }
  }
}

static void mrecv_ack(mdata *data, struct sockaddr_in *addr)
{
  switch(data->head.opcode){
    case MAKUO_OP_PING:
      mrecv_ack_ping(data,  addr);
      break;
    case MAKUO_OP_SEND:
      mrecv_ack_send(data,  addr);
      break;
    case MAKUO_OP_MD5:
      mrecv_ack_md5(data,   addr);
      break;
    case MAKUO_OP_DSYNC:
      mrecv_ack_dsync(data, addr);
      break;
    case MAKUO_OP_DEL:
      mrecv_ack_del(data,   addr);
      break;
    /* 機能追加はここへ */
  }
}

/******************************************************************
*
* Request receive functions (for destination node tasks)
*
*******************************************************************/
static mfile *mrecv_req_search(mdata *data, struct sockaddr_in *addr)
{
  mfile *m = mftop[1];
  while(m){
    if(!memcmp(&m->addr, addr, sizeof(m->addr)) && m->mdata.head.reqid == data->head.reqid){
      break;
    }
    m = m->next;
  }
  return(m);
}

static void mrecv_req_ping(mdata *data, struct sockaddr_in *addr)
{
  mping *p;
  mfile *a;
  char buff[MAKUO_HOSTNAME_MAX + 1];
  member_add(&addr->sin_addr, data);
  a = mkack(data, addr, MAKUO_RECVSTATE_NONE);
  if(gethostname(buff, sizeof(buff)) == -1){
    buff[0] = 0;
  }
  p = (mping *)(a->mdata.data);
  p->hostnamelen = strlen(buff);
  p->versionlen  = strlen(PACKAGE_VERSION);
  a->mdata.head.szdata = sizeof(mping) + p->hostnamelen + p->versionlen;
  a->mdata.p = p->data;
  memcpy(a->mdata.p, buff, p->hostnamelen);
  a->mdata.p += p->hostnamelen;
  memcpy(a->mdata.p, PACKAGE_VERSION, p->versionlen);
  a->mdata.p += p->versionlen;
  p->hostnamelen = htons(p->hostnamelen);
  p->versionlen  = htons(p->versionlen);
}

static void mrecv_req_exit(mdata *data, struct sockaddr_in *addr)
{ 
  mhost *t = member_get(&(addr->sin_addr));
  if(!t){
    return;
  }
  member_del_message(t, "member exit");
  member_del(t);
}

static void mrecv_req_send_break(mfile *m, mdata *r)
{
  msend(mkack(r, &(m->addr), MAKUO_RECVSTATE_IGNORE));
  mrecv_mfdel(m);
}

static void mrecv_req_send_stat(mfile *m, mdata *r)
{
  struct stat fs;
  struct utimbuf mftime;

  if(moption.dontrecv){
    m->mdata.head.nstate = MAKUO_RECVSTATE_READONLY;
  }else{
    if(r->head.flags & MAKUO_FLAG_SYNC){
      if(m->mdata.head.nstate == MAKUO_RECVSTATE_NONE){
        m->mdata.head.nstate = MAKUO_RECVSTATE_DELETEOK;
        if(r->head.flags & MAKUO_FLAG_DRYRUN){
          if(lstat(m->fn, &fs) == -1 && errno == ENOENT){
            m->mdata.head.nstate = MAKUO_RECVSTATE_DELETENG;
          }
        }else{
          if(mremove(NULL, m->fn) == -1){
            m->mdata.head.nstate = MAKUO_RECVSTATE_DELETENG;
          }
        }
      }
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
  }
  msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
}

static void mrecv_req_send_open(mfile *m, mdata *r)
{
  char fpath[PATH_MAX];
  char tpath[PATH_MAX];

  if(m->mdata.head.nstate != MAKUO_RECVSTATE_UPDATE){
    return;
  }

  mtempname(moption.base_dir, m->fn, m->tn);
  sprintf(fpath, "%s/%s", moption.base_dir, m->fn);
  sprintf(tpath, "%s/%s", moption.base_dir, m->tn);
  m->mdata.head.ostate = m->mdata.head.nstate;
  m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;

  if(S_ISLNK(m->fs.st_mode)){
    if(!mcreatelink(moption.base_dir, m->tn, m->ln)){
      m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
      set_filestat(tpath, m->fs.st_uid, m->fs.st_gid, m->fs.st_mode);
    }else{
      lprintf(0, "%s: symlink error %s -> %s\n", __func__, m->ln, m->fn);
      m->mdata.head.error  = errno;
    }
  }else{
    if(S_ISDIR(m->fs.st_mode)){
      if(!is_dir(fpath)){
        mcreatedir(moption.base_dir, m->fn, m->fs.st_mode);
        mkdir(fpath, m->fs.st_mode);
      }
      if(is_dir(fpath)){
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
        set_filestat(fpath, m->fs.st_uid, m->fs.st_gid, m->fs.st_mode);
      }else{
        lprintf(0,"%s: mkdir error %s\n", __func__, m->fn);
        m->mdata.head.error = errno;
      }
    }
    if(S_ISREG(m->fs.st_mode)){
      m->fd = mcreatefile(moption.base_dir, m->tn, m->fs.st_mode);
      if(m->fd != -1){
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
      }else{
        lprintf(0, "%s: %s %s\n", __func__, strerror(errno), m->fn);
        m->mdata.head.error = errno;
      }
    }
    if(S_ISCHR(m->fs.st_mode)){
      if(!mcreatenode(moption.base_dir, m->tn, m->fs.st_mode, m->fs.st_rdev)){
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
        set_filestat(tpath, m->fs.st_uid, m->fs.st_gid, m->fs.st_mode);
      }else{
        lprintf(0, "%s: %s %s\n", __func__, strerror(errno), m->fn);
        m->mdata.head.error = errno;
      }
    }
    if(S_ISBLK(m->fs.st_mode)){
      if(!mcreatenode(moption.base_dir, m->tn, m->fs.st_mode, m->fs.st_rdev)){
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
        set_filestat(tpath, m->fs.st_uid, m->fs.st_gid, m->fs.st_mode);
      }else{
        lprintf(0, "%s: %s %s\n", __func__, strerror(errno), m->fn);
        m->mdata.head.error = errno;
      }
    }
    if(S_ISFIFO(m->fs.st_mode)){
      if(!mcreatenode(moption.base_dir, m->tn, m->fs.st_mode, m->fs.st_rdev)){
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
        set_filestat(tpath, m->fs.st_uid, m->fs.st_gid, m->fs.st_mode);
      }else{
        lprintf(0, "%s: %s %s\n", __func__, strerror(errno), m->fn);
        m->mdata.head.error = errno;
      }
    }
  }
  msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
}

static void mrecv_req_send_mark(mfile *m, mdata *r)
{
  mmark *mm;
  mfile  *a;

  if(m->mdata.head.nstate != MAKUO_RECVSTATE_OPEN){
    return;
  }
  if(m->mdata.head.seqno < m->seqnomax){
    seq_addmark(m, m->mdata.head.seqno, m->seqnomax);
    m->mdata.head.seqno = m->seqnomax;
  }
  m->lickflag = 1;
  a = mkack(&(m->mdata),&(m->addr),MAKUO_RECVSTATE_MARK);
  if(!a){
    lprintf(0, "[error] %s: out of momory\n", __func__);
    return;
  }
  if(a->mdata.head.szdata){
    msend(a);
    return;
  }
  for(mm=m->mark;mm;mm=mm->next){
    if(data_safeset32(&(a->mdata), mm->l)){
      break;
    }
    if(data_safeset32(&(a->mdata), mm->h)){
      a->mdata.head.szdata -= sizeof(uint32_t);
      break;
    }
  }
  msend(a);
}

static void mrecv_req_send_data_write_error(mfile *m, mdata *r)
{
  msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
}

static void mrecv_req_send_data_write(mfile *m, mdata *r)
{
  off_t offset;
  if(r->head.szdata == 0){
    return;
  }
  offset  = r->head.seqno;
  offset *= MAKUO_BUFFER_SIZE;
  if(lseek(m->fd, offset, SEEK_SET) == -1){
    m->mdata.head.error  = errno;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_RECVSTATE_WRITEERROR;
    mrecv_req_send_data_write_error(m, r);
    lprintf(0, "[error] %s: seek error (%s) seq=%u\n",
      __func__,
      strerror(m->mdata.head.error), 
      (int)(r->head.seqno));
    return; /* lseek error */
  }
  if(write(m->fd, r->data, r->head.szdata) == -1){
    m->mdata.head.error  = errno;
    m->mdata.head.ostate = m->mdata.head.nstate;
    m->mdata.head.nstate = MAKUO_RECVSTATE_WRITEERROR;
    mrecv_req_send_data_write_error(m, r);
    lprintf(0, "[error] %s: write error (%s) seqno=%d size=%d %s\n",
      __func__,
      strerror(m->mdata.head.error), 
      (int)(r->head.seqno), 
      r->head.szdata,
      m->fn);
    return; /* write error */
  }
  m->recvcount++;
}

static void mrecv_req_send_data_retry(mfile *m, mdata *r)
{
  mmark *mm;
  mfile *a = mkack(&(m->mdata), &(m->addr), MAKUO_RECVSTATE_OPEN);
  if(!a){
    lprintf(0, "%s: out of momory\n", __func__);
    return;
  }
  if(a->mdata.head.szdata){
    return;
  }
  data_safeset32(&(a->mdata), m->mdata.head.seqno);
  data_safeset32(&(a->mdata), r->head.seqno);
  for(mm=m->mark;mm;mm=mm->next){
    if(data_safeset32(&(a->mdata), mm->l)){
      break;
    }
    if(data_safeset32(&(a->mdata), mm->h)){
      a->mdata.head.szdata -= sizeof(uint32_t);
      break;
    }
  }
  msend(a);
}

static void mrecv_req_send_data(mfile *m, mdata *r)
{
  if(m->mdata.head.nstate != MAKUO_RECVSTATE_OPEN){
    return;
  }
  if(m->lickflag){
    if(seq_delmark(m, r->head.seqno)){
      mrecv_req_send_data_write(m, r);
    }
    return;
  }
  if(m->mdata.head.seqno > r->head.seqno){
    if(seq_delmark(m, r->head.seqno)){
      mrecv_req_send_data_write(m, r);
    }
    return;
  }
  if(m->mdata.head.seqno < r->head.seqno){
    mrecv_req_send_data_retry(m, r);
    seq_addmark(m, m->mdata.head.seqno, r->head.seqno);
    m->mdata.head.seqno = r->head.seqno;
  }
  mrecv_req_send_data_write(m, r);
  m->mdata.head.seqno++;
}

static void mrecv_req_send_close(mfile *m, mdata *r)
{
  struct stat fs;
  struct utimbuf mftime;
  char   path[PATH_MAX];

  if(m->mdata.head.nstate == MAKUO_RECVSTATE_CLOSE || 
     m->mdata.head.nstate == MAKUO_RECVSTATE_CLOSEERROR){
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    return;
  }

  m->mdata.head.ostate = m->mdata.head.nstate;
  if(m->mdata.head.nstate != MAKUO_RECVSTATE_OPEN){
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    return;
  }

  mftime.actime  = m->fs.st_ctime; 
  mftime.modtime = m->fs.st_mtime;
 
  if(S_ISLNK(m->fs.st_mode)){
    if(!mrename(moption.base_dir, m->tn, m->fn)){
      m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
      msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    }else{
      m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
      msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
      lprintf(0, "%s: close error %s -> %s\n", __func__, m->ln, m->fn);
      mremove(moption.base_dir, m->tn);
    }
    return;
  }

  if(S_ISDIR(m->fs.st_mode)){
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    sprintf(path, "%s/%s", moption.base_dir, m->fn);
    utime(path, &mftime);
    return;
  }

  if(!S_ISREG(m->fs.st_mode)){
    if(!mrename(moption.base_dir, m->tn, m->fn)){
      m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
      msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
      sprintf(path, "%s/%s", moption.base_dir, m->tn);
      utime(path, &mftime);
    }else{
      m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
      msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
      lprintf(0, "[error] %s: close error %s (can't rename)\n", __func__, m->fn);
      mremove(moption.base_dir, m->tn);
    }
    return;
  }

  if(m->fd == -1){
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    lprintf(0, "[error] %s: bat discriptor close error %s\n", __func__, m->fn);
    mremove(moption.base_dir, m->tn);
    return;
  }

  if(fstat(m->fd, &fs) == -1){
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    lprintf(0, "[error] %s: %s fstat error %s\n", __func__, strerror(errno), m->fn);
    return; 
  }

  if(close(m->fd) == -1){
    m->fd = -1;
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    lprintf(0, "[error] %s: %s close error %s\n", __func__, strerror(errno), m->fn);
    return; 
  }

  m->fd = -1;
  if(fs.st_size != m->fs.st_size){
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    lprintf(0, "[error] %s: close error %s (file size mismatch %d != %d)\n", __func__, m->fn, (int)(fs.st_size), (int)(m->fs.st_size));
    lprintf(0, "[error] %s: seq=%d max=%d mark=%d recv=%d\n", __func__, m->mdata.head.seqno, m->seqnomax, m->markcount, m->recvcount);
    mremove(moption.base_dir, m->tn);
    return;
  }

  if(!mrename(moption.base_dir, m->tn, m->fn)){
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    sprintf(path, "%s/%s", moption.base_dir, m->fn);
    set_filestat(path, m->fs.st_uid, m->fs.st_gid, m->fs.st_mode);
    utime(path, &mftime);
  }else{
    m->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
    msend(mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate));
    lprintf(0, "%s: close error %s (can't rename)\n", __func__, m->fn);
    mremove(moption.base_dir, m->tn);
  }
}

static void mrecv_req_send_last(mfile *m, mdata *r)
{
  msend(mkack(r, &(m->addr), MAKUO_RECVSTATE_LAST));
  mrecv_mfdel(m);
}

static void mrecv_req_send_next(mfile *m, mdata *r)
{
  switch(r->head.nstate){
    case MAKUO_SENDSTATE_STAT:
      mrecv_req_send_stat(m, r);
      break;

    case MAKUO_SENDSTATE_OPEN:
      mrecv_req_send_open(m, r);
      break;

    case MAKUO_SENDSTATE_DATA:
      mrecv_req_send_data(m, r);
      break;

    case MAKUO_SENDSTATE_MARK:
      mrecv_req_send_mark(m, r);
      break;

    case MAKUO_SENDSTATE_CLOSE:
      mrecv_req_send_close(m, r);
      break;

    case MAKUO_SENDSTATE_LAST:
      mrecv_req_send_last(m, r);
      break;

    case MAKUO_SENDSTATE_BREAK:
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
  uint32_t  ldev;
  uint32_t  hdev;
  uint64_t  rdev;

  if(m = mrecv_req_search(data, addr)){
    return(m);
  }

  if(data->head.nstate != MAKUO_SENDSTATE_STAT){
    return(NULL);
  }

  /* create object */
  if(!(m = mfadd(1))){
    return(NULL);
  }

  /* copy header and addr */
  memcpy(&(m->addr), addr, sizeof(m->addr));
  memcpy(&(m->mdata.head), &(data->head), sizeof(m->mdata.head));

  /* read mstat */
  data->p = data->data;
  data_safeget(data, &fs, sizeof(fs));

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
  data_safeget(data, m->fn, fnlen);
  m->fn[fnlen] = 0;

  /* read linkname */
  data_safeget(data, m->ln, lnlen);
  m->ln[lnlen] = 0;

  /* rdev */
  data_safeget32(data, &hdev);
  data_safeget32(data, &ldev);
  rdev  = hdev;
  rdev <<=  32;
  rdev |= ldev;
  m->fs.st_rdev = (dev_t)rdev;

  /* Number of blocks */
  m->seqnomax = m->fs.st_size / MAKUO_BUFFER_SIZE;
  if(m->fs.st_size % MAKUO_BUFFER_SIZE){
    m->seqnomax++; 
  }

  return(m);
}

static void mrecv_req_send(mdata *data, struct sockaddr_in *addr)
{
  mfile *m;
  if(m = mrecv_req_send_create(data, addr)){
    mtimeget(&(m->lastrecv));
    mrecv_req_send_next(m, data);
  }else{
    if(data->head.nstate != MAKUO_SENDSTATE_DATA){
      mkack(data, addr, MAKUO_RECVSTATE_IGNORE);
    }
  }
}

static void mrecv_req_md5_open(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  int    r;
  int    l;
  mhash *h;

  if(!m){
    m = mfadd(1);
    if(!m){
      lprintf(0,"%s: out of memory\n", __func__);
      return;
    }
    memcpy(&(m->addr), addr, sizeof(m->addr));
    memcpy(&(m->mdata.head), &(data->head), sizeof(m->mdata.head));
    h = (mhash *)(data->data);
    l = ntohs(h->fnlen);
    memcpy(m->fn, h->filename, l);
    m->fn[l] = 0;
    m->fd = open(m->fn, O_RDONLY);
    if(m->fd == -1){
      m->mdata.head.error  = errno;
      m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
    }else{
      r = md5sum(m->fd, m->mdata.data);
      close(m->fd);
      m->fd = -1;
      if(r == -1){
	      lprintf(0, "%s: file read error %s\n", __func__, m->fn);
        m->mdata.head.error  = errno;
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
  mtimeget(&(m->lastrecv));
  mkack(&(m->mdata), &(m->addr), m->mdata.head.nstate);
}

static void mrecv_req_md5_close(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  mkack(data, addr, MAKUO_RECVSTATE_CLOSE);
  mrecv_mfdel(m);
}

/*
 * md5チェック要求を受け取ったときの処理
 * mfileオブジェクトを生成して
 * 対象ファイルのmd5を取得する
 */
static void mrecv_req_md5(mdata *data, struct sockaddr_in *addr)
{
  mfile *m = mrecv_req_search(data, addr);
  switch(data->head.nstate){
    case MAKUO_SENDSTATE_OPEN:
      mrecv_req_md5_open(m, data, addr);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      mrecv_req_md5_close(m, data, addr);
      break;
  }
}

static void dsync_write(int fd, char *base, uint8_t sta, uint16_t len, uint32_t mod)
{
  int r;
  size_t s;
  fd_set wfds;
  char buff[PATH_MAX + sizeof(sta) +  sizeof(mod) +  sizeof(len)];
  char *p = buff;

  if(!loop_flag){
    return;
  }
  if(!strcmp(base, ".")){
    return;
  }
  if(!memcmp(base, "./", 2)){
    base += 2;
    len  -= 2;
  }
  while(*base == '/'){
    base++;
    len--;
  }

  *(uint16_t *)p = len + sizeof(mod); 
  p += sizeof(len);
  *(uint32_t *)p = mod; 
  p += sizeof(mod);
  memcpy(p, base, len);

  p = buff;
  s = sizeof(len) + sizeof(mod) + len;
  while(s){
    FD_ZERO(&wfds);
    FD_SET(fd,&wfds);
    if(select(1024, NULL, &wfds, NULL, NULL) < 0){
      if(!loop_flag){
        return;
      }
      continue;
    }
    if(FD_ISSET(fd,&wfds)){
      r = write(fd, p, s);
      if(r == -1){
        if(errno == EINTR){
          continue;
        }
        lprintf(0, "[error] %s: write error\n", __func__);
        return;
      }else{
        s -= r;
        p += r;
      }
    }
  }
}

static void dsync_scan(int fd, char *base, int recurs, excludeitem *e)
{
  DIR *d;
  uint16_t len;
  struct stat st;
  struct dirent *dent;
  char path[PATH_MAX];

  if(!loop_flag){
    return;
  }
  /*----- exclude -----*/
  if(isexclude(base, e, 0)){
    return;
  }
  len = strlen(base);
  if(lstat(base, &st) == -1){
    dsync_write(fd, base, MAKUO_SENDSTATE_ERROR, len, st.st_mode);
    return;
  }
  if(S_ISLNK(st.st_mode)){
    dsync_write(fd, base, MAKUO_SENDSTATE_STAT, len, st.st_mode);
    return;
  }
  if(!S_ISDIR(st.st_mode)){
    dsync_write(fd, base, MAKUO_SENDSTATE_STAT, len, st.st_mode);
    return;
  }
  /*----- exclude dir -----*/
  if(isexclude(base, e, 1)){
    return;
  }
  d = opendir(base);
  if(!d){
    dsync_write(fd, base, MAKUO_SENDSTATE_ERROR, len, st.st_mode);
  }else{
    while(dent=readdir(d)){
      if(!loop_flag)
        break;
      if(!strcmp(dent->d_name, "."))
        continue;
      if(!strcmp(dent->d_name, ".."))
        continue;
      sprintf(path, "%s/%s", base, dent->d_name);
      if(recurs){
        dsync_scan(fd, path, recurs, e);
      }else{
        len = strlen(path);
        dsync_write(fd, path, MAKUO_SENDSTATE_STAT, len, st.st_mode);
      }
    }
    closedir(d);
    len = strlen(base);
    dsync_write(fd, base, MAKUO_SENDSTATE_STAT, len, st.st_mode);
  }
}

static void mrecv_req_dsync_open(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  mkack(data, addr, MAKUO_RECVSTATE_OPEN);
  if(m){
    return;
  }
  m = mfadd(1);
  m->mdata.head.opcode = data->head.opcode;
  m->mdata.head.reqid  = data->head.reqid;
  m->mdata.head.flags  = data->head.flags;
  m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
  memcpy(&(m->addr), addr, sizeof(m->addr));
  if(data->head.szdata){
    memcpy(m->fn, data->data, data->head.szdata);
  }
  m->fn[data->head.szdata] = 0;
}

static void mrecv_req_dsync_data(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  int  pid;
  int p[2];
  mfile *d;
  char path[PATH_MAX];
  uint16_t len;

  mkack(data, addr, MAKUO_RECVSTATE_OPEN);
  if(m->mdata.head.seqno >= data->head.seqno){
    return;
  }

  if(data->head.szdata){
    data->p = data->data;
    while(!data_safeget16(data, &len)){
      data_safeget(data, path, len);
      path[len] = 0;
      m->exclude = exclude_add(m->exclude, path);
      m->mdata.head.seqno++;
    }
    return;
  }

  d = mfins(0);
  d->link = m;
  m->link = d;
  d->initstate = 1;
  d->sendwait  = 0;
  d->exclude = m->exclude;
  m->exclude = NULL;
  d->mdata.head.opcode = MAKUO_OP_DEL;
  d->mdata.head.reqid  = getrid();
  d->mdata.head.flags  = data->head.flags;
  d->mdata.head.seqno  = data->head.reqid;
  d->mdata.head.nstate = MAKUO_SENDSTATE_STAT;
  memcpy(&(d->addr), addr, sizeof(d->addr));
  strcpy(d->fn, m->fn);
  d->sendto = 1;
  if(d->mdata.head.flags & MAKUO_FLAG_RECURS){
    d->recurs = 1;
  }
  if(d->mdata.head.flags & MAKUO_FLAG_DRYRUN){
    d->dryrun = 1;
  }

  /* fork */
  pipe(p);
  pid = fork();
  if(pid == -1){
    lprintf(0, "%s: %s fork error\n", __func__, strerror(errno));
    close(p[0]);
    close(p[1]);
    return;
  }
  if(pid){
    /* parent */
    d->pid  = pid;
    d->pipe = p[0];
    close(p[1]); /* write close */
    while(d->exclude = exclude_del(d->exclude));
  }else{
    /* child */
    close(p[0]); /* read close */
    dsync_scan(p[1], d->fn, d->recurs, d->exclude);
    close(p[1]);
    _exit(0);
  }  
}

static void mrecv_req_dsync_last(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  if(!m){
    return;
  }
  if(m->link){
    m->link->mdata.head.nstate = MAKUO_SENDSTATE_LAST;
    m->link->sendwait = 0;
  }
  mrecv_mfdel(m); 
}

static void mrecv_req_dsync_break(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  if(m){
    if(m->link){
      m->link->mdata.head.nstate = MAKUO_SENDSTATE_BREAK;
      m->link->sendwait = 0;
    }
    mrecv_mfdel(m);
  }
  mkack(data, addr, MAKUO_RECVSTATE_BREAK);
}

/*
 *  dsync
 */
static void mrecv_req_dsync(mdata *data, struct sockaddr_in *addr)
{
  mfile *m = mrecv_req_search(data, addr);
  switch(data->head.nstate){
    case MAKUO_SENDSTATE_OPEN:
      mrecv_req_dsync_open(m, data, addr);
      break;
    case MAKUO_SENDSTATE_DATA:
      mrecv_req_dsync_data(m, data, addr);
      break;
    case MAKUO_SENDSTATE_LAST:
      mrecv_req_dsync_last(m, data, addr);
      break;
    case MAKUO_SENDSTATE_BREAK:
      mrecv_req_dsync_break(m, data, addr);
      break;
  }
}

/*
 *  del
 */
static void mrecv_req_del_open(mdata *data, struct sockaddr_in *addr)
{
  uint16_t len;
  uint32_t mod;
  mhost *t = member_get(&(addr->sin_addr));
  mfile *a = mkack(data, addr, MAKUO_RECVSTATE_OPEN);
  char path[PATH_MAX];

  if(!a){
    lprintf(0, "[error] %s: ack can't create\n", __func__);
    return;
  }
  data->p = data->data;
  while(!data_safeget16(data, &len)){
    data_safeget32(data, &mod);
    len -= sizeof(uint32_t);
    data_safeget(data, path, len);
    path[len] =  0;
    if(lstat(path, &(a->fs)) == -1 && errno == ENOENT){
      data_safeset16(&(a->mdata), len + sizeof(uint32_t));
      data_safeset32(&(a->mdata), 0);
      data_safeset(&(a->mdata), path, len);
    }
  }
}

static void mrecv_req_del_data_report(mfile *m, mcomm *c, uint32_t err, char *hn, char *path)
{
  char *dryrun = "";

  if(m->dryrun){
    dryrun = "(dryrun) ";
  }
  if(err){
    cprintf(0, c,  "(%s) delete error %s:%s\n", strerror(err), hn, path);
    lprintf(1, "%s: (%s) delete error %s:%s\n", __func__, strerror(err), hn, path);
  }else{
    cprintf(0, c,  "%sdelete %s:%s\n", dryrun, hn, path);
    lprintf(1, "%s: %sdelete %s:%s\n", __func__, dryrun, hn, path);
  }
}

static void mrecv_req_del_data(mdata *data, struct sockaddr_in *addr)
{
  uint32_t err;
  uint16_t len;
  char *hn = "unknown host";
  mhost *t = member_get(&(addr->sin_addr));
  mcomm *c = NULL;
  mfile *m = mrecv_req_search(data, addr);
  mfile *a = mkack(data, addr, MAKUO_RECVSTATE_OPEN);
  char path[PATH_MAX];

  if(m){
    return;
  }
  if(t){
    hn = t->hostname;
  }
  m = mfadd(1);
  m->mdata.head.opcode = data->head.opcode;
  m->mdata.head.reqid  = data->head.reqid;
  m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
  memcpy(&(m->addr), addr, sizeof(m->addr));
  if(data->head.flags & MAKUO_FLAG_DRYRUN){
    m->dryrun = 1;
  }
  for(a=mftop[0];a;a=a->next){
    if((a->mdata.head.reqid == data->head.seqno) && (a->comm != NULL)){
      c = a->comm;
      break;
    } 
  }
  data->p = data->data;
  while(!data_safeget16(data, &len)){
    data_safeget32(data, &err);
    len -= sizeof(uint32_t);
    data_safeget(data, path, len);
    path[len] =  0;
    mrecv_req_del_data_report(m, c, err, hn, path);
  }
}

static void mrecv_req_del_close(mdata *data, struct sockaddr_in *addr)
{
  mfile *m = mrecv_req_search(data, addr);
  mfile *a = mkack(data, addr, MAKUO_RECVSTATE_CLOSE);
  mrecv_mfdel(m);
}

static void mrecv_req_del(mdata *data, struct sockaddr_in *addr)
{
  switch(data->head.nstate){
    case MAKUO_SENDSTATE_OPEN: 
      mrecv_req_del_open(data, addr);
      break;
    case MAKUO_SENDSTATE_DATA: 
      mrecv_req_del_data(data, addr);
      break;
    case MAKUO_SENDSTATE_CLOSE: 
      mrecv_req_del_close(data, addr);
      break;
  }
}

static void mrecv_req(mdata *data, struct sockaddr_in *addr)
{
  switch(data->head.opcode){
    case MAKUO_OP_PING:
      mrecv_req_ping(data,  addr);
      break;
    case MAKUO_OP_EXIT:
      mrecv_req_exit(data,  addr);
      break;
    case MAKUO_OP_SEND:
      mrecv_req_send(data,  addr);
      break;
    case MAKUO_OP_MD5:
      mrecv_req_md5(data,   addr);
      break;
    case MAKUO_OP_DSYNC:
      mrecv_req_dsync(data, addr);
      break;
    case MAKUO_OP_DEL:
      mrecv_req_del(data,   addr);
      break;
    default:
      mkack(data, addr, MAKUO_RECVSTATE_IGNORE);
      break;
  }
}

/******************************************************************
*
* Receive common functions (public)
*
*******************************************************************/
void mrecv_gc()
{
  mhost *t = members;
  mfile *m = mftop[1]; 

  /* file timeout */
  while(m){
    if(mtimeout(&(m->lastrecv), MAKUO_RECV_GCWAIT)){
      lprintf(0,"%s: mfile object GC state=%s %s\n",
        __func__, strrstate(m->mdata.head.nstate), m->fn);
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
      member_del_message(t, "pong time out");
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

void mrecv_clean()
{
  mfile *m = mftop[1];
  while(m=mrecv_mfdel(m));
}

int mrecv()
{
  mfile *m;
  mhost *t;
  mdata data;
  struct sockaddr_in addr;

  m = mftop[0];
  if(mrecv_packet(moption.mcsocket, &data, &addr) == -1){
    return(0);
  }
  if(t = member_get(&addr.sin_addr)){
    mtimeget(&(t->lastrecv));
  }
  if(data.head.flags & MAKUO_FLAG_ACK){
    mrecv_ack(&data, &addr);
  }else{
    mrecv_req(&data, &addr);
  }
  return(m == mftop[0]);
}


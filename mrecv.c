/*
 *  mrecv.c
 */
#include "makuosan.h"

/*
 * mfile を開放する
 * mrecv.c の中で生成した mfile は必ずここで開放すること
 */
static mfile *mrecv_mfdel(mfile *m)
{
  mfile *r;
  if(!m)
    return(NULL);
  r = m->next;
  if(m->fd != -1){
    close(m->fd);
    m->fd = -1;
    if(S_ISREG(m->fs.st_mode))
      mremove(moption.base_dir, m->tn);
  }
  if(m->mark){
    free(m->mark);
    m->mark = NULL;
  }
  mfdel(m);
  return(r);
}

static void mrecv_ping(mdata *data, struct sockaddr_in *addr)
{
  mping *p;
  mfile *m;
  char buff[HOST_NAME_MAX + 1];
  member_add(&addr->sin_addr, data);
  m = mfadd(0);
  if(!m){
    return;
  }
  m->mdata.head.opcode    = MAKUO_OP_PONG;
  m->mdata.head.reqid   = getrid();
  m->mdata.head.seqno = 0;
  m->mdata.head.szdata  = 0;
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

static void mrecv_pong(mdata *data, struct sockaddr_in *addr)
{
  member_add(&addr->sin_addr, data);
}

static void mrecv_exit(mdata *data, struct sockaddr_in *addr)
{
  mhost *h;
  for(h=members;h;h=h->next)
    if(!memcmp(&(h->ad), &(addr->sin_addr), sizeof(h->ad)))
      break;
  member_del(h);
}

/*
 *  データ受信
 */
static int mrecv_file_data(mfile *m,  mdata *r)
{
  if(m->mdata.head.nstate != MAKUO_RECVSTATE_OPEN)
    return(0);

  if(m->lickflag){
    if(!seq_delmark(m, r->head.seqno)){
      return(0);
    }
  }else{
    if(r->head.seqno < m->mdata.head.seqno){
      seq_delmark(m, r->head.seqno);
    }else{
      m->mdata.head.seqno++;
      if(m->mdata.head.seqno < r->head.seqno){
        seq_addmark(m, m->mdata.head.seqno, r->head.seqno);
        m->mdata.head.seqno = r->head.seqno;
      }
    }
  }
  if(lseek(m->fd, (r->head.seqno - 1) * MAKUO_BUFFER_SIZE, SEEK_SET) == -1){
    lprintf(0, "mrecv_file_data: seek error seq=%d size=%d fd=%d err=%d\n", (int)r->head.seqno, r->head.szdata, m->fd, errno);
    m->mdata.head.nstate = MAKUO_RECVSTATE_WRITEERROR;
  }else{
    if(write(m->fd, r->data, r->head.szdata) != -1){
      m->recvcount++;
    }else{
      lprintf(0, "mrecv_file_data: write error seqno=%d size=%d fd=%d err=%d\n", (int)r->head.seqno, r->head.szdata, m->fd, errno);
      m->mdata.head.nstate = MAKUO_RECVSTATE_WRITEERROR;
    }
  }
  return(0);
}

/*
 *  転送中断
 */
static int mrecv_file_break(mfile *m, mdata *r)
{
  mrecv_mfdel(m);
  return(0);
}

/*
 *  転送開始処理
 */
static int mrecv_file_open(mfile *m, mdata *r)
{
  char fpath[PATH_MAX];
  char tpath[PATH_MAX];

  if(m->mdata.head.nstate != MAKUO_RECVSTATE_UPDATE)
    return(0);

  sprintf(fpath, "%s/%s", moption.base_dir, m->fn);
  sprintf(tpath, "%s/%s", moption.base_dir, m->tn);

  mfile *a = mfins(0);
  a->mdata.head.opcode = MAKUO_OP_ACK;
  a->mdata.head.reqid = r->head.reqid;
  a->mdata.head.seqno = r->head.seqno;
  a->mdata.head.ostate = m->mdata.head.nstate;
  a->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
  m->mdata.head.nstate = MAKUO_RECVSTATE_OPEN;
  memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
  if(S_ISLNK(m->fs.st_mode)){
    mtempname(moption.base_dir, m->fn, m->tn);
    sprintf(tpath, "%s/%s", moption.base_dir, m->tn);
    if(symlink(m->ln, m->tn) != -1){
      lprintf(2, "mrecv_file: open %s -> %s\n", m->ln, m->fn);
    }else{
      lprintf(0, "mrecv_file: symlink error %s\n", m->fn);
      m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
      a->mdata.head.nstate = m->mdata.head.nstate;
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
        lprintf(0,"mrecv_file: mkdir error %s\n", m->fn);
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
        a->mdata.head.nstate = m->mdata.head.nstate;
      }
    }
    if(S_ISREG(m->fs.st_mode)){
      mtempname(moption.base_dir, m->fn, m->tn);
      sprintf(tpath, "%s/%s", moption.base_dir, m->tn);
      m->fd = mcreate(moption.base_dir, m->tn, m->fs.st_mode);
      if(m->fd == -1){
        lprintf(0, "mrecv_file: open error %s\n", m->fn);
        m->mdata.head.nstate = MAKUO_RECVSTATE_OPENERROR;
        a->mdata.head.nstate = m->mdata.head.nstate;
      }
    }
  }
  return(0);
}

/*
 *  転送終了処理
 */
static int mrecv_file_close(mfile *m, mdata *r)
{
  struct utimbuf mftime;
  char  fpath[PATH_MAX];
  char  tpath[PATH_MAX];
  sprintf(fpath, "%s/%s", moption.base_dir, m->fn);
  sprintf(tpath, "%s/%s", moption.base_dir, m->tn);

  if(m->mdata.head.nstate == MAKUO_RECVSTATE_OPEN  ||
     m->mdata.head.nstate == MAKUO_RECVSTATE_UPDATE){
    mfile *a = mfins(0);
    a->mdata.head.opcode = MAKUO_OP_ACK;
    a->mdata.head.reqid = r->head.reqid;
    a->mdata.head.seqno = r->head.seqno;
    a->mdata.head.ostate = m->mdata.head.nstate;
    a->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
    memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
    if(m->mdata.head.nstate == MAKUO_RECVSTATE_OPEN){
      if(m->fd != -1){
        fstat(m->fd, &(a->fs));
        close(m->fd);
      }
      m->fd = -1;
      mftime.actime  = m->fs.st_ctime; 
      mftime.modtime = m->fs.st_mtime;
      if(S_ISLNK(m->fs.st_mode)){
        if(!mrename(moption.base_dir, m->tn, m->fn)){
          lprintf(2, "mrecv_file: close %s -> %s\n", m->ln, m->fn);
        }else{
          a->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
          mremove(moption.base_dir, m->tn);
          lprintf(0, "mrecv_file: close error %s -> %s\n", m->ln, m->fn);
        }
      }else{
        if(S_ISDIR(m->fs.st_mode)){
          utime(fpath, &mftime);
        }else{
          utime(tpath, &mftime);
          if(a->fs.st_size != m->fs.st_size){
            a->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
            mremove(moption.base_dir, m->tn);
            lprintf(0, "mrecv_file: close error %s (file size mismatch %d != %d)\n", m->fn, (int)(a->fs.st_size), (int)(m->fs.st_size));
            lprintf(0, "mrecv_file: seq=%d max=%d markcnt=%d\n",m->mdata.head.seqno, m->seqnomax, m->markcount);
          }else{
            if(!mrename(moption.base_dir, m->tn, m->fn)){
              lprintf(2, "mrecv_file: close %s recv=%d mark=%d\n", m->fn , m->recvcount, m->markcount);
            }else{
              a->mdata.head.nstate = MAKUO_RECVSTATE_CLOSEERROR;
              mremove(moption.base_dir, m->tn);
              lprintf(0, "mrecv_file: close error %s\n", m->fn);
            }
          }
        }
        if(!geteuid()){
          chown(fpath, m->fs.st_uid, m->fs.st_gid);
        }
      }
    }
  }
  mrecv_mfdel(m);
  return(0);
}

/*
 *  再送要求
 */
static int mrecv_file_mark(mfile *m, mdata *r)
{
  if(m->mdata.head.nstate != MAKUO_RECVSTATE_OPEN)
    return(0);

  mfile *a = mfins(0);
  a->mdata.head.opcode    = MAKUO_OP_ACK;
  a->mdata.head.reqid   = r->head.reqid;
  a->mdata.head.seqno = r->head.seqno;
  a->mdata.head.nstate = m->mdata.head.nstate;
  a->mdata.head.szdata  = 0;
  memcpy(&(a->addr), &(m->addr), sizeof(a->addr));
  m->lickflag = 1;
  a->lickflag = 1;
  if(m->mdata.head.seqno < m->seqnomax){
    seq_addmark(m, m->mdata.head.seqno, m->seqnomax + 1);
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
    lprintf(3, "mrecv_file: retry %s recv=%d mark=%d reqest=%d\n", m->fn , m->recvcount, m->markcount, a->markcount);
  }
  return(0);
}

/*
 *  受信状態遷移関数
 *
 */
static int mrecv_file_next(mfile *m,  mdata *r)
{
  if(r->head.seqno){
    return(mrecv_file_data(m, r));
  }
  switch(r->head.nstate){
    case MAKUO_SENDSTATE_BREAK:
      lprintf(9,"mrecv_file: MAKUO_SENDSTATE_BREAK: state=%d %s\n", m->mdata.head.nstate, m->fn);
      return(mrecv_file_break(m, r));
    case MAKUO_SENDSTATE_OPEN:
      lprintf(9,"mrecv_file: MAKUO_SENDSTATE_OPEN : state=%d %s\n", m->mdata.head.nstate, m->fn);
      return(mrecv_file_open(m, r));
    case MAKUO_SENDSTATE_MARK:
      lprintf(9,"mrecv_file: MAKUO_SENDSTATE_MARK : state=%d seqno=%d max=%d cnt=%d %s\n", 
             m->mdata.head.nstate, m->mdata.head.seqno, m->seqnomax, m->markcount, m->fn);
      return(mrecv_file_mark(m, r));
    case MAKUO_SENDSTATE_CLOSE:
      lprintf(9,"mrecv_file: MAKUO_SENDSTATE_CLOSE: state=%d %s\n", m->mdata.head.nstate, m->fn);
      return(mrecv_file_close(m, r));
  }
  return(0);
}

/*
 *  ファイルの受信を開始するために呼び出される関数
 *  - 引数として生データが格納されているバッファのポインタを受け取る
 *  - 受信したデータが転送開始メッセージならばmfileを生成する
*/
static mfile *mrecv_file_stat(mdata *data, struct sockaddr_in *addr)
{
  mstat fs;
  uint16_t  fnlen;
  uint16_t  lnlen;
  mfile *m = NULL;
  mfile *a = NULL;
  struct utimbuf mftime;

  /* 転送中のパケットは無視する */
  if(data->head.seqno)
    return(NULL);

  a = mfins(0);
  a->mdata.head.opcode    = MAKUO_OP_ACK;
  a->mdata.head.reqid   = data->head.reqid;
  a->mdata.head.szdata  = 0;
  a->mdata.head.seqno = data->head.seqno;
  a->mdata.head.nstate = MAKUO_RECVSTATE_IGNORE;
  memcpy(&(a->addr), addr, sizeof(a->addr));
  if(data->head.nstate == MAKUO_SENDSTATE_STAT){
    m = mfadd(1);
    mtimeget(&(m->lastrecv));
    data->p = data->data;
    memcpy(&(m->addr), addr, sizeof(m->addr));
    memcpy(&(m->mdata.head), &(data->head), sizeof(m->mdata.head));

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

    m->seqnomax = m->fs.st_size / MAKUO_BUFFER_SIZE;
    if(m->fs.st_size % MAKUO_BUFFER_SIZE){
      m->seqnomax++; 
    }
    if(moption.dontrecv){
      m->mdata.head.nstate = MAKUO_RECVSTATE_READONLY;
    }else{
      if(S_ISLNK(m->fs.st_mode)){
        m->mdata.head.nstate = linkcmp(m);
      }else{
        if(lstat(m->fn, &(a->fs)) == -1){
          m->mdata.head.nstate = MAKUO_RECVSTATE_UPDATE;
        }else{
          m->mdata.head.nstate = statcmp(&(m->fs), &(a->fs));
        }
      }
    }
    a->mdata.head.nstate = m->mdata.head.nstate;
    lprintf(9,"mrecv_file: MAKUO_SENDSTATE_STAT : state=%d %s\n", m->mdata.head.nstate, m->fn);
  }
  return(m);
}

static void mrecv_file(mdata *data, struct sockaddr_in *addr)
{
  mfile *m = mftop[1]; 
  while(m){
    if(!memcmp(&m->addr, addr, sizeof(m->addr)) && m->mdata.head.reqid == data->head.reqid){
      mtimeget(&m->lastrecv);
      break;
    }
    m = m->next;
  }
  if(!m){
    mrecv_file_stat(data, addr);
  }else{
    mtimeget(&(m->lastrecv));
    mrecv_file_next(m, data);
  }
}

static void mrecv_ack_file(mfile *m, mhost *h, mdata *data)
{
  uint32_t *d;

  if(data->head.nstate == MAKUO_RECVSTATE_IGNORE){
    cprintf(4, m->comm, "%s: file update ignore %s\n", h->hostname, m->fn);
    lprintf(0,          "mrecv_ack: file update ignore rid=%06d state=%02d %s(%s) %s\n", 
      data->head.reqid, data->head.nstate, inet_ntoa(h->ad), h->hostname, m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_OPEN){
    d = (uint32_t *)(data->data);
    while(d < (uint32_t *)&data->data[data->head.szdata]){
      seq_addmark(m, *d, (*d) + 1);
      d++;
    }
  }
}

static void mrecv_ack_md5(mfile *m, mhost *h, mdata *data)
{
  if(h->state != data->head.nstate){
    if(data->head.nstate == MAKUO_RECVSTATE_MD5OK){
      cprintf(1, m->comm, "%s: OK %s\r\n", h->hostname, m->fn);
      lprintf(1,          "mrecv_ack_md5: OK %s\n", m->fn);
    }
    if(data->head.nstate == MAKUO_RECVSTATE_MD5NG){
      cprintf(0, m->comm, "%s: NG %s\r\n", h->hostname, m->fn);
      lprintf(0,          "mrecv_ack_md5: NG %s\n", m->fn);
    }
  }
}

/*
 *  ack受信処理
 */
static void mrecv_ack(mdata *data, struct sockaddr_in *addr)
{
  mfile *m;
  mhost *h;

  h = member_add(&addr->sin_addr, NULL);
  if(!h){
    lprintf(0, "mrecv_ack: member not found %s\n", inet_ntoa(addr->sin_addr));
    return;
  }
  for(m=mftop[0];m;m=m->next)
    if(m->mdata.head.reqid == data->head.reqid)
      break;
  if(!m){
    lprintf(4, "mrecv_ack: mfile not found rid=%06d state=%02d %s(%s)\n", 
      data->head.reqid, data->head.nstate, inet_ntoa(addr->sin_addr), h->hostname);
    return;
  }
  mtimeget(&m->lastrecv);
  switch(m->mdata.head.opcode){
    case MAKUO_OP_FILE:
      mrecv_ack_file(m,h,data);
      break;
    case MAKUO_OP_MD5:
      mrecv_ack_md5(m,h,data);
      break;
  }
  if(data->head.nstate == MAKUO_RECVSTATE_OPENERROR){
    cprintf(0, m->comm, "%s: file open error %s\n", h->hostname, m->fn);
    lprintf(0,          "mrecv_ack: file open error rid=%06d state=%02d %s(%s) %s\n", 
      data->head.reqid, data->head.nstate, inet_ntoa(h->ad), h->hostname, m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_WRITEERROR){
    cprintf(0, m->comm, "%s: file write error %s\n", h->hostname, m->fn);
    lprintf(0,          "mrecv_ack: file write error rid=%06d state=%02d %s(%s) %s\n", 
     data->head.reqid, data->head.nstate, inet_ntoa(h->ad), h->hostname, m->fn);
  }
  if(data->head.nstate == MAKUO_RECVSTATE_CLOSEERROR){
    cprintf(0, m->comm, "%s: file close error %s\n", h->hostname, m->fn);
    lprintf(0,          "mrecv_ack: file close error rid=%06d state=%02d %s(%s) %s\n", 
      data->head.reqid, data->head.nstate, inet_ntoa(h->ad), h->hostname, m->fn);
  }
  h->state = data->head.nstate;
  return;
}

static void mrecv_md5_open(mfile *m, mdata *data, struct sockaddr_in *addr)
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
	      lprintf(0, "mrecv_md5: file read error %s\n", m->fn);
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
  a->mdata.head.opcode    = MAKUO_OP_ACK;
  a->mdata.head.reqid   = m->mdata.head.reqid;
  a->mdata.head.seqno = 0;
  a->mdata.head.szdata  = 0;
  a->mdata.head.nstate = m->mdata.head.nstate;
  memcpy(&(a->addr), addr, sizeof(a->addr));
  mtimeget(&(m->lastrecv));
}

static void mrecv_md5_close(mfile *m, mdata *data, struct sockaddr_in *addr)
{
  mfile *a = mfadd(0);
  a->mdata.head.opcode    = MAKUO_OP_ACK;
  a->mdata.head.reqid   = data->head.reqid;
  a->mdata.head.szdata  = 0;
  a->mdata.head.seqno = 0;
  a->mdata.head.nstate = MAKUO_RECVSTATE_CLOSE;
  memcpy(&(a->addr), addr, sizeof(a->addr));
  mrecv_mfdel(m);
}

/*
 * md5チェック要求を受け取ったときの処理
 * mfileオブジェクトを生成して
 * 対象ファイルのmd5を取得する
 */
static void mrecv_md5(mdata *data, struct sockaddr_in *addr)
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
      mrecv_md5_open(m, data, addr);
      break;
    case MAKUO_SENDSTATE_CLOSE:
      mrecv_md5_close(m, data, addr);
      break;
  }
}

static int mrecv_decrypt(mdata *data, struct sockaddr_in *addr)
{
  int i;
  MD5_CTX ctx;
  uint8_t hash[16];

  if(data->head.flags & MAKUO_FLAG_CRYPT){
    if(!moption.cryptena){
      lprintf(0, "mrecv_decrypt: recv encrypt packet from %s. I have not key!", inet_ntoa(addr->sin_addr));
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
        lprintf(0, "mrecv_decrypt: protocol checksum error from %s\n", inet_ntoa(addr->sin_addr));
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
        lprintf(0, "mrecv_packets: recv error from %s\n", inet_ntoa(addr->sin_addr));
        return(-1);
      }
    }
  }
  if(recvsize < sizeof(data->head)){
    lprintf(0, "mrecv: recv head size error\n");
    return(-1);
  }

  /* ヘッダをホストバイトオーダに変換する */
  data->head.szdata = ntohs(data->head.szdata);
  data->head.flags  = ntohs(data->head.flags);
  data->head.reqid  = ntohl(data->head.reqid);
  data->head.seqno  = ntohl(data->head.seqno);

  /* プロトコルバージョンが一致しないパケットは破棄する */
  if(data->head.vproto != PROTOCOL_VERSION){
    lprintf(0, "mrecv_packet: protocol version error(%d != %d) from %s\n",
       data->head.vproto, PROTOCOL_VERSION, inet_ntoa(addr->sin_addr));
    return(-1);
  }

  return(mrecv_decrypt(data, addr));
}

/*
 *  通信断などで残ってしまったオブジェクトを掃除
 */
void mrecv_gc()
{
  mhost *t = members;
  mfile *m = mftop[1]; 
  while(m){
    if(mtimeout(&(m->lastrecv), MAKUO_RECV_GCWAIT)){
      lprintf(0,"mrecv_gc: mfile object GC state=%d %s\n", m->mdata.head.nstate, m->fn);
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
      lprintf(0,"mrecv_gc: pong timeout %s\n", t->hostname);
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

/*
 *  ソケットからデータを読み込んでmdata構造体に格納
 *  オペコードによってそれぞれの処理に分岐する
 */
void mrecv(int s)
{
  mdata  data;
  struct sockaddr_in addr;

  if(mrecv_packet(s, &data, &addr) == -1){
    return;
  }
  switch(data.head.opcode){
    case MAKUO_OP_PING:
      mrecv_ping(&data, &addr);
      break;
    case MAKUO_OP_PONG:
      mrecv_pong(&data, &addr);
      break;
    case MAKUO_OP_EXIT:
      mrecv_exit(&data, &addr);
      break;
    case MAKUO_OP_ACK:
      mrecv_ack(&data, &addr);
      break;
    case MAKUO_OP_FILE:
      mrecv_file(&data, &addr);
      break;
    case MAKUO_OP_MD5:
      mrecv_md5(&data, &addr);
      break;
  }
}


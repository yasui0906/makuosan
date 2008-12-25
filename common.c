/*
 * common.c
 * Copyright (C) 2008 KLab Inc.
 */
#include "makuosan.h"

mopt moption;
mfile *mftop[2] = {NULL,NULL};
mhost *members  = NULL;
int loop_flag   = 1;
struct timeval curtime;
BF_KEY EncKey;

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
                       "SEND_UNKNOWN"};

uint8_t sstatenumlist[]={MAKUO_SENDSTATE_STAT,
                         MAKUO_SENDSTATE_OPEN,
                         MAKUO_SENDSTATE_DATA,
                         MAKUO_SENDSTATE_MARK,
                         MAKUO_SENDSTATE_CLOSE,
                         MAKUO_SENDSTATE_LAST,
                         MAKUO_SENDSTATE_ERROR,
                         MAKUO_SENDSTATE_BREAK,
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

int md5sum(int fd, unsigned char *digest)
{
  int  rd;
  char buff[1024];
  MD5_CTX ctx;
  MD5_Init(&ctx);
  while(rd = read(fd, buff, sizeof(buff))){
    if(rd == -1){
      return(-1);
    }
    MD5_Update(&ctx, buff, rd);
  }
  MD5_Final(digest, &ctx);
  return(0);
}

/*
 *  タイムアウト時間が経過しているかどうかを判断する
 *   - 現在時刻がtfからmsec[ms]経過していれば1を返す
 *   - それ以外は0を返す
 */
int mtimeout(struct timeval *tf, uint32_t msec)
{
  struct timeval tv;
  struct timeval tr;
  
  if((tf->tv_sec == 0) && (tf->tv_usec == 0)){
    return(0);
  }
  tv.tv_sec  = msec / 1000;
  tv.tv_usec = (msec % 1000) * 1000;
  timeradd(tf, &tv, &tr);
  return(timercmp(&tr, &curtime, <));
}

/*
 *  現在時刻を取得する
 *  （といってもcurtimeをコピーするだけだけど）
 */
int mtimeget(struct timeval *tv)
{
  memcpy(tv, &curtime, sizeof(curtime));
  return(0);
}

/*
 *  ファイル名がexcludeリストにマッチするかどうかを調べる
 *   - マッチした場合はそのexcludeitem構造体のポインタを返す
 *   - マッチしない場合はNULLを返す
 */
excludeitem *mfnmatch(char *str, excludeitem *exclude)
{
  char *p;
  excludeitem *e;
  for(e=exclude;e;e=e->next){
    p=str;
    while(*p){
      if(strlen(p) < strlen(e->pattern)){
        break;
      }
      if(!fnmatch(e->pattern, p, FNM_PATHNAME)){
        return(e);
      }
      while(*p){
        if(*(p++) == '/'){
          break;
        }
      }
    }
  }
  return(NULL);
}

int isexclude(char *fn, excludeitem *exclude, int dir)
{
  char path[PATH_MAX];
  if(!strcmp(fn, ".")){
    fn = "";
  }
  if(!memcmp(fn, "./", 2)){
    fn += 2;
  }
  while(*fn == '/'){
    fn++;
  }
  if(dir){
    sprintf(path, "%s/%s/", moption.real_dir, fn);
  }else{
    sprintf(path, "%s/%s" , moption.real_dir, fn);
  }
  if(mfnmatch(path, exclude)){
    return(1);
  }
  return(0);
}

void fdprintf(int s, char *fmt, ...)
{
  char m[2048];
  va_list arg;
  if(s != -1){
    va_start(arg, fmt);
    vsprintf(m, fmt, arg);
    va_end(arg);
    write(s, m, strlen(m));
  }
}

void lprintf(int l, char *fmt, ...)
{
  va_list arg;
  struct timeval tv;
  char msg[2048];
  if(moption.loglevel >= l){
    va_start(arg, fmt);
    vsprintf(msg, fmt, arg);
    va_end(arg);
#ifdef MAKUO_DEBUG
    gettimeofday(&tv, NULL);
    fprintf(stderr, "%02d.%06d %s", tv.tv_sec % 60, tv.tv_usec, msg);
#else
    fprintf(stderr, "%s", msg);
#endif
    syslog(LOG_ERR, "%s: %s", moption.user_name, msg);
  }
}

void cprintf(int l, mcomm *c, char *fmt, ...)
{
  char m[2048];
  va_list arg;
  if(!c)
    return;
  if(c->fd[0] == -1)
    return;
  if(c->loglevel >= l){
    va_start(arg, fmt);
    vsprintf(m, fmt, arg);
    va_end(arg);
    write(c->fd[0], m, strlen(m));
    fsync(c->fd[0]);
  }
}

void mprintf(const char *func, mfile *m)
{
  lprintf(9, "%s: rid=%d init=%d wait=%d %s %s %s %s\n",
    func, 
    m->mdata.head.reqid, 
    m->initstate, m->sendwait, 
    inet_ntoa(m->addr.sin_addr), 
    stropcode(&(m->mdata)),
    strmstate(&(m->mdata)),
    m->fn);
}

uint32_t getrid()
{
  static uint32_t rid=0;
  return(rid++);
}

int workend(mcomm *c)
{
  if(c){
    if(c->working && !c->cpid){
      c->working = 0;
      if(moption.commpass && !c->authchk){
        cprintf(0, c, "password: \x1b]E");
      }else{
        cprintf(0,c,"> ");
        lprintf(1,"mexec: ======= separator =======\n");
      }
    }
  }
  return(0);
}

void mfdel(mfile *m)
{
  mfile *p;
  mfile *n;
  if(m){
    if(p = (mfile *)m->prev)
      p->next = m->next;
    if(n = (mfile *)m->next)
      n->prev = m->prev;
    if(mftop[0] == m)
      mftop[0] = n;
    if(mftop[1] == m)
      mftop[1] = n;
    free(m);
  }
}

mfile *mfnew()
{
  mfile *m;
  if(m = (mfile *)malloc(sizeof(mfile))){
    memset(m, 0, sizeof(mfile));
    m->mdata.head.maddr  = moption.maddr.sin_addr.s_addr;
    m->mdata.head.mport  = moption.maddr.sin_port;
    m->mdata.head.vproto = PROTOCOL_VERSION;
    m->fd   = -1;
    m->pipe = -1;
    m->retrycnt = MAKUO_SEND_RETRYCNT;
    memcpy(&(m->addr), &(moption.maddr), sizeof(m->addr));
  }
  return(m);
}

mfile *mfadd(int n)
{
  mfile *m;
  if(m = mfnew()){
    if(!mftop[n]){
      mftop[n] =m;
    }else{
      mfile *l;
      for(l=mftop[n];l->next;l=l->next);
      l->next = m;
      m->prev = l;
      m->next = NULL;
    }
  }
  return(m);
}

mfile *mfins(int n)
{
  mfile *m;
  if(m = mfnew()){
    if(mftop[n]){
      mftop[n]->prev = m;
      m->next = mftop[n];
    }
    mftop[n] =m;
  }
  return(m);
}

mhost *member_get(struct in_addr *addr)
{
  mhost *t;
  for(t=members;t;t=t->next){
    if(!memcmp(&t->ad, addr, sizeof(t->ad))){
      break;
    }
  }
  return(t); 
}

mhost *member_add(struct in_addr *addr, mdata *data)
{
  int f = 0;
  int l = 0;
  mping *p = NULL;
  mhost *t = member_get(addr);

  if(!t){
    f = 1;
    t = malloc(sizeof(mhost));
    if(!t){
      lprintf(0, "%s: out of memory\n", __func__);
      return(NULL);
    }
    memset(t, 0, sizeof(mhost));
    memcpy(&t->ad, addr, sizeof(t->ad));
    if(members){
      members->prev = t;
      t->next = members;
    }
    members = t;
    t->hostname[0] = 0;
  }
  if(data){
    if(data->head.opcode == MAKUO_OP_PING){
      p = (mping *)data->data;
      l = ntohs(p->hostnamelen);
      data->p = p->data;
      memcpy(t->hostname, data->p, l);
      t->hostname[l] = 0;
      data->p += l;
      l = ntohs(p->versionlen);
      memcpy(t->version,  data->p, l);
      t->version[l] = 0;
    }
  }
  if(f){
    lprintf(0, "%s: %s (%s)\n", __func__, inet_ntoa(t->ad), t->hostname);
  }
  mtimeget(&(t->lastrecv));
  return(t);
}

void member_del(mhost *t)
{
  mhost *p;
  mhost *n;
  if(!t){
    return;
  }
  lprintf(0, "%s: %s (%s)\n", __func__, inet_ntoa(t->ad), t->hostname);
  if(p = (mhost *)t->prev){
    p->next = t->next;
  }
  if(n = (mhost *)t->next){
    n->prev = t->prev;
  }
  if(members == t){
    members = n;
  }
  free(t);
}

void member_del_message(mhost *t, char *mess)
{
  int i;
  for(i=0;i<MAX_COMM;i++){
    if(moption.comm[i].working){
      cprintf(0, &(moption.comm[i]), "error: %s %s(%s)\n", 
        mess, 
        inet_ntoa(t->ad), 
        t->hostname);
    }
  }
}

mmark *markalloc()
{
  mmark *mm = calloc(1, sizeof(mmark));
  return(mm);

}

void markfree(mmark *mm)
{
  free(mm);
}

mmark *addmark(mmark *mm, uint32_t l, uint32_t h)
{
  mmark *nn = markalloc();
  nn->l = l;
  nn->h = h;
  if(mm){
    nn->next = mm;
    nn->prev = mm->prev;
    mm->prev = nn;
    if(nn->prev){
      nn->prev->next = nn;
    }
  }
  return(nn);
}

mmark *delmark(mmark *mm)
{
  mmark *nn = NULL;
  if(mm){
    if(mm->prev){
      mm->prev->next = mm->next;
    }
    if(mm->next){
      mm->next->prev = mm->prev;
    }
    nn = mm->next;
    markfree(mm);
  }
  return(nn);
}

void seq_addmark(mfile *m, uint32_t l, uint32_t h)
{
  mmark *mm;
  if(!m){
    return;
  }
  if(h == l){
    return;
  }
  m->markcount += (h - l);
  m->mark = addmark(m->mark, l, h);

  int c=0;
  for(mm=m->mark;mm;mm=mm->next){
    c++;
  }
  lprintf(9, "%s: %06d->%06d (%d) markcount=%d marklist=%d %s\n", __func__, l, h, h - l, m->markcount, c, m->fn);
  return;
}

int seq_delmark(mfile *m, uint32_t seq)
{
  uint32_t l;
  uint32_t h;
  mmark  *mm;
  if(!m){
    return(0);
  }

  for(mm=m->mark;mm;mm=mm->next){
    l = mm->l;
    h = mm->h - 1;
    if(seq == l){
      mm->l++;
      if(mm->l == mm->h){
        if(mm == m->mark){
          m->mark = mm->next;
        }
        delmark(mm);
      }
      m->markcount--;
      return(1);
    }
    if(seq == h){
      mm->h--;
      if(mm->l == mm->h){
        if(mm == m->mark){
          m->mark = mm->next;
        }
        delmark(mm);
      }
      m->markcount--;
      return(1);
    }
    if((seq>l) && (seq<h)){
      if(mm == m->mark){
        m->mark = addmark(mm, mm->l, seq);
      }else{
        addmark(mm, mm->l, seq);
      }
      mm->l = seq + 1;
      m->markcount--;
      return(1);
    }
  }
  return(0);
}

void seq_setmark(mfile *m, uint32_t l, uint32_t h)
{
  mmark *mm;
  mmark *mn;

  if(!m){
    return;
  }
  mm = m->mark;
  mn = addmark(NULL, l, h);
  while(mm){
    if((mn->h < mm->l) || (mn->l > mm->h)){
      mm = mm->next;
      continue;
    }
    if(mn->l > mm->l){
      mn->l = mm->l;
    }
    if(mn->h < mm->h){
      mn->h = mm->h;
    }
    if(mm == m->mark){
      m->mark = mm->next;
    }
    mm = delmark(mm);
  }
  if(mn->next = m->mark){
    m->mark->prev = mn;
  }
  m->mark = mn;
  m->markcount = 0;
  for(mm=m->mark;mm;mm=mm->next){
    m->markcount += (mm->h - mm->l);
  }
  lprintf(9, "%s: %06d->%06d (%d) rid=%d %s\n", __func__, l, h, h - l, m->mdata.head.reqid, m->fn);
}

uint32_t seq_getmark(mfile *m)
{
  uint32_t seq;
  if(!m){
    return(0);
  }
  if(!m->mark){
    return(0);
  }
  seq = m->mark->l;
  m->markcount--;
  m->mark->l++;
  if(m->mark->l == m->mark->h){
    m->mark = delmark(m->mark);
  }  
  return(seq);
}

void clr_hoststate(mfile *m)
{
  int i;
  mhost *t;
  for(t=members;t;t=t->next){
    for(i=0;i<MAKUO_PARALLEL_MAX;i++){
      if(t->mflist[i] == m){
        t->mflist[i] = NULL;
        t->state[i]  = 0;
      }
    }
  }
}

void dump_hoststate(mfile *m, char *func)
{
  mhost   *t;
  uint8_t *r;
  for(t=members;t;t=t->next){
    if(r=get_hoststate(t,m)){
      lprintf(9,"%s: %s from %s %s\n", func, strrstate(*r), t->hostname, m->fn);
    }
  }
}

uint8_t *get_hoststate(mhost *t, mfile *m)
{
  int i;
  int r;
  if(!t || !m){
    return(NULL);
  }
  r = -1;
  for(i=0;i<MAKUO_PARALLEL_MAX;i++){
    if(t->mflist[i] == m){
      return(&(t->state[i]));
    }else{
      if((r == -1) && !(t->mflist[i])){
        r = i;
      }
    }
  }
  if(r != -1){
    t->mflist[r] = m;
    return(&(t->state[r]));
  }
  return(NULL);
}

uint8_t *set_hoststate(mhost *t, mfile *m, uint8_t state)
{
  uint8_t *s;
  if(s = get_hoststate(t,m)){
    *s = state;
  }
  return(s);
}

int ack_clear(mfile *m, int state)
{
  uint8_t *s;
  mhost   *t;
  for(t=members;t;t=t->next){
    if(!m->sendto){
      if(s = get_hoststate(t, m)){
        if(state == -1 || *s == state){
          *s = MAKUO_RECVSTATE_NONE;
        }
      }
    }else{
      if(!memcmp(&(m->addr.sin_addr), &(t->ad), sizeof(m->addr.sin_addr))){
        if(s = get_hoststate(t, m)){
          if(state == -1 || *s == state){
            *s = MAKUO_RECVSTATE_NONE;
            return(1);
          }else{
            return(0);
          }
        }
      }
    }
  }
  if(m->sendto)
    return(-1);
  return(0);
}

/* 指定したステータスを持つ応答メッセージがあるかをチェックする
 * 引数  :
 *      m: 送信対象のファイルオブジェクト
 *  state: 検索するステータス
 *
 * 戻り値:
 *      0: 見つからなかった
 *      1: 見つかった
 *     -1: ホスト指定転送なのにホストオブジェクトが見つからない
*/
int ack_check(mfile *m, int state)
{
  uint8_t *s;
  mhost   *t;
  for(t=members;t;t=t->next){
    if(!m->sendto){
      s = get_hoststate(t,m);
      if(!s){
        lprintf(0,"%s: can't get state area host=%s fn=%s\n", 
          __func__,
          t->hostname, 
          m->fn);
      }else{
        if(*s == state){
          return(1);
        }
      }
    }else{
      if(!memcmp(&(m->addr.sin_addr), &(t->ad), sizeof(m->addr.sin_addr))){
        s = get_hoststate(t,m);
        if(!s){
          lprintf(0,"%s: can't get state area host=%s fn=%s\n", 
            __func__,
            t->hostname, 
            m->fn);
        }else{
          if(*s == state){
            return(1);
          }else{
            return(0);
          }
        }
      }
    }
  }
  if(m->sendto)
    return(-1);
  return(0);
}

int linkcmp(mfile *m)
{
  ssize_t size;
  char ln[PATH_MAX];
  if(m){
    size = readlink(m->fn, ln, PATH_MAX);
    if(size != -1 && size < PATH_MAX){
      ln[size] = 0;
      if(!strcmp(m->ln, ln)){
        return(MAKUO_RECVSTATE_SKIP);
      }
    }
  }
  return(MAKUO_RECVSTATE_UPDATE);
}

int statcmp(struct stat *s1, struct stat *s2)
{
  if(s1->st_mtime != s2->st_mtime)
    return(MAKUO_RECVSTATE_UPDATE);
  if(!geteuid() || !getegid()){
    if(s1->st_uid != s2->st_uid){
      return(MAKUO_RECVSTATE_UPDATE);
    }
    if(s1->st_gid != s2->st_gid){
      return(MAKUO_RECVSTATE_UPDATE);
    }
  }
  if((S_ISDIR(s1->st_mode)) && (S_ISDIR(s2->st_mode))){
    if(s1->st_mode != s2->st_mode)
      return(MAKUO_RECVSTATE_UPDATE);
    return(MAKUO_RECVSTATE_SKIP);
  }
  if((S_ISREG(s1->st_mode)) && (S_ISREG(s2->st_mode))){
    if(s1->st_mode != s2->st_mode)
      return(MAKUO_RECVSTATE_UPDATE);
    if(s1->st_size != s2->st_size)
      return(MAKUO_RECVSTATE_UPDATE);
    return(MAKUO_RECVSTATE_SKIP);
  }
  if(s1->st_mode == s2->st_mode){
    if(s1->st_rdev == s2->st_rdev){
      return(MAKUO_RECVSTATE_SKIP);
    }
  }
  return(MAKUO_RECVSTATE_UPDATE);
} 

int is_dir(char *path)
{
  struct stat mstat;
  if(!lstat(path,&mstat))
    return(S_ISDIR(mstat.st_mode));
  return(0);
}

int is_reg(char *path)
{
  struct stat mstat;
  if(!lstat(path,&mstat))
    return(S_ISREG(mstat.st_mode));
  return(0);
}

int set_guid(uid_t uid, gid_t gid, gid_t *gids)
{
  size_t num;

  /*----- setgids -----*/
  if(gids){
    for(num=0;gids[num];num++);
    if(num){
      if(setgroups(num, gids) == -1){
        return(-1);
      }
    }
  }else{
    if(gid != getegid()){
      if(setgroups(1, &gid) == -1){
        return(-1);
      }
    }
  }

  /*----- setgid -----*/
  if(gid != getegid()){
    if(setegid(gid) == -1){
      return(-1);
    }
  }
  /*----- setuid -----*/
  if(uid != geteuid()){
    if(seteuid(uid) == -1){
      return(-1);
    }
  }  
  return(0);
}

int set_gids(char *groups)
{
  char *p;
  size_t num;
  struct group *g;
  char buff[1024];

  num = 0;
  strcpy(buff, groups);
  p = strtok(buff,",");
  while(p){
    p = strtok(NULL,",");
    num++;
  }
  if(moption.gids){
    free(moption.gids);
  }
  moption.gids = malloc(sizeof(gid_t) * (num + 1));
 
  num = 0; 
  strcpy(buff, groups);
  p = strtok(buff,",");
  while(p){
    if(*p >= '0' && *p <= '9'){
      moption.gids[num] = atoi(p);
      if(g = getgrgid(moption.gids[num])){
        strcpy(moption.grnames[num], g->gr_name);
      }
    }else{
      if(g = getgrnam(p)){
        moption.gids[num] = g->gr_gid;
        strcpy(moption.grnames[num], p);
      }
    }
    p = strtok(NULL,",");
    num++;
  }
  moption.gids[num] = 0;
  return(0);
}

void set_filestat(char *path, uid_t uid, gid_t gid, mode_t mode)
{
  struct stat fs;
  if(lstat(path, &fs) == -1){
    return;
  }
  if(fs.st_uid != uid){
    lchown(path, uid, -1);
  }
  if(fs.st_gid != gid){
    lchown(path, -1, gid);
  }
  chmod(path, mode & 07777);
}

void mtempname(char *base, char *fn, char *tn)
{
  struct stat    st;
  struct timeval tv;
  char path[PATH_MAX];
  do{
    gettimeofday(&tv, NULL);
    sprintf(tn, "%s.makuo%03u%03u", fn, getrid() % 1000,  (int)tv.tv_usec);
    sprintf(path, "%s/%s", base, tn);
  }while(lstat(tn, &st) != -1);
}

int mremove(char *base, char *name)
{
  DIR *d;
  struct dirent *dent;
  char path[PATH_MAX];
  if(!base){
    strcpy(path,name);
  }else{
    sprintf(path, "%s/%s", base, name);
  }
  if(is_dir(path)){
    if(d = opendir(path)){
      while(dent=readdir(d)){
        if(!strcmp(dent->d_name, "."))
          continue;
        if(!strcmp(dent->d_name, ".."))
          continue;
        mremove(path, dent->d_name);
      }
      closedir(d);
    }
  }
  return(remove(path));
}

int mrename(char *base, char *oldname, char *newname)
{
  char oldpath[PATH_MAX];
  char newpath[PATH_MAX];
  char tmppath[PATH_MAX];
  sprintf(oldpath,"%s/%s", base, oldname);
  sprintf(newpath,"%s/%s", base, newname);
  mtempname(base, newname, tmppath);
  rename(newpath,tmppath);
  if(rename(oldpath,newpath) == -1){
    rename(tmppath, newpath);
    return(-1);
  }
  mremove(NULL,tmppath);
  return(0);
}

int mcreatedir(char *base, char *name, mode_t mode)
{
  char *p;
  char buff[PATH_MAX];
  char path[PATH_MAX];
  strcpy(buff, name);
  strcpy(path, base);
  p = strtok(buff, "/");
  while(p){
    strcat(path, "/");
    strcat(path, p);
    if(p = strtok(NULL,"/")){
      if(!is_dir(path)){
        remove(path);
        if(mkdir(path,mode) == -1){
          return(-1);
        }
      }
    }
  }
  return(0);
}

int mcreatenode(char *base, char *name, mode_t mode, dev_t dev)
{
  int r = -1;
  mode_t u = umask(0);
  char path[PATH_MAX];
  if(!mcreatedir(base, name, 0755)){
    sprintf(path,"%s/%s",base,name);
    r = mknod(path, mode, dev);
  }
  umask(u);
  return(r);
}

int mcreatefile(char *base, char *name, mode_t mode)
{
  int fd = -1;
  mode_t u = umask(0);
  char path[PATH_MAX];
  if(!mcreatedir(base,name,0755)){
    sprintf(path,"%s/%s",base,name);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, mode & 0xFFF);
  }
  umask(u);
  return(fd);
}

int mcreatelink(char *base, char *name, char *link)
{
  char path[PATH_MAX];
  if(!mcreatedir(base,name,0755)){
    sprintf(path,"%s/%s",base,name);
    return(symlink(link,path));
  }
  return(-1);
}

int space_escape(char *str)
{
  int  r = 0;
  char buff[PATH_MAX];
  char *s = str;
  char *d = buff;
  
  while(*s){
    if(*s == ' '){
      r++;
      *(d++) = '\\';
    }
    *(d++) = *(s++);
  }
  *d = 0;
  strcpy(str, buff);
  return(r);
}

mfile *mkreq(mdata *data, struct sockaddr_in *addr, uint8_t state)
{
  mfile *a;
  if(a = mfins(0)){
    a->mdata.head.opcode = data->head.opcode;
    a->mdata.head.reqid  = data->head.reqid;
    a->mdata.head.seqno  = data->head.seqno;
    a->mdata.head.nstate = state;
    memcpy(&(a->addr), addr, sizeof(a->addr));
  }
  return(a);
}

mfile *mkack(mdata *data, struct sockaddr_in *addr, uint8_t state)
{
  mfile *a;
  for(a=mftop[0];a;a=a->next){
    if((a->mdata.head.flags & MAKUO_FLAG_ACK)      &&
       (a->mdata.head.opcode == data->head.opcode) &&
       (a->mdata.head.reqid  == data->head.reqid)  &&
       (a->mdata.head.seqno  == data->head.seqno)  &&
       (a->mdata.head.nstate == state)             &&
       (!memcmp(&(a->addr), addr, sizeof(a->addr)))){
      return(a);
    }
  }
  if(a = mfins(0)){
    a->mdata.head.flags |= MAKUO_FLAG_ACK;
    a->mdata.head.opcode = data->head.opcode;
    a->mdata.head.reqid  = data->head.reqid;
    a->mdata.head.seqno  = data->head.seqno;
    a->mdata.head.ostate = data->head.ostate;
    a->mdata.head.nstate = state;
    a->mdata.head.error  = data->head.error;
    memcpy(&(a->addr), addr, sizeof(a->addr));
  }
  return(a);
}

int atomic_read(int fd, char *buff, int size)
{
  int r;

  while(size){
    r = read(fd, buff, size);
    if(r == -1){
      if(errno == EINTR){
        continue;
      }
      return(-1);
    }
    if(r == 0){
      return(1);
    }
    size -= r;
    buff += r;
  }
  return(0);
}

int data_safeget(mdata *data, void *buff, size_t size)
{
  if(data->p + size > data->data + data->head.szdata){
    return(-1);
  }
  memcpy(buff, data->p, size);
  data->p += size;
  return(0);
}

int data_safeget16(mdata *data, uint16_t *buff)
{
  int r = data_safeget(data, buff, sizeof(uint16_t));
  if(!r){
    *buff = ntohs(*buff);
  }
  return(r);
}

int data_safeget32(mdata *data, uint32_t *buff)
{
  int r = data_safeget(data, buff, sizeof(uint32_t));
  if(!r){
    *buff = ntohl(*buff);
  }
  return(r);
}

int data_safeset(mdata *data, void *buff, size_t size)
{
  if(data->head.szdata + size > MAKUO_BUFFER_SIZE){
    return(-1);
  }
  memcpy(data->data + data->head.szdata, buff, size);
  data->head.szdata += size;
  return(0);
}

int data_safeset16(mdata *data, uint16_t val)
{
  if(data->head.szdata + sizeof(uint16_t) > MAKUO_BUFFER_SIZE){
    return(-1);
  }
  *(uint16_t *)(data->data + data->head.szdata) = htons(val);
  data->head.szdata += sizeof(uint16_t);
  return(0);
}

int data_safeset32(mdata *data, uint32_t val)
{
  if(data->head.szdata + sizeof(uint32_t) > MAKUO_BUFFER_SIZE){
    return(-1);
  }
  *(uint32_t *)(data->data + data->head.szdata) = htonl(val);
  data->head.szdata += sizeof(uint32_t);
  return(0);
}

excludeitem *exclude_add(excludeitem *exclude, char *pattern)
{
  excludeitem *e = malloc(sizeof(excludeitem));
  e->prev = NULL;
  e->next = NULL;
  if(exclude){
    e->next = exclude;
    e->prev = exclude->prev;
    exclude->prev = e;
    if(e->prev){
      e->prev->next = e;
    }
  }
  e->pattern = malloc(strlen(pattern)+1);
  strcpy(e->pattern, pattern);
  return(e);
}

excludeitem *exclude_del(excludeitem *e)
{
  excludeitem *r = NULL;
  excludeitem *p = NULL;
  excludeitem *n = NULL;

  if(!e){
    return(NULL);
  }
  p = e->prev;
  n = e->next;
  if(p){
    p->next=n;
  }
  if(n){
    n->prev=p;
    r = n;
  }
  free(e->pattern);
  e->pattern = NULL;
  e->prev = NULL;
  e->next = NULL;
  free(e);
  return(r);
}


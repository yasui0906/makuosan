/*
 *  common.c
 */
#include "makuosan.h"

mopt moption;
mfile *mftop[2] = {NULL,NULL};
mhost *members  = NULL;
int loop_flag   = 1;
char TZ[256];
struct timeval curtime;
BF_KEY EncKey;

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
  tv.tv_sec  = msec / 1000;
  tv.tv_usec = (msec % 1000) * 1000;
  timeradd(tf, &tv, &tr);
  return(timercmp(&tr, &curtime, <));
}

/*
 *  現在時刻を取得する
 *  といってもcurtimeをコピーするだけ
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

int atomic_write(int fd, void *buff, size_t size)
{
  int s = 0;
  int r = 0;
  int w = 0;
  struct pollfd pf;

  while(size){
    pf.fd      = fd;
    pf.events  = POLLOUT;
    pf.revents = 0;
    s = poll(&pf,1,1000);
    if(s == -1){
      if(errno == EINTR){
        continue;
      }else{
        break;
      }
    }
    if(s){
      w = write(fd,buff,size);
      if(w <= 0){
        return(-1);
      }else{
        size -= w;
        buff += w;
        r    += w;
      }
    }
  }
  return(r);
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
  char msg[512];
  if(moption.loglevel >= l){
    va_start(arg, fmt);
    vsprintf(msg, fmt, arg);
    va_end(arg);
    if(moption.dontfork){
      fprintf(stderr, msg);
    }
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

int getrid()
{
  static int rid=0;
  return(rid++);
}

int workend(mcomm *c)
{
  if(c){
    if(c->working && !c->cpid){
      c->working = 0;
      if(moption.commpass && !c->authchk){
        cprintf(0, c, "Password: \x1b]E");
      }else{
        cprintf(0,c,"> ");
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
    m->mdata.head.vproto = PROTOCOL_VERSION;
    m->fd = -1;
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
      l->next = (void *)m;
      m->prev = (void *)l;
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

mhost *member_add(struct in_addr *addr, mdata *data)
{
  int    f = 1;
  int    l = 0;
  mhost *t = NULL;
  mping *p = NULL;
  for(t=members;t;t=t->next)
    if(!(f=memcmp(&t->ad, addr, sizeof(t->ad))))
      break;
  if(!t){
    t = malloc(sizeof(mhost));
    if(!t){
      lprintf(0,"member_add: out of memory\n");
      return(NULL);
    }
    memcpy(&t->ad, addr, sizeof(t->ad));
    t->state = 0;
    t->prev  = NULL;
    t->next  = NULL;
    if(members){
      members->prev = t;
      t->next = members;
    }
    members = t;
    t->hostname[0] = 0;
  }
  if(data){
    if(data->head.opcode == MAKUO_OP_PING || data->head.opcode == MAKUO_OP_PONG){
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
    lprintf(0,"member_add: %s (%s)\n", inet_ntoa(t->ad), t->hostname);
  }
  mtimeget(&(t->lastrecv));
  return(t);
}

void member_del(mhost *t)
{
  mfile *m;
  mhost *p;
  mhost *n;
  if(!t)
    return;
  lprintf(0,"member_del: %s (%s)\n", inet_ntoa(t->ad), t->hostname);
  if(p = (mhost *)t->prev)
    p->next = t->next;
  if(n = (mhost *)t->next)
    n->prev = t->prev;
  if(members == t)
    members = n;
  do{
    for(m=mftop[1];m;m=m->next){
      if(!memcmp(&(m->addr.sin_addr), &(t->ad), sizeof(m->addr.sin_addr))){
        if(m->mdata.head.nstate == MAKUO_RECVSTATE_OPEN){
          if(m->fd != -1){
            close(m->fd);
          }
          m->fd = -1;
          if(S_ISREG(m->fs.st_mode)){
            mremove(moption.base_dir,m->tn);
          }
        }
        lprintf(0,"member_del: mfile break %s\n", m->fn);
        mfdel(m);
        break;
      }
    }
  }while(m);
  free(t);
}

int seq_addmark(mfile *m, uint32_t lseq, uint32_t useq)
{
  int i,j;
  int size;
  void *n;

  if(!m->mark){
    m->markcount = 0;
    m->marksize  = 512;
    m->mark = malloc(sizeof(uint32_t) * m->marksize);
  }
  size = m->marksize;
  while(size < m->markcount + useq - lseq)
    size += 512;
  if(size != m->marksize){
    n = malloc(sizeof(uint32_t) * size);
    memcpy(n, m->mark, sizeof(uint32_t) * m->marksize);
    free(m->mark);
    m->mark = n;
    m->marksize = size;
  }
  for(i=lseq;i<useq;i++){
    for(j=0;j<m->markcount;j++)
      if(i == m->mark[j])
        break;
    if(j == m->markcount){
      m->mark[m->markcount++] = i;
    }
  }
  return(0);
}

int seq_delmark(mfile *m, uint32_t seq)
{
  int i;
  int r = 0;
  for(i=0;i<m->markcount;i++){
    if(m->mark[i] == seq){
      r = 1;
      m->markcount--;
      m->mark[i] = m->mark[m->markcount];
    }
  }
  return(r);
}

int seq_popmark(mfile *m, int n)
{
  char *s;
  char *d;
  int size = m->markcount - n;
  if(size > 0){
    s = (char *)(m->mark + n);
    d = (char *)(m->mark + 0);
   memmove(d, s, size * sizeof(uint32_t));
    m->markcount = size;
  }else{
    m->markcount = 0;
  }
}

int ack_clear(mfile *m, int state)
{
  mhost *h;
  for(h=members;h;h=h->next){
    if(!m->sendto){
      if(state == -1 || h->state == state)
        h->state = MAKUO_RECVSTATE_NONE;
    }else{
      if(!memcmp(&(m->addr.sin_addr), &(h->ad), sizeof(m->addr.sin_addr))){
        if(state == -1 || h->state == state){
          h->state = MAKUO_RECVSTATE_NONE;
          return(1);
        }else{
          return(0);
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
 *
*/
int ack_check(mfile *m, int state)
{
  mhost *h;
  for(h=members;h;h=h->next){
    if(!m->sendto){
      if(h->state == state){
        return(1);
      }
    }else{
      if(!memcmp(&(m->addr.sin_addr), &(h->ad), sizeof(m->addr.sin_addr))){
        if(h->state == state){
          return(1);
        }else{
          return(0);
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
  mode_t s1mode;
  mode_t s2mode;

  if((S_ISDIR(s1->st_mode)) && (S_ISDIR(s2->st_mode))){
    s1mode = s1->st_mode & 0xFFF;
    s2mode = s2->st_mode & 0xFFF;
    if(s1mode != s2mode)
      return(MAKUO_RECVSTATE_UPDATE);
    if(s1->st_mtime != s2->st_mtime)
      return(MAKUO_RECVSTATE_UPDATE);
    return(MAKUO_RECVSTATE_SKIP);
  }
  if((S_ISREG(s1->st_mode)) && (S_ISREG(s2->st_mode))){
    if(s1->st_size != s2->st_size)
      return(MAKUO_RECVSTATE_UPDATE);
    if(s1->st_mtime != s2->st_mtime)
      return(MAKUO_RECVSTATE_UPDATE);
    return(MAKUO_RECVSTATE_SKIP);
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

void mtempname(char *base, char *fn, char *tn)
{
  struct stat  st;
  struct timeb tb;
  char path[PATH_MAX];
  do{
    ftime(&tb);
    sprintf(tn, "%s.makuo%03u%03u", fn, getrid() % 1000,  (int)tb.millitm);
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
    sprintf(path,"%s/%s", base, name);
    lprintf(0,"mremove: %s\n",  path);
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

int mcreate(char *base, char *name, mode_t mode)
{
  int fd = -1;
  char path[PATH_MAX];
  if(!mcreatedir(base,name,0755)){
    sprintf(path,"%s/%s",base,name);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, mode & 0xFFF);
  }
  return(fd);
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


/*
 * mexec.c
 * Copyright (C) 2008 KLab Inc.
 */

#include "makuosan.h"

char *command_list[]={"quit",     /*  */
                      "exit",     /*  */
                      "bye",      /*  */
                      "send",     /*  */
                      "sync",     /*  */
                      "dsync",    /*  */
                      "members",  /*  */
                      "status",   /*  */
                      "md5",      /*  */
                      "check",    /*  */
                      "echo",     /*  */
                      "exclude",  /*  */
                      "loglevel", /*  */
                      "help",     /*  */
                      NULL};      /*  */

int mexec_scan_cmd(int fd, char *buff)
{
  int r;
  int size;
  char *cmd;
  fd_set fds;
  struct timeval tv;

  cmd = buff;
  size = strlen(buff);
  while(loop_flag && size){
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(fd,&fds);
    if(select(1024, NULL, &fds, NULL, &tv)<0)
      continue;
    if(FD_ISSET(fd,&fds)){
      r = write(fd, cmd, size);
      if(r == -1){
        lprintf(0, "%s: commend write error! %s", 
          __func__, 
          buff);
        return(-1);
      }
      size -= r;
      cmd  += r;
    }
  }
  return(0);
}

int mexec_scan_echo(int fd, char *fmt, ...)
{
  char buff[MAKUO_BUFFER_SIZE];
  char comm[MAKUO_BUFFER_SIZE];
  va_list arg;
  va_start(arg, fmt);
  vsprintf(buff, fmt, arg);
  va_end(arg);
  sprintf(comm, "echo %s\n", buff);
  mexec_scan_cmd(fd, comm);
  return(0);
}

int mexec_scan_send(int fd, char *path, char *sendhost, int mode)
{
  char buff[MAKUO_BUFFER_SIZE];
  char comm[MAKUO_BUFFER_SIZE];

  buff[0] = 0;
  if(sendhost && *sendhost){
    strcat(buff, " -t ");
    strcat(buff, sendhost);
    strcat(buff, " ");
  }
  switch(mode){
    case MAKUO_MEXEC_SEND:
      sprintf(comm, "send %s%s\r\n",    buff, path);
      break;
    case MAKUO_MEXEC_DRY:
      sprintf(comm, "send -n %s%s\r\n", buff, path);
      break;
    case MAKUO_MEXEC_MD5:
      if(!is_reg(path)){
        return(0);
      }
      sprintf(comm, "check %s%s\r\n",     buff, path);
      break;
  }
  mexec_scan_cmd(fd, comm);
  return(0);
}

int mexec_scan_dir(int fd, char *base, char *sendhost, int mode, mcomm *c, int baseflag)
{
  DIR *d;
  struct dirent *dent;
  char path[PATH_MAX];

  d = opendir(base);
  if(!d){
    /* directory open error */
    mexec_scan_echo(fd, "directory open error %s", base);
  }else{
    while(dent=readdir(d)){
      if(!loop_flag)
        break;
      if(!strcmp(dent->d_name, "."))
        continue;
      if(!strcmp(dent->d_name, ".."))
        continue;
      if(baseflag){
        sprintf(path, "%s/%s", base, dent->d_name);
      }else{
        strcpy(path, dent->d_name);
      }
      space_escape(path);
      mexec_scan_child(fd, path, sendhost, mode, c);
    }
    closedir(d);
  }
  return(0);
}

int mexec_scan_child(int fd, char *base, char *sendhost, int mode, mcomm *c)
{
  char path[PATH_MAX];
  if(*base == 0){
    getcwd(path, PATH_MAX);
    mexec_scan_dir(fd, path, sendhost, mode, c, 0);
  }else{
    /*----- exclude -----*/
    sprintf(path, "%s/%s", moption.real_dir, base);
    if(!mfnmatch(path, c->exclude)){
      if(!is_dir(base)){
        mexec_scan_send(fd, base, sendhost, mode);
      }else{
        /*----- exclude dir -----*/
        strcat(path, "/");
        if(mfnmatch(path, c->exclude))
          return(0);
        mexec_scan_dir(fd, base, sendhost, mode, c, 1);
        if(loop_flag && (mode != MAKUO_MEXEC_MD5)){
          mexec_scan_send(fd, base, sendhost, mode);
        }
      }
    }
  }
  return(0);
}

int mexec_scan(mcomm *c, char *fn, mhost *h, int mode)
{
  int pid;
  int p[2];
  char sendhost[256];
  char base[PATH_MAX];

  if(pipe(p) == -1){
    cprintf(0, c, "error: pipe error\n");    
    lprintf(0, "%s: pipe error\n", __func__);    
    return(-1);
  }

  base[0] = 0;
  sendhost[0] = 0;
  if(h)
    strcpy(sendhost, h->hostname);
  if(fn)
    strcpy(base, fn);

  pid=fork();
  if(pid == -1){
    close(p[0]);
    close(p[1]);
    cprintf(0, c, "error: fork error\n");
    lprintf(0, "%s: fork error\n", __func__);
    return(-1);
  }
  if(pid){
    /* parent */
    close(p[1]);
    c->cpid  = pid;
    c->fd[1] = p[0];
    return(0);
  }else{
    /* child */
    close(p[0]);
    mexec_scan_child(p[1], base, sendhost, mode, c);
    close(p[1]);
    _exit(0);
  }
  return(0);
}

int mexec_close(mcomm *c, int n)
{
  mfile *m;

  lprintf(1 + n * 7, "%s: fd=%d n=%d\n", __func__, c->fd[n], n);
  if(c->fd[n] != -1)
    close(c->fd[n]);
  c->fd[n]  = -1;
  c->size[n] = 0;
  if(!n){
    c->authchk  = 0;
    c->loglevel = 0;
    if(c->cpid){
      kill(c->cpid, SIGTERM);
      mexec_close(c, 1);
    }
    while(c->exclude){
      mexec_exclude_del(c, c->exclude);
    }
    for(m=mftop[0];m;m=m->next){
      if(m->comm == c){
        m->comm = NULL;
        lprintf(3, "%s: cancel %s\n", __func__, m->fn);
      }
    }
  }
  return(0);
}

int mexec_quit(mcomm *c, int n)
{
  mexec_close(c, n);
  return(0);
}

int mexec_help(mcomm *c, int n)
{
  cprintf(0, c, "COMMAND:\n");
  cprintf(0, c, "  quit\n");
  cprintf(0, c, "  exclude add PATTERN\n");
  cprintf(0, c, "  exclude del PATTERN\n");
  cprintf(0, c, "  exclude list\n");
  cprintf(0, c, "  exclude clear\n");
  cprintf(0, c, "  send  [-r] [-t host] [-n] [path]\n");
  cprintf(0, c, "  sync  [-r] [-t host] [-n] [path]\n");
  cprintf(0, c, "  dsync [-r] [-t host] [-n] [path]\n");
  cprintf(0, c, "  check [-r] [-t host] [path]\n");
  cprintf(0, c, "  loglevel num (0-9)\n");
  cprintf(0, c, "  members\n");
  cprintf(0, c, "  help\n");
  return(0);
}

int mexec_send(mcomm *c, int n, int sync)
{
  int i;
  ssize_t size;
  char *argv[9];
  char *fn = NULL;
  mfile *m = NULL;
  mhost *h = NULL;
  int recursive = 0;
  int mode = MAKUO_MEXEC_SEND;

  if(moption.dontsend){
    cprintf(0, c, "error: this server can't send\n");
    return(0);
  }
  for(i=0;i<c->argc[n];i++)
    argv[i] = c->parse[n][i];
  argv[i] = NULL;
  optind = 0;
  while((i=getopt(c->argc[n], argv, "t:nr")) != -1){
    switch(i){
      case 'n':
        mode = MAKUO_MEXEC_DRY;
        break;
      case 'r':
        recursive = 1;
        break;
      case 't':
        for(h=members;h;h=h->next)
          if(!strcmp(h->hostname, optarg))
            break;
        if(!h){
          cprintf(0, c, "%s is not contained in members\r\n", optarg);
          return(0);
        }
        break;
      case '?':
        cprintf(0, c, "invalid option -- %c\r\n", optopt);
        return(0); 
    }
  }

  while(optind < c->argc[n])
    fn = c->parse[n][optind++];

  /*----- directory scan -----*/
  if(recursive){
    if(c->cpid){
      cprintf(0, c, "recursive process active now!\n");
      return(0);
    }
    return(mexec_scan(c, fn, h, mode));
  }
  /*----- help -----*/
  if(!fn){
    if(sync){
      cprintf(0, c, "sync [-n] [-r] [-t host] [path]\r\n");
      cprintf(0, c, "  -n  # dryrun\r\n");
      cprintf(0, c, "  -r  # recursive\r\n");
      cprintf(0, c, "  -t  # target host\r\n");
    }else{
      cprintf(0, c, "send [-n] [-r] [-t host] [path]\r\n");
      cprintf(0, c, "  -n  # dryrun\r\n");
      cprintf(0, c, "  -r  # recursive\r\n");
      cprintf(0, c, "  -t  # target host\r\n");
    }
    return(0);
  }
  /*----- send file -----*/
  m = mfadd(0);
  if(!m){
	  lprintf(0, "%s: out of memorry\n", __func__);
    return(0);
	}

  /*----- send to address set -----*/
  if(h){
    m->sendto = 1;
    memcpy(&(m->addr.sin_addr), &(h->ad), sizeof(m->addr.sin_addr));
  }

	strcpy(m->fn, fn);
	m->mdata.head.reqid  = getrid();
	m->mdata.head.opcode = MAKUO_OP_SEND;
  m->mdata.head.nstate = MAKUO_SENDSTATE_STAT;
	m->comm      = c;
  m->dryrun    = (mode == MAKUO_MEXEC_DRY);
  m->initstate = 1;
  if(m->dryrun){
    m->mdata.head.flags |= MAKUO_FLAG_DRYRUN;
  }

	if(lstat(fn, &m->fs) == -1){
    if(errno == ENOENT){
      if(sync){
        m->mdata.head.flags |= MAKUO_FLAG_SYNC;
        return(0);
      }      
    }
	  cprintf(0, c, "error: file not found %s\n", fn);
		lprintf(1, "%s: lstat() error argc=%d cmd=%s\n",
      __func__, 
      c->argc[n], 
      c->cmdline[n]);
    for(i=0;i<c->argc[n];i++){
		  lprintf(1, "%s: read error argv[%d]=%s\n",
        __func__, 
        i, 
        c->parse[n][i]);
    }
		lprintf(0, "%s: read error file=%s\n", 
      __func__, 
      fn);
		mfdel(m);
    return(0);
	}
  
  m->seqnomax  = m->fs.st_size / MAKUO_BUFFER_SIZE;
  if(m->fs.st_size % MAKUO_BUFFER_SIZE){
    m->seqnomax++; 
  }

  /*----- socket check -----*/
  if(S_ISSOCK(m->fs.st_mode)){
	  cprintf(0, c, "skip: unix domain socket %s\n", fn);
		mfdel(m);
    return(0);
  }

  /*----- owner check -----*/
  if(moption.ownmatch && (moption.uid != m->fs.st_uid)){
	  cprintf(0, c, "skip: owner unmatch %s (%d != %d)\n", fn, moption.uid, m->fs.st_uid);
		lprintf(0, "%s: owner unmatch %s (%d != %d)\n", __func__, fn, moption.uid, m->fs.st_uid);
		mfdel(m);
    return(0);
  }

  /*----- readlink -----*/
  if(S_ISLNK(m->fs.st_mode)){
    size = readlink(m->fn, m->ln, PATH_MAX);
    if(size >= 0 && size < PATH_MAX){
      m->ln[size] = 0;
    }else{
		  cprintf(0, c, "error: readlink error %s\n", fn);
		  lprintf(0, "%s: readlink error %s\n", __func__, fn);
		  mfdel(m);
    }
  }  
  return(0);
}

int mexec_check(mcomm *c, int n)
{
  int i;
  int r;
  ssize_t size;
  char *argv[9];
  char *fn = NULL;
  mfile *m = NULL;
  mhost *t = NULL;
  mhash *h = NULL;
  int recursive = 0;

  for(i=0;i<c->argc[n];i++)
    argv[i] = c->parse[n][i];
  argv[i] = NULL;
  optind = 0;
  while((i=getopt(c->argc[n], argv, "t:r")) != -1){
    switch(i){
      case 'r':
        recursive = 1;
        break;
      case 't':
        for(t=members;t;t=t->next)
          if(!strcmp(t->hostname, optarg))
            break;
        if(!t){
          cprintf(0, c, "%s is not contained in members\r\n", optarg);
          return(0);
        }
        break;
      case '?':
        cprintf(0, c, "invalid option -- %c\r\n", optopt);
        return(0); 
    }
  }

  while(optind < c->argc[n])
    fn = c->parse[n][optind++];

  /*----- directory scan -----*/
  if(recursive){
    if(c->cpid){
      cprintf(0, c, "recursive process active now!\n");
      return(0);
    }
    return(mexec_scan(c, fn, t, MAKUO_MEXEC_MD5));
  }

  /*----- help -----*/
  if(!fn){
    cprintf(0, c,"usage: check [-t host] [-r] [path]\r\n");
    cprintf(0, c, "  -r  # dir recursive\r\n");
    cprintf(0, c, "  -t  # target host\r\n");
    return(0);
  }

  /*----- create mfile -----*/
  m = mfadd(0);
  if(!m){
	  lprintf(0, "%s: out of memorry\n", __func__);
	  cprintf(0, c, "error: out of memorry\n");
    return(0);
	}
	m->mdata.head.reqid  = getrid();
	m->mdata.head.seqno  = 0;
	m->mdata.head.opcode = MAKUO_OP_MD5;
  m->mdata.head.nstate = MAKUO_SENDSTATE_OPEN;
  m->initstate = 1;
	m->comm      = c;
  m->sendto    = 0;
  m->dryrun    = 0;
  m->ln[0]     = 0;
	strcpy(m->fn, fn);

  /*----- open -----*/
  m->fd = open(m->fn, O_RDONLY);
  if(m->fd == -1){
	  lprintf(0, "%s: file open error %s\n", __func__, m->fn);
    cprintf(0, c, "file open error: %s\r\n", m->fn);
    mfdel(m);
    return(0);
  }

  /*----- md5 -----*/
  h = (mhash *)m->mdata.data;
  h->fnlen = strlen(m->fn);
  r = md5sum(m->fd, h->hash);
  close(m->fd);
  m->fd = -1;
  if(r == -1){
	  lprintf(0, "%s: file read error %s\n", __func__, m->fn);
    cprintf(0, c, "error: file read error %s\n", m->fn);
    mfdel(m);
    return(0);
  }
  memcpy(h->filename, m->fn, h->fnlen);
  m->mdata.head.szdata = sizeof(mhash) + h->fnlen;
  h->fnlen = htons(h->fnlen);

  /*----- sendto address -----*/
  if(t){
    m->sendto = 1;
    memcpy(&(m->addr.sin_addr), &(t->ad), sizeof(m->addr.sin_addr));
  }
  return(0);
}

int mexec_dsync(mcomm *c, int n)
{
  int i;
  ssize_t size;
  char *argv[9];
  char *fn = NULL;
  mfile *m = NULL;
  mhost *t = NULL;
  int  recurs = 0;
  int  dryrun = 0;

  if(moption.dontsend){
    cprintf(0, c, "error: this server can't send\n");
    return(0);
  }
  for(i=0;i<c->argc[n];i++)
    argv[i] = c->parse[n][i];
  argv[i] = NULL;
  optind = 0;
  while((i=getopt(c->argc[n], argv, "t:nr")) != -1){
    switch(i){
      case 'n':
        dryrun = 1;
        break;
      case 'r':
        recurs = 1;
        break;
      case 't':
        for(t=members;t;t=t->next)
          if(!strcmp(t->hostname, optarg))
            break;
        if(!t){
          cprintf(0, c, "%s is not contained in members\r\n", optarg);
          return(0);
        }
        break;
      case '?':
        cprintf(0, c, "invalid option -- %c\r\n", optopt);
        return(0); 
    }
  }

  while(optind < c->argc[n]){
    fn = c->parse[n][optind++];
  }

  /*----- help -----*/
  if(c->argc[n]<2){
    cprintf(0, c, "dsync [-r] [-t host] [-n] [path]\r\n");
    cprintf(0, c, "  -r  # recursive\r\n");
    cprintf(0, c, "  -t  # target host\r\n");
    cprintf(0, c, "  -n  # dryrun\r\n");
    return(0);
  }

  /*----- start dsync -----*/
  m = mfadd(0);
  if(!m){
	  lprintf(0, "%s: out of memorry\n", __func__);
    return(0);
	}

  strcpy(m->fn, ".");
  if(fn){
    if(*fn != '/'){
	    strcat(m->fn, "/");
    }
	  strcat(m->fn, fn);
  }
  
  strcpy(m->mdata.data, m->fn);
	m->mdata.head.reqid  = getrid();
	m->mdata.head.szdata = strlen(m->fn);
	m->mdata.head.opcode = MAKUO_OP_DSYNC;
  m->mdata.head.nstate = MAKUO_SENDSTATE_OPEN;
	m->comm = c;
  if(dryrun){
    m->dryrun = 1;
    m->mdata.head.flags |= MAKUO_FLAG_DRYRUN;
  }
  if(recurs){
    m->recurs = 1;
    m->mdata.head.flags |= MAKUO_FLAG_RECURS;
  }
  m->initstate = 1;

  /*----- send to address set -----*/
  if(t){
    m->sendto = 1;
    memcpy(&(m->addr.sin_addr), &(t->ad), sizeof(m->addr.sin_addr));
  }
  return(0);
}

int mexec_members(mcomm *c, int n)
{
  int count=0;
  mhost *h;
	for(h=members;h;h=h->next){
    cprintf(0, c, "%s: %s %s\n", h->version, h->hostname, inet_ntoa(h->ad));
    count++;
  }
  cprintf(0, c, "Total: %d members\n", count);
  return(0);
}

int mexec_echo(mcomm *c, int n)
{
  int i;
  cprintf(0, c, "%s", c->parse[n][1]);
  for(i=2;i<8;i++){
    if(c->parse[n][i][0]){
      cprintf(0, c, " %s", c->parse[n][i]);
    }
  }
  cprintf(0, c, "\n");
  return(0);
}

int mexec_loglevel(mcomm *c, int n)
{
  c->loglevel=atoi(c->parse[n][1]);
  return(0);
}

int mexec_exclude_add(mcomm *c, char *pattern)
{
  excludeitem *e = malloc(sizeof(excludeitem));
  
  e->prev = NULL;
  e->next = NULL;
  if(c->exclude){
    e->next = c->exclude;
    c->exclude->prev = e;
  }
  c->exclude = e;
  e->pattern = malloc(strlen(pattern)+1);
  strcpy(e->pattern, pattern);
  return(0);
}

int mexec_exclude_del(mcomm *c, excludeitem *e)
{
  excludeitem *p;
  excludeitem *n;

  if(!e)
    return(0);
  p = e->prev;
  n = e->next;
  if(p)
    p->next=n;
  if(n)
    n->prev=p;
  if(e == c->exclude)
    c->exclude = n; 
  free(e->pattern);
  e->pattern = NULL;
  e->prev = NULL;
  e->next = NULL;
  free(e);
  return(0);
}

int mexec_exclude(mcomm *c, int n)
{
  excludeitem *e;
  switch(c->argc[n]){
    case 2:
      if(!strcmp("list", c->parse[n][1])){
        for(e=c->exclude;e;e=e->next){
          cprintf(0,c,"%s\n", e->pattern);
        }
        return(0);
      }
      if(!strcmp("clear", c->parse[n][1])){
        while(c->exclude){
          mexec_exclude_del(c, c->exclude);
        }
        return(0);
      }
      break;

    case 3:
      if(!strcmp("add", c->parse[n][1])){
        for(e=c->exclude;e;e=e->next){
          if(!strcmp(e->pattern, c->parse[n][2])){
            break;
          }
        }
        if(!e){
          mexec_exclude_add(c, c->parse[n][2]);
          return(0);
        }
      }
      if(!strcmp("del", c->parse[n][1])){
        for(e=c->exclude;e;e=e->next){
          if(!strcmp(e->pattern, c->parse[n][2])){
            mexec_exclude_del(c, e);
            return(0);
          }
        }
        cprintf(0,c,"pattern not found %s\n", c->parse[n][2]);
      }
      break;
  }
  cprintf(0,c,"usage: exclude add PATTERN\n");
  cprintf(0,c,"       exclude del PATTERN\n");
  cprintf(0,c,"       exclude list\n");
  cprintf(0,c,"       exclude clear\n");
  return(0);
}

int mexec_status(mcomm *c, int n)
{
  int count;
  mfile  *m;
  struct tm *t;

  cprintf(0,c,"version: %s\n", PACKAGE_VERSION);
  if(moption.chroot){
    cprintf(0, c, "chroot : %s/\n", moption.real_dir);
  }else{
    cprintf(0, c, "basedir: %s/\n", moption.base_dir);
  }
  count = 0;
  for(m=mftop[0];m;m=m->next){
    count++;
  }
  cprintf(0,c,"send op: %d\n", count);
  for(m=mftop[0];m;m=m->next){
    uint32_t snow = m->seqnonow;
    uint32_t smax = m->seqnomax;
    if(snow > smax){
      snow = smax;
    }
    if(m->mdata.head.flags & MAKUO_FLAG_ACK){
      cprintf(0, c, "  (ack) %s %s %s (%u:%u/%u)\n", 
        OPCODE(m->mdata.head.opcode), 
        RSTATE(m->mdata.head.nstate), 
        m->fn, 
        m->markcount, snow, smax); 
    }else{
      cprintf(0, c, "  (req) %s %s %s (%u:%u/%u)\n", 
        OPCODE(m->mdata.head.opcode), 
        SSTATE(m->mdata.head.nstate), 
        m->fn, 
        m->markcount, snow, smax); 
    }
  }

  count = 0;
  for(m=mftop[1];m;m=m->next)
    count++;
  cprintf(0, c, "recv op: %d\n", count);
  for(m=mftop[1];m;m=m->next){
    t = localtime(&(m->lastrecv.tv_sec));
    cprintf(0, c, "  %s %s %02d:%02d:%02d %s (%d/%d) mark=%d\n",
      OPCODE(m->mdata.head.opcode), 
      RSTATE(m->mdata.head.nstate), 
      t->tm_hour, t->tm_min, t->tm_sec, 
      m->fn, 
      m->recvcount, m->seqnomax, 
      m->markcount); 
  }
  return(0);
}

int mexec_password(char *password)
{
  unsigned char digest[16];
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, password, strlen(password));
  MD5_Final(digest, &ctx);
  if(!memcmp(moption.password[0], digest, 16)){ 
    return(1);
  }
  return(0);
}

int mexec_parse(mcomm *c, int n)
{
  int i;
  int j;
  int l;
  char *p;
  char cmd[MAKUO_BUFFER_SIZE];

  c->argc[n] = 0;
  p = c->cmdline[n];
  for(i=0;i<8;i++)
    c->parse[n][i][0]=0;
  for(i=0;i<c->size[n];i++){
    *p = c->readbuff[n][i];
    if(c->readbuff[n][i] == '\r')
      *p = 0;
    if(c->readbuff[n][i] == '\n'){
      *p = 0;
      break;
    }
    p++;
  }
  c->check[n] = 0;
  if(i == c->size[n])
    return(-1);
  i++;
  memmove(c->readbuff[n], c->readbuff[n] + i, MAKUO_BUFFER_SIZE - i);
  if(c->size[n] -= i)
    c->check[n] = 1;
  if(moption.commpass && !c->authchk){
    c->authchk = mexec_password(c->cmdline[n]);
    c->cmdline[n][0]=0;
    cprintf(0, c,"\r");
    if(!c->authchk){
      cprintf(0, c, "sorry.\n");
      mexec_close(c, n);
      return(-1);
    }
  }else{
    strcpy(cmd, c->cmdline[n]);
    p=strtok(cmd, " ");
    for(j=0;j<8;j++){
      if(!p)
        break;
      strcpy(c->parse[n][j], p);
      if(j){
        if(l = strlen(c->parse[n][j-1])){
          if(c->parse[n][j-1][l-1] == '\\'){
            c->parse[n][j-1][l-1] = 0;
            strcat(c->parse[n][j-1], " ");
            strcat(c->parse[n][j-1], p);
            c->parse[n][j][0] = 0;
            j--;
          }
        }
      }
      p = strtok(NULL, " ");
    }
    c->argc[n] = j;
  }
  for(i=0;command_list[i];i++)
    if(!strcmp(c->parse[n][0], command_list[i]))
      break;
  return(i);
}

int mexec(mcomm *c, int n)
{
  int r;
  int size   = MAKUO_BUFFER_SIZE - c->size[n];
  char *buff = c->readbuff[n] + c->size[n];
  mfile *m   = NULL;
  int count  = 0;

  if(n == 0 && c->working){
    c->size[n] = 0;
    r = read(c->fd[n], buff, size);
    if(r>0){
    }else{
      if(r == -1){
        lprintf(0, "%s: read error n=%d\n", __func__, n);
      }
      mexec_close(c, n);
    }
    return(-1);
  }

  if(n == 1){
    for(m=mftop[0];m;m=m->next){
      if(m->comm == c){
        if(count++ == MAKUO_PARALLEL_MAX){
          return(-1);
        }
      }
    }
  }

  if(!size){
    lprintf(0, "%s: buffer over fllow n=%d\n", __func__, n);
    mexec_close(c, n);
    return(-1);
  }

  if(!c->check[n]){
    r = read(c->fd[n], buff, size);
    if(r > 0){
      c->size[n] += r;
    }else{
      if(r < 0){
        lprintf(0, "%s: read error n=%d\n", __func__, n);
      }
      mexec_close(c, n);
      return(-1);
    }
  }

  if((r = mexec_parse(c, n)) == -1)
    return(-1); 

  if(!command_list[r]){
    if(c->parse[n][0][0]){
      cprintf(0, c, "mexec: command error '%s'\n", c->parse[n][0]);
    }
    if(moption.commpass && !c->authchk){
      cprintf(0,c,"password: \x1b]E");
    }else{
      cprintf(0, c, "> ");
    }
  }else{
    lprintf(1 + n * 7, "%s: %s\n", __func__, c->cmdline[n]);
    c->working = 1;

    if(!strcmp("help",command_list[r]))
      return(mexec_help(c,n));

    if(!strcmp("quit",command_list[r]))
      return(mexec_quit(c,n));

    if(!strcmp("exit",command_list[r]))
      return(mexec_quit(c,n));

    if(!strcmp("bye",command_list[r]))
      return(mexec_quit(c,n));

    if(!strcmp("send",command_list[r]))
      return(mexec_send(c,n,0));

    if(!strcmp("sync",command_list[r]))
      return(mexec_send(c,n,1));

    if(!strcmp("md5",command_list[r]))
      return(mexec_check(c,n));

    if(!strcmp("check",command_list[r]))
      return(mexec_check(c,n));

    if(!strcmp("dsync",command_list[r]))
      return(mexec_dsync(c,n));

    if(!strcmp("members",command_list[r]))
      return(mexec_members(c,n));

    if(!strcmp("echo",command_list[r]))
      return(mexec_echo(c,n));

    if(!strcmp("loglevel",command_list[r]))
      return(mexec_loglevel(c,n));

    if(!strcmp("exclude",command_list[r]))
      return(mexec_exclude(c,n));

    if(!strcmp("status",command_list[r]))
      return(mexec_status(c,n));

    c->working = 0;
  }
  return(r);
}


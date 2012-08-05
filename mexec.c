/*
 * mexec.c
 * Copyright (C) 2008 KLab Inc.
 */

#include "makuosan.h"

char *command_list[]={"quit",
                      "exit",
                      "bye",
                      "send",
                      "sync",
                      "dsync",
                      "members",
                      "status",
                      "md5",
                      "check",
                      "echo",
                      "exclude",
                      "loglevel",
                      "alive",
                      "help",
                      NULL};

mfile *mexec_with_dsync(mcomm *c, char *fn, int dryrun, int recurs, mhost *t)
{
  mfile *m = mfadd(MFSEND);
  if(!m){
	  lprintf(0, "[error] %s: out of memorry\n", __func__);
	  cprintf(0, c, "error: out of memorry\n");
    return(m);
	}

  strcpy(m->fn, ".");
  if(fn){
    if(*fn != '/'){
	    strcat(m->fn, "/");
    }
	  strcat(m->fn, fn);
  }
  
  strcpy((char *)(m->mdata.data), m->fn);
  strcpy(m->cmdline, c->cmdline[0]);
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
  return(m);
}

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
        if(errno == EINTR){
          continue;
        }
        lprintf(0, "[error] %s: commend write error (%s) %s", __func__, strerror(errno), buff);
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

int mexec_scan_send(int fd, char *path, char *sendhost, int mode, gid_t gid)
{
  char buff[MAKUO_BUFFER_SIZE];
  char comm[MAKUO_BUFFER_SIZE];

  buff[0] = 0;
  if((gid != -1) && (mode == MAKUO_MEXEC_SEND)){
    sprintf(buff, "-g %d ", gid);
  }
  if(sendhost && *sendhost){
    strcat(buff, " -t ");
    strcat(buff, sendhost);
    strcat(buff, " ");
  }
  switch(mode){
    case MAKUO_MEXEC_SEND:
      sprintf(comm, "send %s%s\r\n", buff, path);
      break;
    case MAKUO_MEXEC_DRY:
      sprintf(comm, "send -n %s%s\r\n", buff, path);
      break;
    case MAKUO_MEXEC_MD5:
      if(!is_reg(path)){
        return(0);
      }
      sprintf(comm, "check %s%s\r\n", buff, path);
      break;
  }
  return(mexec_scan_cmd(fd, comm));
}

int mexec_scan_dir(int fd, char *base, char *sendhost, int mode, mcomm *c, int baseflag, gid_t gid)
{
  int r;
  DIR *d;
  struct dirent *dent;
  char path[PATH_MAX];

  d = opendir(base);
  if(!d){
    /* directory open error */
    mexec_scan_echo(fd, "directory open error %s", base);
  }else{
    while(dent=readdir(d)){
      if(!loop_flag){
        return(1);
      }
      if(!strcmp(dent->d_name, ".")){
        continue;
      }
      if(!strcmp(dent->d_name, "..")){
        continue;
      }
      if(baseflag){
        sprintf(path, "%s/%s", base, dent->d_name);
      }else{
        strcpy(path, dent->d_name);
      }
      space_escape(path);
      if(r = mexec_scan_child(fd, path, sendhost, mode, c, gid)){
        return(r);
      }
    }
    closedir(d);
  }
  return(0);
}

int mexec_scan_child(int fd, char *base, char *sendhost, int mode, mcomm *c, gid_t gid)
{
  int r;
  char path[PATH_MAX];
  if(*base == 0){
    getcwd(path, PATH_MAX);
    return(mexec_scan_dir(fd, path, sendhost, mode, c, 0, gid));
  }
  /*----- exclude -----*/
  sprintf(path, "%s/%s", moption.real_dir, base);
  if(!mfnmatch(path, c->exclude)){
    if(!is_dir(base)){
      return(mexec_scan_send(fd, base, sendhost, mode, gid));
    }else{
      /*----- exclude dir -----*/
      strcat(path, "/");
      if(mfnmatch(path, c->exclude)){
        return(0);
      }
      /*----- scan dir -----*/
      if(r = mexec_scan_dir(fd, base, sendhost, mode, c, 1, gid)){
        return(r);
      }
      if(loop_flag && (mode != MAKUO_MEXEC_MD5)){
        return(mexec_scan_send(fd, base, sendhost, mode, gid));
      }
    }
  }
  return(0);
}

int mexec_scan(mcomm *c, char *fn, mhost *h, int mode, gid_t gid)
{
  int pid;
  int p[2];
  char sendhost[256];
  char base[PATH_MAX];

  if(pipe(p) == -1){
    cprintf(0, c, "error: pipe error\n");    
    lprintf(0, "[error] %s: %s pipe error\n", __func__, strerror(errno));    
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
    lprintf(0, "[error] %s: %s fork error\n", __func__, strerror(errno));
    return(-1);
  }
  if(pid){
    /* parent */
    close(p[1]);
    c->cpid  = pid;
    c->fd[1] = p[0];
    lprintf(9, "%d$ (connect)\n", c->no);
    return(0);
  }else{
    /* child */
    close(p[0]);
    mexec_scan_child(p[1], base, sendhost, mode, c, gid);
    close(p[1]);
    _exit(0);
  }
  return(0);
}

int mexec_open(int l, mcomm *c, int n)
{
  if(n){
    lprintf(9, "%d$ %s\n", c->no, c->cmdline[n]);
    return(0);
  }
  if(c->logflag){
    lprintf(l, "%d>-----------------------\n", c->no);
    lprintf(l, "%d> %s\n", c->no, c->cmdline[n]);
  }else{
    if(l <= moption.loglevel){
      lprintf(l, "%d>======= connect =======\n", c->no);
      lprintf(l, "%d> %s\n", c->no, c->cmdline[n]);
      c->logflag = 1;
    }
  }
  return(0);
}

int mexec_close(mcomm *c, int n)
{
  mfile *m;
  if(c->fd[n] != -1){
    close(c->fd[n]);
    if(n){
      lprintf(9, "%d$ (disconnect)\n", c->no);
    }else{
      if(c->logflag){
        lprintf(1, "%d>---- disconnect -------\n", c->no);
      }
      lprintf(5, "%s: socket=%d\n", __func__, c->no);
    }
  }
  c->fd[n]  = -1;
  c->size[n] = 0;
  if(!n){
    c->authchk  = 0;
    c->logflag  = 0;
    c->logover  = 0;
    c->loglevel = 0;
    c->isalive  = 0;
    if(c->cpid){
      kill(c->cpid, SIGTERM);
      mexec_close(c, 1);
    }
    while(c->exclude){
      mexec_exclude_del(c, c->exclude);
    }
    for(m=mftop[MFSEND];m;m=m->next){
      if(m->comm == c){
        m->comm = NULL;
        lprintf(3, "%s: cancel> %s\n", __func__, m->cmdline);
      }
    }
  }
  return(0);
}

int mexec_quit(mcomm *c, int n)
{
  if(c->logflag){
    lprintf(1, "%d>-----------------------\n", c->no);
    lprintf(1, "%d> %s\n", c->no, c->cmdline[n]);
  }
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
  cprintf(0, c, "  alive on|off\n");
  cprintf(0, c, "  loglevel num (0-9)\n");
  cprintf(0, c, "  members\n");
  cprintf(0, c, "  help\n");
  return(0);
}

int mexec_send_help(mcomm *c, int n, int sync)
{
  if(sync){
    cprintf(0, c, "sync [-n] [-r] [-t host] [path]\n");
    cprintf(0, c, "  -n  # dryrun\n");
    cprintf(0, c, "  -r  # recursive\n");
    cprintf(0, c, "  -t  # target host\n");
  }else{
    cprintf(0, c, "send [-n] [-r] [-t host] [path]\n");
    cprintf(0, c, "  -n  # dryrun\n");
    cprintf(0, c, "  -r  # recursive\n");
    cprintf(0, c, "  -D  # with delete\n");
    cprintf(0, c, "  -t  # target host\n");
  }
  return(0);
}

int mexec_send(mcomm *c, int n, int sync)
{
  int e;
  int i;
  int j;
  ssize_t size;
  char *argv[9];
  char *fn = NULL;
  mfile *m = NULL;
  mhost *t = NULL;
  int dryrun = 0;
  int recurs = 0;
  gid_t gid = -1;
  int mode = MAKUO_MEXEC_SEND;

  if(moption.dontsend){
    cprintf(0, c, "error: this server can't send\n");
    return(0);
  }
  for(i=0;i<c->argc[n];i++){
    argv[i] = c->parse[n][i];
  }
  argv[i] = NULL;
  
  if(!strcmp("SunOS", moption.uts.sysname)){
    optind = 1; /* solaris */
  }else{
    optind = 0; /* other */
  }
  opterr = 1;
#ifdef HAVE_GETOPT_OPTRESET
  optreset = 1;
#endif
  while((i=getopt(c->argc[n], argv, "g:t:nr")) != -1){
    switch(i){
      case 'n':
        dryrun = 1;
        mode = MAKUO_MEXEC_DRY;
        break;
      case 'r':
        recurs = 1;
        break;
      case 'g':
        if(*optarg >= '0' && *optarg <='9'){
          gid = atoi(optarg);
        }else{
          if(!strcmp(optarg, moption.group_name)){
            gid = moption.gid;
          }else{
            for(j=0;j<moption.gidn;j++){
              if(!strcmp(optarg, moption.grnames[j])){
                gid = moption.gids[j];
                break;
              }
            }
          }
          if(gid == -1){
            lprintf(0, "[error] %s: not found group %s\n", __func__, optarg);
            cprintf(0, c, "error: not found group %s\n", optarg);
            return(0);
          }
        }
        break;
      case 't':
        for(t=members;t;t=t->next){
          if(!strcmp(t->hostname, optarg)){
            break;
          }
        }
        if(!t){
          cprintf(0, c, "%s is not contained in members\n", optarg);
          return(0);
        }
        break;
      case '?':
        cprintf(0, c, "invalid option -- %c\n", optopt);
        return(0); 
    }
  }

  while(optind < c->argc[n])
    fn = c->parse[n][optind++];

  if(fn){
    int len;
    if(len = strlen(fn)){
      if(fn[len - 1] == '/'){
        fn[len - 1] = 0;
      }
    }
  }

  /*----- directory scan -----*/
  if(recurs){
    if(c->cpid){
      cprintf(0, c, "recursive process active now!\n");
      return(0);
    }
    return(mexec_scan(c, fn, t, mode, gid));
  }

  /*----- help -----*/
  if(!fn){
    mexec_send_help(c, n, sync);
    return(0);
  }

  /*----- send file -----*/
  m = mfadd(MFSEND);
  if(!m){
	  lprintf(0, "[error] %s: out of memorry\n", __func__);
	  cprintf(0, c, "error: out of memorry\n");
    return(0);
	}

  /*----- send to address set -----*/
  if(t){
    m->sendto = 1;
    memcpy(&(m->addr.sin_addr), &(t->ad), sizeof(m->addr.sin_addr));
  }

	strcpy(m->fn, fn);
  strcpy(m->cmdline, c->cmdline[n]);
	m->mdata.head.reqid  = getrid();
	m->mdata.head.opcode = MAKUO_OP_SEND;
  m->mdata.head.nstate = MAKUO_SENDSTATE_STAT;
	m->comm      = c;
  m->dryrun    = dryrun;
  m->recurs    = recurs;
  m->initstate = 1;
  if(m->dryrun){
    m->mdata.head.flags |= MAKUO_FLAG_DRYRUN;
  }

	if(lstat(fn, &m->fs) == -1){
    e = errno;
    if(e == ENOENT){
      if(sync){
        m->mdata.head.flags |= MAKUO_FLAG_SYNC;
        return(0);
      }      
    }
	  cprintf(0, c, "error: %s %s\n", strerror(e), fn);
		lprintf(0, "[error] %s: %s %s\n", __func__, strerror(e), fn);
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
		  lprintf(0, "[error] %s: readlink error %s\n", __func__, fn);
		  mfdel(m);
      return(0);
    }
  }

  /*----- chgrp -----*/
  if((m->dryrun == 0) && (gid != -1)){
    if(m->fs.st_gid != gid){
      if(!lchown(m->fn, -1, gid)){
        m->fs.st_gid = gid;
      }else{
        e = errno;
        cprintf(0, c,   "error: can't chgrp (%s) [%d->%d] %s\n", strerror(e),  m->fs.st_gid, gid, m->fn);
        lprintf(0, "[error] %s: can't chgrp (%s) [%d->%d] %s\n", __func__, strerror(e),  m->fs.st_gid, gid, m->fn);
      }
    }
  }
  return(0);
}

int mexec_check(mcomm *c, int n)
{
  int e;
  int i;
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
  if(!strcmp("SunOS", moption.uts.sysname)){
    optind = 1; /* solaris */
  }else{
    optind = 0; /* other */
  }
  opterr = 1;
#ifdef HAVE_GETOPT_OPTRESET
  optreset = 1;
#endif
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
          cprintf(0, c, "%s is not contained in members\n", optarg);
          return(0);
        }
        break;
      case '?':
        cprintf(0, c, "invalid option -- %c\n", optopt);
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
    return(mexec_scan(c, fn, t, MAKUO_MEXEC_MD5, -1));
  }

  /*----- help -----*/
  if(!fn){
    cprintf(0, c,"usage: check [-t host] [-r] [path]\n");
    cprintf(0, c, "  -r  # dir recursive\n");
    cprintf(0, c, "  -t  # target host\n");
    return(0);
  }

  /*----- create mfile -----*/
  m = mfadd(MFSEND);
  if(!m){
	  lprintf(0, "[error] %s: out of memorry\n", __func__);
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
  strcpy(m->cmdline, c->cmdline[n]);

  /*----- open -----*/
  m->fd = open(m->fn, O_RDONLY);
  if(m->fd == -1){
    e = errno;
	  lprintf(0, "[error] %s: %s %s\n", __func__, strerror(e), m->fn);
    cprintf(0, c, "error: %s %s\n", strerror(e), m->fn);
    mfdel(m);
    return(0);
  }

  /*----- md5 -----*/
  h = (mhash *)m->mdata.data;
  h->fnlen = strlen(m->fn);
  memcpy(h->filename, m->fn, h->fnlen);
  m->mdata.head.szdata = sizeof(mhash) + h->fnlen;
  h->fnlen = htons(h->fnlen);
  MD5_Init(&(m->md5));

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
  if(!strcmp("SunOS", moption.uts.sysname)){
    optind = 1; /* solaris */
  }else{
    optind = 0; /* other */
  }
  opterr = 1;
#ifdef HAVE_GETOPT_OPTRESET
  optreset = 1;
#endif
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
          cprintf(0, c, "%s is not contained in members\n", optarg);
          return(0);
        }
        break;
      case '?':
        cprintf(0, c, "invalid option -- %c\n", optopt);
        return(0); 
    }
  }

  while(optind < c->argc[n]){
    fn = c->parse[n][optind++];
  }

  if(fn){
    int len;
    if(len = strlen(fn)){
      if(fn[len - 1] == '/'){
        fn[len - 1] = 0;
      }
    }
  }

  /*----- help -----*/
  if(c->argc[n]<2){
    cprintf(0, c, "dsync [-r] [-t host] [-n] [path]\n");
    cprintf(0, c, "  -r  # recursive\n");
    cprintf(0, c, "  -t  # target host\n");
    cprintf(0, c, "  -n  # dryrun\n");
    return(0);
  }

  mexec_with_dsync(c, fn, dryrun, recurs, t);
  return(0);
}

int mexec_members(mcomm *c, int n)
{
  int i, j;
  int counter = 0;
  int namelen = 0;
  int addrlen = 0;
  int statcnt = 0;
  mhost *t;
  mhost **pt;
  char form[256];

  /* count */
	for(t=members;t;t=t->next){
    counter++;
    if(namelen < strlen(t->hostname)){
      namelen = strlen(t->hostname);
    }
    if(addrlen < strlen(inet_ntoa(t->ad))){
      addrlen = strlen(inet_ntoa(t->ad));
    }
  }

  /* set */
  t  = members;
  pt = malloc(sizeof(mhost *) * counter);
  for(i=0;i<counter;i++){
    pt[i] = t;
    t = t->next;
  }

  /* sort */
  for(i=0;i<counter;i++){
    for(j=i+1;j<counter;j++){
      if(strcmp(pt[i]->hostname, pt[j]->hostname) > 0){
        t = pt[i];
        pt[i] = pt[j];
        pt[j] = t;
      }
    }
  }

  /* view */
#ifdef MAKUO_DEBUG
  sprintf(form, "%%-%ds %%-%ds (Ver%%s) STATE_AREA(%%d/%%d)\n", namelen, addrlen);
  for(i=0;i<counter;i++){
    statcnt = 0;
    for(j=0;j<MAKUO_HOSTSTATE_SIZE;j++){
      if(pt[i]->mflist[j]){
        statcnt++;
      }
    }
    cprintf(0, c, form, pt[i]->hostname, inet_ntoa(pt[i]->ad), pt[i]->version, statcnt, MAKUO_HOSTSTATE_SIZE);
  }
#else
  sprintf(form, "%%-%ds %%-%ds (Ver%%s)\n", namelen, addrlen);
  for(i=0;i<counter;i++){
    cprintf(0, c, form, pt[i]->hostname, inet_ntoa(pt[i]->ad), pt[i]->version);
  }
#endif
  cprintf(0, c, "Total: %d members\n", counter);
  free(pt);
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
  c->exclude = exclude_add(c->exclude, pattern);
  return(0);
}

int mexec_exclude_del(mcomm *c, excludeitem *e)
{
  excludeitem *d = exclude_del(e);
  if(e == c->exclude){
    c->exclude = d;
  }
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
  int i;
  int count;
  mfile  *m;
  struct tm *t;

  /*----- pid -----*/
  cprintf(0, c, "process : %d\n", getpid());

  /*----- version -----*/
  cprintf(0,c,"version : %s\n", PACKAGE_VERSION);

  /*----- basedir -----*/
  if(moption.chroot){
    cprintf(0, c, "chroot  : %s/\n", moption.real_dir);
  }else{
    cprintf(0, c, "basedir : %s/\n", moption.base_dir);
  }

  /*----- mfalloc -----*/
  count = 0;
  for(m=mftop[MFSEND];m;m=m->next){
    count++;
  }
  for(m=mftop[MFRECV];m;m=m->next){
    count++;
  }
  for(m=mfreeobj;m;m=m->next){
    count++;
  }
  cprintf(0, c, "mfalloc : %d\n", count);

  /*----- RCVBUF/SNDBUF -----*/
  cprintf(0, c, "recvsize: %d\n", moption.recvsize);
  cprintf(0, c, "sendsize: %d\n", moption.sendsize);
  
  /*----- send rate -----*/
  if(moption.sendrate){
    cprintf(0, c, "sendrate: %d/%d\n", 
      view_rate        * 8 / 1024 / 1024, 
      moption.sendrate * 8 / 1024 / 1024);
  }

  /*----- command -----*/
  count = 0;
  for(i=0;i<MAX_COMM;i++){
    if(moption.comm[i].working && (c != &(moption.comm[i]))){
      count++;
    }
  }
  cprintf(0, c, "command : %d\n", count);
  for(i=0;i<MAX_COMM;i++){
    if(moption.comm[i].working && (c != &(moption.comm[i]))){
      cprintf(0, c, "  %d> %s\n", i, moption.comm[i].cmdline[0]);
    }
  }

  /*----- send -----*/
  count = 0;
  for(m=mftop[MFSEND];m;m=m->next){
    count++;
  }
  cprintf(0,c,"send op : %d\n", count);
  for(m=mftop[MFSEND];m;m=m->next){
    uint32_t snow = m->seqnonow;
    uint32_t smax = m->seqnomax;
    if(snow > smax){
      snow = smax;
    }
    cprintf(0, c, "  (%s) %s %s %s (%u:%u/%u) rid=%d flags=%x\n",
      strackreq(&(m->mdata)), 
      stropcode(&(m->mdata)), 
      strmstate(&(m->mdata)), 
      m->fn, 
      m->markcount,
      snow, 
      smax,
      m->mdata.head.reqid,
      m->mdata.head.flags);
  }

  /*----- recv -----*/
  count = 0;
  for(m=mftop[MFRECV];m;m=m->next)
    count++;
  cprintf(0, c, "recv op : %d\n", count);
  for(m=mftop[MFRECV];m;m=m->next){
    t = localtime(&(m->lastrecv.tv_sec));
    cprintf(0, c, "  %s %s %02d:%02d:%02d %s (%d/%d) mark=%d rid=%d\n",
      stropcode(&(m->mdata)), 
      strrstate(m->mdata.head.nstate), 
      t->tm_hour, t->tm_min, t->tm_sec, 
      m->fn, 
      m->recvcount,
      m->seqnomax, 
      m->markcount,
      m->mdata.head.reqid); 
  }
  return(0);
}

int mexec_alive(mcomm *c, int n)
{
  if(c->argc[n] > 2){
    return(mexec_help(c, n));
  }
  if(c->argc[n] == 1){
    if(c->isalive){
      cprintf(0, c, "alive on\n");
    }else{
      cprintf(0, c, "alive off\n");
    }
    return(0);
  }
  if(!strcmp("on", c->parse[n][1])){
    c->isalive = 1;
    return(0);
  }
  if(!strcmp("off", c->parse[n][1])){
    c->isalive = 0;
    return(0);
  }
  return(mexec_help(c, n));
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

  if(n == 0){
    mtimeget(&(c->tv));
    if(c->working){
      c->size[n] = 0;
      r = read(c->fd[n], buff, size);
      if(r>0){
      }else{
        if(r == -1){
          lprintf(0, "[error] %s: read error n=%d fd=%d\n", __func__, n, c->fd[n]);
        }
        mexec_close(c, n);
      }
      return(-1);
    }
  }

  if(n == 1){
    for(m=mftop[MFSEND];m;m=m->next){
      if(m->comm == c){
        count++;
        if(count == MAKUO_PARALLEL_MAX){
          return(-1);
        }
      }
    }
  }

  if(!size){
    lprintf(0, "[error] %s: buffer over fllow n=%d\n", __func__, n);
    mexec_close(c, n);
    return(-1);
  }

  if(!c->check[n]){
    r = read(c->fd[n], buff, size);
    if(r > 0){
      c->size[n] += r;
    }else{
      if(r < 0){
        lprintf(0, "[error] %s: read error(%s) n=%d fd=%d\n", __func__, strerror(errno), n, c->fd[n]);
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
    c->working = 1;
    if(!strcmp("help", command_list[r])){
      mexec_open(1, c, n);
      return(mexec_help(c, n));
    }
    if(!strcmp("quit", command_list[r])){
      return(mexec_quit(c, n));
    }
    if(!strcmp("exit", command_list[r])){
      return(mexec_quit(c, n));
    }
    if(!strcmp("bye", command_list[r])){
      return(mexec_quit(c, n));
    }
    if(!strcmp("send", command_list[r])){
      mexec_open(1, c, n);
      return(mexec_send(c, n, 0));
    }
    if(!strcmp("sync", command_list[r])){
      mexec_open(1, c, n);
      return(mexec_send(c, n, 1));
    }
    if(!strcmp("md5", command_list[r])){
      mexec_open(1, c, n);
      return(mexec_check(c, n));
    }
    if(!strcmp("check", command_list[r])){
      mexec_open(1, c, n);
      return(mexec_check(c, n));
    }
    if(!strcmp("dsync", command_list[r])){
      mexec_open(1, c, n);
      return(mexec_dsync(c, n));
    }
    if(!strcmp("members", command_list[r])){
      mexec_open(4, c, n);
      return(mexec_members(c, n));
    }
    if(!strcmp("echo", command_list[r])){
      mexec_open(4, c, n);
      return(mexec_echo(c, n));
    }
    if(!strcmp("loglevel", command_list[r])){
      mexec_open(4, c, n);
      return(mexec_loglevel(c, n));
    }
    if(!strcmp("exclude", command_list[r])){
      mexec_open(4, c, n);
      return(mexec_exclude(c, n));
    }
    if(!strcmp("status", command_list[r])){
      mexec_open(4, c, n);
      return(mexec_status(c, n));
    }
    if(!strcmp("alive", command_list[r])){
      mexec_open(4, c, n);
      return(mexec_alive(c, n));
    }
    c->working = 0;
  }
  return(r);
}


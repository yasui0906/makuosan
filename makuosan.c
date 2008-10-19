/*
 * makuosan.c
 * Copyright (C) 2008 KLab Inc.
 */
#include "makuosan.h"

void usage()
{
  printf("makuosan (Multicast Advance Keep Update Overwrite Synchronization Always Network)\n");
  printf("version %s\n\n", MAKUOSAN_VERSION);
  printf("usage: makuosan [OPTION]\n");
  printf("  -d num   # loglevel(0-9)\n");
  printf("  -u uid   # user\n");
  printf("  -g gid   # group\n");
  printf("  -b dir   # base dir\n");
  printf("  -p port  # port number       (default: 5000)\n");
  printf("  -m addr  # multicast address (default: 224.0.0.108)\n");
  printf("  -l addr  # listen address    (default: 127.0.0.1)\n");
  printf("  -U path  # unix domain socket\n");
  printf("  -k file  # key file (encrypt password)\n");
  printf("  -K file  # key file (console password)\n");
  printf("  -f num   # parallel send count(default: 1) \n");
  printf("  -c       # chroot to base dir\n");
  printf("  -n       # don't fork\n");
  printf("  -r       # don't recv\n");
  printf("  -s       # don't send\n");
  printf("  -o       # don't listen (console off mode)\n");
  printf("  -O       # owner match limitation mode\n");
  printf("  -h       # help\n\n"); 
  exit(0);
}

int chexit()
{
  char cwd[PATH_MAX];
  if(moption.chroot){
    /*----- chroot exit -----*/
    mtempname("",".MAKUOWORK",cwd);
    mkdir(cwd,0700);
    chroot(cwd);
    rmdir(cwd);
    chdir("..");
    getcwd(cwd,PATH_MAX);
    while(strcmp("/", cwd)){
      chdir("..");
      getcwd(cwd,PATH_MAX);
    }
    chroot(".");
  }
  return(0);
}

int setguid(int uid, int gid)
{
  /*----- setgid -----*/
  if(gid != getegid()){
    if(setgroups(1, &gid) == -1){
      return(-1);
    }
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

int restoreguid()
{
  if(getuid() != geteuid())
    seteuid(getuid());
  if(getgid() != getegid())
    setegid(getgid());
  return(0);
}

void recv_timeout(mfile *m)
{
  mhost   *t;
  uint8_t *r;
  if(m){
    m->retrycnt = MAKUO_SEND_RETRYCNT;
    do{
      for(t=members;t;t=t->next){
        r = get_hoststate(t, m);
        if(*r == MAKUO_RECVSTATE_NONE){
          lprintf(0, "%s: %s(%s) timeout\n", __func__, inet_ntoa(t->ad), t->hostname);
          member_del(t);
          break;
        }
      }
    }while(t); 
  }
}

struct timeval *pingpong(int n)
{
  static struct timeval tv;
  mfile *m = mfins(0);
  mping *p = NULL;
  char buff[MAKUO_HOSTNAME_MAX + 1];

  if(!m){
    lprintf(0, "%s: out of memmory\r\n", __func__);
    return(0);
  }
  switch(n){
    case 0:
      m->mdata.head.opcode = MAKUO_OP_PING;
      break;
    case 1:
      m->mdata.head.opcode = MAKUO_OP_PING;
      m->mdata.head.flags |= MAKUO_FLAG_ACK;
      break;
    case 2:
      m->mdata.head.opcode = MAKUO_OP_EXIT;
      break;
  } 
  m->mdata.head.reqid  = getrid();
  m->mdata.head.seqno  = 0;
  m->mdata.head.szdata = 0;
  m->sendwait          = 0;
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
  gettimeofday(&tv,NULL);
  return(&tv);
}

int cleanup()
{
  mfile *m;
  socklen_t namelen;
  struct sockaddr_un addr;

  /*----- send object -----*/
  while(m=mftop[0])
    mfdel(m);

  /*----- recv object -----*/
  while(m=mftop[1]){
    if(m->mdata.head.nstate == MAKUO_RECVSTATE_OPEN){
      if(m->fd != -1){
        close(m->fd);
        m->fd = -1;
      }
      if(S_ISREG(m->fs.st_mode)){
        mremove(moption.base_dir,m->tn);
      }
    }
    mfdel(m);
  }

  /*----- exit notify -----*/
  pingpong(2);
  msend(moption.mcsocket, mftop[0]);

  /*----- unlink unix domain socket -----*/
  namelen=sizeof(addr);
  if(!getsockname(moption.lisocket, (struct sockaddr *)&addr, &namelen)){
    if(addr.sun_family == AF_UNIX){
      unlink(addr.sun_path);
    }
  }

  /*----- close -----*/
  close(moption.mcsocket);
  close(moption.lisocket);
  return(0);
}

int mcomm_accept(mcomm *c, fd_set *fds, int s)
{
  int i;
  if(s == -1)
    return(0);
  if(!FD_ISSET(s,fds))
    return(0);
  for(i=0;i<MAX_COMM;i++)
    if(c[i].fd[0] == -1)
      break;
  if(i==MAX_COMM){
    close(accept(s, NULL, 0)); 
    return(0);
  }
  c[i].addrlen = sizeof(c[i].addr);
  c[i].fd[0] = accept(s, (struct sockaddr *)(&c[i].addr), &(c[i].addrlen));
  lprintf(1, "%s: accept from %s i=%d fd=%d\n", __func__, inet_ntoa(c[i].addr.sin_addr), i, c[i].fd[0]);
  c[i].working = 1;
  return(0);
}

int mcomm_read(mcomm *c, fd_set *fds){
  int i, j;
  mfile *m;
  for(i=0;i<MAX_COMM;i++){
    for(j=0;j<2;j++){
      if(c[i].fd[j] != -1){
        if(FD_ISSET(c[i].fd[j], fds) || c[i].check[j]){
          mexec(&c[i], j);
        }
      }
    }
    if(c[i].fd[1] == -1){
      for(m=mftop[0];m;m=m->next){
        if(m->comm == &c[i]){
          break;
        }
      }
      if(!m){
        if(c[i].working && !c[i].cpid){
          workend(&c[i]);
        }
      }
    }
  }
  return(0);
}

int mcomm_fdset(mcomm *c, fd_set *fds)
{
  int i;

  /*----- listen socket -----*/
  if(moption.lisocket != -1)
    FD_SET(moption.lisocket, fds);

  /*----- connect socket -----*/
  for(i=0;i<MAX_COMM;i++){
    if(c[i].fd[0] != -1){
      FD_SET(c[i].fd[0], fds);
    }
    if(c[i].fd[1] != -1){
      FD_SET(c[i].fd[1], fds);
    }else{
      if(c[i].cpid){
        if(waitpid(c[i].cpid, NULL, WNOHANG) == c[i].cpid){
          c[i].cpid = 0;
        }
      }
    }
  }
  return(0);
}

int ismsend(int s, mfile *m)
{
  int r;
  if(!m){
    return(0);
  }
  if(!S_ISLNK(m->fs.st_mode) && S_ISDIR(m->fs.st_mode)){
    if(m != mftop[0]){
      return(0);
    }
  }
  if(m->senddelay){
    if(!mtimeout(&(m->lastsend), m->senddelay)){
      return(1);
    }
  }
  r = ack_check(m, MAKUO_RECVSTATE_NONE);
  if(r == -1){
    m->mdata.head.seqno  = 0;
    m->mdata.head.nstate = MAKUO_SENDSTATE_BREAK;
  }
  if(!r){
    m->sendwait = 0;
  }
  if(m->sendwait){
    if(!mtimeout(&(m->lastsend), MAKUO_SEND_TIMEOUT)){
      return(1);
    }
    if(!(m->retrycnt)){
      recv_timeout(m);
    }
  }
  msend(s,m);
  return(1);
}

/***** main loop *****/
int mloop()
{
  fd_set rfds;
  fd_set wfds;
  struct timeval *lastpong;
  struct timeval tv;
  
  gettimeofday(&curtime,NULL);
  lastpong = pingpong(0);
  while(loop_flag){
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    gettimeofday(&curtime,NULL);
    if(mtimeout(lastpong, MAKUO_PONG_INTERVAL))
      lastpong = pingpong(1);

    mcomm_fdset(moption.comm, &rfds);
    FD_SET(moption.mcsocket,  &rfds);
    if(mftop[0]){
      tv.tv_sec  = 0;
      tv.tv_usec = 10000;
      FD_SET(moption.mcsocket, &wfds);
    }

    if(select(1024, &rfds, &wfds, NULL, &tv) < 0)
      continue;

    gettimeofday(&curtime,NULL);
    if(FD_ISSET(moption.mcsocket,&wfds)){
      int para = 0;
      mfile *n = NULL;
      mfile *m = mftop[0];
      while(m){
        n = m->next;
        para += ismsend(moption.mcsocket, m);
        m = n;
        if(para == moption.parallel){
          break;
        }
      }
    }
    if(FD_ISSET(moption.mcsocket,&rfds))
      mrecv(moption.mcsocket);

    mrecv_gc();
    mcomm_accept(moption.comm, &rfds, moption.lisocket); /* new console  */
    mcomm_read(moption.comm, &rfds);                     /* command exec */
  }
  return(0);
}

void mexit()
{
  lprintf(0, "%s: shutdown start\n", __func__);
  restoreguid(); /* euid,egidを元に戻す      */
  chexit();      /* chrootから脱出           */
  cleanup();     /* ディスクリプタの開放など */
  lprintf(0, "%s: shutdown complete\n", __func__);
}

int main(int argc, char *argv[])
{
  minit(argc,argv);
  mloop();
  mexit();
  return(0);
}


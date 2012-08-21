/*
 * minit.c
 * Copyright (C) 2008-2012 KLab Inc.
 */
#include "makuosan.h"

static void version_print()
{
  printf("makuosan version %s\n", PACKAGE_VERSION);
}

static void usage()
{
  version_print();
  printf("(Multicasts All-Kinds of Updating Operation for Servers on Administered Network)\n\n");
  printf("usage: makuosan [OPTION]\n");
  printf("  -d num       # loglevel(0-9)\n");
  printf("  -u uid       # user\n");
  printf("  -g gid       # group\n");
  printf("  -G gid,..    # groups\n");
  printf("  -b dir       # base dir\n");
  printf("  -p port      # port number       (default: 5000)\n");
  printf("  -m addr      # multicast address (default: 224.0.0.108)\n");
  printf("  -i addr      # interface address (default: 0.0.0.0)\n");
  printf("  -l addr      # listen address    (default: 127.0.0.1)\n");
  printf("  -U path      # unix domain socket\n");
  printf("  -k file      # key file (encrypt password)\n");
  printf("  -K file      # key file (console password)\n");
  printf("  -f num       # parallel send count(default: 5) \n");
  printf("  -R num       # recv buffer size [bytes]\n");
  printf("  -S num       # send buffer size [bytes]\n");
  printf("  -T num       # traffic rate     [Mbps]\n");
  printf("  -n           # don't fork\n");
  printf("  -r           # don't recv\n");
  printf("  -s           # don't send\n");
  printf("  -o           # don't listen (console off mode)\n");
  printf("  -O           # owner match limitation mode\n");
  printf("  -c --chroot  # chroot to base dir\n");
  printf("  -V --version # version\n"); 
  printf("  -h --help    # help\n\n"); 
  exit(0);
}

static void signal_handler(int n)
{
  switch(n){
    case SIGINT:
    case SIGTERM:
      loop_flag = 0;
      break;
    case SIGPIPE:
      break;
    case SIGUSR1:
      if(log_level<9){
        log_level++;
      }
      break;
    case SIGUSR2:
      if(log_level>0){
        log_level--;
      }
      break;
  }
}

static void minit_option_setdefault()
{
  int i;
  memset(&moption, 0, sizeof(moption));
  moption.maddr.sin_family      = AF_INET;
  moption.maddr.sin_addr.s_addr = inet_addr(MAKUO_MCAST_ADDR);
  moption.maddr.sin_port        = htons(MAKUO_MCAST_PORT);
  moption.iaddr.sin_family      = AF_INET;
  moption.iaddr.sin_addr.s_addr = INADDR_ANY;
  moption.iaddr.sin_port        = htons(MAKUO_MCAST_PORT);
  moption.laddr.sin_family      = AF_INET;
  moption.laddr.sin_addr.s_addr = inet_addr(MAKUO_LOCAL_ADDR);
  moption.laddr.sin_port        = htons(MAKUO_MCAST_PORT);
  moption.uaddr.sun_family      = AF_UNIX;
  moption.uaddr.sun_path[0]     = 0;
  moption.loglevel              = 0;
  moption.dontrecv              = 0;
  moption.dontsend              = 0;
  moption.dontfork              = 0;
  moption.cryptena              = 0;
  moption.comm_ena              = 1;
  moption.commpass              = 0;
  moption.ownmatch              = 0;
  moption.parallel              = 5;
  moption.recvsize              = 0;
  moption.sendsize              = 0;
  moption.sendrate              = 0;
  moption.chroot                = 0;
  moption.uid                   = geteuid();
  moption.gid                   = getegid();
  moption.gids                  = NULL;
  getcwd(moption.base_dir, PATH_MAX);
  for(i=0;i<MAX_COMM;i++){
    moption.comm[i].no = i;
    moption.comm[i].fd[0] = -1;
    moption.comm[i].fd[1] = -1;
  }
  uname(&moption.uts);
}

static int minit_option_setuid(char *name)
{
  struct passwd *pw;
  if(*name >= '0' && *name <= '9'){
    moption.uid = atoi(name);
  }else{
    if((pw = getpwnam(name))){
      moption.uid = pw->pw_uid;
      moption.gid = pw->pw_gid;
    }else{
      lprintf(0,"[error] %s: not found user %s\n", __func__, name);
      return(1);
    }
  }
  return(0);
}

static int minit_option_setgid(char *name)
{
  struct group *gr;
  if(*name >= '0' && *name <='9'){
    moption.gid = atoi(name);
  }else{
    if((gr = getgrnam(name))){
      moption.gid = gr->gr_gid;
    }else{
      lprintf(0,"[error] %s: not found group %s\n", __func__, name);
      return(1);
    }
  }
  return(0);
}

static int minit_option_setgids(char *name)
{
  char *p;
  gid_t gid;
  size_t num;
  struct group *g;
  char buff[1024];

  if(moption.gids){
    free(moption.gids);
  }
  moption.gids = NULL;
  moption.gidn = 0;

  if(!name){
    return(0);
  }

  if(strlen(name) >= sizeof(buff)){
    lprintf(0, "[error] %s: gids too long %s\n", __func__, name);
    return(1);
  }

  num = 0;
  strcpy(buff, name);
  p = strtok(buff,",");
  while(p){
    p = strtok(NULL,",");
    num++;
  }
  if(!num){
    return(0);
  }
  moption.gidn = num;
  moption.gids = malloc(sizeof(gid_t) * num);
 
  num = 0; 
  strcpy(buff, name);
  p = strtok(buff,",");
  while(p){
    if(*p >= '0' && *p <= '9'){
      gid = atoi(p);
      if((g = getgrgid(gid))){
        moption.gids[num] = gid;
        strcpy(moption.grnames[num], g->gr_name);
      }else{
        lprintf(0, "[error] %s: not found group %s\n", __func__, p);
        return(1);
      }
    }else{
      if((g = getgrnam(p))){
        moption.gids[num] = g->gr_gid;
        strcpy(moption.grnames[num], p);
      }else{
        lprintf(0, "[error] %s: not found group %s\n", __func__, p);
        return(1);
      }
    }
    p = strtok(NULL,",");
    num++;
  }
  return(0);
}

static void minit_option_getenv()
{
  char *env;

  if((env=getenv("MAKUOSAN_BASE"))){
    if(*env){
      realpath(env, moption.base_dir);
    }
  }
  if((env=getenv("MAKUOSAN_PORT"))){
    if(*env && atoi(env)){
      moption.maddr.sin_port = htons(atoi(env));
      moption.laddr.sin_port = htons(atoi(env));
    }
  }
  if((env=getenv("MAKUOSAN_USER"))){
    if(*env && minit_option_setuid(env)){
      exit(1);
    }
  }
  if((env=getenv("MAKUOSAN_GROUP"))){
    if(*env && minit_option_setgid(env)){
      exit(1);
    }
  }
  if((env=getenv("MAKUOSAN_GROUPS"))){
    if(*env && minit_option_setgids(env)){
      exit(1);
    }
  }
  if((env=getenv("MAKUOSAN_SOCK"))){
    strcpy(moption.uaddr.sun_path, env);
  }
  if((env=getenv("MAKUOSAN_RCVBUF"))){
    moption.recvsize = atoi(env);
  }
  if((env=getenv("MAKUOSAN_SNDBUF"))){
    moption.sendsize = atoi(env);
  }
}

static void minit_signal()
{
  struct sigaction sig;
  memset(&sig, 0, sizeof(sig));
  sig.sa_handler = signal_handler;
  if(sigaction(SIGINT,  &sig, NULL) == -1){
    lprintf(0, "%s: sigaction error SIGINT\n", __func__);
    exit(1);
  }
  if(sigaction(SIGTERM, &sig, NULL) == -1){
    lprintf(0, "%s: sigaction error SIGTERM\n", __func__);
    exit(1);
  }
  if(sigaction(SIGPIPE, &sig, NULL) == -1){
    lprintf(0, "%s: sigaction error SIGPIPE\n", __func__);
    exit(1);
  }
  if(sigaction(SIGUSR1, &sig, NULL) == -1){
    lprintf(0, "%s: sigaction error SIGUSR1\n", __func__);
    exit(1);
  }
  if(sigaction(SIGUSR2, &sig, NULL) == -1){
    lprintf(0, "%s: sigaction error SIGUSR2\n", __func__);
    exit(1);
  }
}

static void minit_password(char *filename, int n)
{
  int i;
  int f;
  char buff[64];
  MD5_CTX ctx;

  f = open(filename, O_RDONLY);
  if(f == -1){
    lprintf(0, "[error] %s: file open error %s\n", __func__, filename);
    exit(1);
  }
  memset(buff, 0, sizeof(buff));
  i = read(f, buff, sizeof(buff) - 1);
  if(i == -1){
    lprintf(0, "[error] %s: file read error %s\n", __func__, filename);
    exit(1);
  }
  if(i < 4){
    lprintf(0, "[error] %s: password too short %s\n", __func__, filename);
    exit(1);
  }
  while(i--){
    if(buff[i] == '\r')
      buff[i] = 0;
    if(buff[i] == '\n')
      buff[i] = 0;
  }
  MD5_Init(&ctx);
  MD5_Update(&ctx, buff, strlen(buff));
  MD5_Final((unsigned char *)(moption.password[n]), &ctx);
  if(read(f, buff, sizeof(buff))){
    lprintf(0, "[error] %s: password too long %s\n", __func__, filename);
    exit(1);
  }
  close(f);
}

static void minit_getopt(int argc, char *argv[])
{
  int r;
  struct option opt[]={
    {"chroot",  0, NULL, 'c'},
    {"help",    0, NULL, 'h'},
    {"version", 0, NULL, 'V'},
    {0, 0, 0, 0}
  };

  while((r=getopt_long(argc, argv, "T:R:S:f:u:g:G:d:b:p:m:i:l:U:k:K:VhnsroOc", opt, NULL)) != -1){
    switch(r){
      case 'V':
        version_print();
        exit(0);

      case 'h':
        usage();
        exit(0);

      case 'T':
        moption.sendrate = atoi(optarg) * 1024 * 1024 / 8;
        break;

      case 'R':
        moption.recvsize = atoi(optarg);
        break;

      case 'S':
        moption.sendsize = atoi(optarg);
        break;

      case 'f':
        moption.parallel = atoi(optarg);
        if(moption.parallel < 1){
          moption.parallel = 1;
        }
        if(moption.parallel >= MAKUO_PARALLEL_MAX){
          moption.parallel = MAKUO_PARALLEL_MAX - 1;
        }
        break;

      case 'n':
        moption.dontfork = 1;
        break;

      case 's':
        moption.dontsend = 1;
        break;

      case 'r':
        moption.dontrecv = 1;
        break;

      case 'o':
        moption.comm_ena = 0;
        break;

      case 'c':
        moption.chroot = 1;
        break;

      case 'd':
        moption.loglevel = atoi(optarg);
        break;

      case 'u':
        if(minit_option_setuid(optarg)){
          exit(1);
        }
        break;

      case 'g':
        if(minit_option_setgid(optarg)){
          exit(1);
        }
        break;

      case 'G':
        if(minit_option_setgids(optarg)){
          exit(1);
        }
        break;

      case 'b':
        realpath(optarg, moption.base_dir);
        break;

      case 'm':
        moption.maddr.sin_addr.s_addr = inet_addr(optarg);
        break;

      case 'i':
        moption.iaddr.sin_addr.s_addr = inet_addr(optarg);
        break;

      case 'l':
        moption.laddr.sin_addr.s_addr = inet_addr(optarg);
        break;

      case 'U':
        strcpy(moption.uaddr.sun_path, optarg);
        break;

      case 'p':
        moption.laddr.sin_port = htons(atoi(optarg));
        moption.maddr.sin_port = htons(atoi(optarg));
        break;

      case 'K':
        moption.commpass = 1;
        minit_password(optarg, 0);
        break;

      case 'k':
        moption.cryptena = 1;
        minit_password(optarg, 1);
        break;

      case 'O':
        moption.ownmatch = 1;
        break;
  
      case '?':
        exit(1);
    }
  }
  log_level = moption.loglevel;
}

static void minit_syslog()
{
  openlog("makuosan", LOG_NDELAY, LOG_DAEMON);
}

static void minit_socket()
{
  int  s;
  char lpen  = 0;
  char mttl  = 1;
  socklen_t slen;
  struct ip_mreq mg;
  struct sockaddr_in addr;
  mg.imr_multiaddr.s_addr = moption.maddr.sin_addr.s_addr;
  mg.imr_interface.s_addr = moption.iaddr.sin_addr.s_addr;
  addr.sin_family         = AF_INET;
  addr.sin_port           = moption.maddr.sin_port; 
  addr.sin_addr.s_addr    = INADDR_ANY;

  s=socket(AF_INET, SOCK_DGRAM, 0);
  if(s == -1){
    lprintf(0, "%s: can't create multicast socket\n", __func__);
    exit(1);
  }
  if(moption.recvsize){
    if(setsockopt(s, SOL_SOCKET, SO_RCVBUF, (void *)&(moption.recvsize), sizeof(moption.recvsize)) == -1){
      lprintf(0, "%s: setsockopt SO_RCVBUF error\n", __func__);
      exit(1);
    }
  }
  slen=sizeof(moption.recvsize);
  if(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (void *)&(moption.recvsize), &slen) == -1){
    lprintf(0, "%s: getsockopt SO_RCVBUF error\n", __func__);
    exit(1);
  }
  moption.recvsize /= 2;
  if(moption.sendsize){
    if(setsockopt(s, SOL_SOCKET, SO_SNDBUF, (void *)&(moption.sendsize), sizeof(moption.sendsize)) == -1){
      lprintf(0, "%s: setsockopt SO_SNDBUF error\n", __func__);
      exit(1);
    }
  }
  slen=sizeof(moption.sendsize);
  if(getsockopt(s, SOL_SOCKET, SO_SNDBUF, (void *)&(moption.sendsize), &slen) == -1){
    lprintf(0, "%s: getsockopt SO_SNDBUF error\n", __func__);
    exit(1);
  }
  moption.sendsize /= 2;
  if(fcntl(s, F_SETFL , O_NONBLOCK)){
    lprintf(0, "%s: fcntl error\n", __func__);
    exit(1);
  }
  if(bind(s, (struct sockaddr*)&addr, sizeof(addr)) == -1){
    lprintf(0, "%s: bind error\n", __func__);
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mg, sizeof(mg)) == -1){
    lprintf(0, "%s: IP_ADD_MEMBERSHIP error\n", __func__);
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,   (void *)&mg.imr_interface.s_addr, sizeof(mg.imr_interface.s_addr)) == -1){
    lprintf(0, "%s: IP_MULTICAST_IF error\n", __func__);
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (void *)&lpen, sizeof(lpen)) == -1){
    lprintf(0, "%s: IP_MULTICAST_LOOP error\n", __func__);
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,  (void *)&mttl, sizeof(mttl)) == -1){
    lprintf(0, "%s: IP_MULTICAST_TTL error\n", __func__);
    exit(1);
  }
  moption.mcsocket = s;
}

static void minit_console()
{
  int s;
  int reuse = 1;

  if(!moption.comm_ena){
    moption.lisocket = -1;
    return;
  }

  if(moption.uaddr.sun_path[0]){
    s=socket(AF_UNIX,SOCK_STREAM,0);
    if(!connect(s, (struct sockaddr*)&moption.uaddr, sizeof(moption.uaddr))){
      lprintf(0, "%s: can't create %s\n", __func__, moption.uaddr.sun_path);
      exit(1);
    }
    close(s);
    unlink(moption.uaddr.sun_path);
    s=socket(AF_UNIX,SOCK_STREAM,0);
    if(s == -1){
      lprintf(0, "%s: can't create listen socket\n", __func__);
      exit(1);
    }
    if(bind(s, (struct sockaddr*)&moption.uaddr, sizeof(moption.uaddr)) == -1){
      lprintf(0, "%s: bind error\n", __func__);
      exit(1);
    }
    chmod(moption.uaddr.sun_path , S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
    chown(moption.uaddr.sun_path , moption.uid, moption.gid);
  }else{
    s=socket(AF_INET,SOCK_STREAM,0);
    if(s == -1){
      lprintf(0, "%s: can't create listen socket\n", __func__);
      exit(1);
    }
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(reuse)) == -1){
      lprintf(0, "%s: SO_REUSEADDR error\n", __func__);
      exit(1);
    }
    if(bind(s, (struct sockaddr*)&moption.laddr, sizeof(moption.laddr)) == -1){
      lprintf(0, "%s: bind error\n", __func__);
      exit(1);
    }
  }
  if(listen(s,5) == -1){
    lprintf(0, "%s: listen error\n", __func__);
    exit(1);
  }
  moption.lisocket = s;
}

static void minit_chdir()
{
  if(chdir(moption.base_dir) == -1){
    lprintf(0, "%s: can't chdir %s\n", __func__,  moption.base_dir);
    exit(1);
  }
  getcwd(moption.real_dir, PATH_MAX);
}

static void minit_chroot()
{
  char tz[256];
  if(moption.chroot){
    tzset();
    sprintf(tz, "%s%+ld", tzname[0], timezone/3600);
    setenv("TZ", tz, 0);
    tzset();
    if(chroot(moption.base_dir) == -1){
      fprintf(stderr, "%s: can't chroot %s\n", __func__, moption.base_dir);
      exit(1);
    }
  }
  getcwd(moption.base_dir, PATH_MAX);
}

static void minit_getguid()
{
  struct passwd *pw;
  struct group  *gr;
  if((pw = getpwuid(moption.uid))){
    strcpy(moption.user_name, pw->pw_name);
  }
  if((gr = getgrgid(moption.gid))){
    strcpy(moption.group_name,gr->gr_name);
  }
}

static void minit_setguid()
{
  size_t num;
  if(set_guid(moption.uid, moption.gid, moption.gidn, moption.gids) == -1){
    fprintf(stderr, "%s: can't setguid %d:%d", __func__, moption.uid, moption.gid);
    if(moption.gidn){
      for(num=0;num<moption.gidn;num++){
        fprintf(stderr, ",%d", moption.gids[num]);
      }
    }
    fprintf(stderr, "\n");
    exit(1);
  }
}

static void minit_daemonize()
{
  int pid;
  if(moption.dontfork){
    lprintf(0, "pid       : %d\n", getpid());
    return;
  }

  pid = fork();
  if(pid == -1){
    fprintf(stderr, "%s: can't fork()\n", __func__);
    exit(1); 
  }
  if(pid)
    _exit(0);
  setsid();
  pid=fork();
  if(pid == -1){
    fprintf(stderr, "%s: can't fork()\n", __func__);
    exit(1); 
  }
  if(pid){
    lprintf(0, "pid       : %d\n",pid);
    _exit(0);
  }

  /*----- daemon process -----*/
  close(2);
  close(1);
  close(0);
  open("/dev/null",O_RDWR); /* new stdin  */
  dup(0);                   /* new stdout */
  dup(0);                   /* new stderr */
}

static void minit_bootlog()
{
  int i;

  lprintf(0, "makuosan version %s\n", PACKAGE_VERSION);
  lprintf(0, "sysname   : %s\n", moption.uts.sysname);
  lprintf(0, "loglevel  : %d\n", moption.loglevel);
  if(moption.chroot){
    lprintf(0, "chroot    : %s\n", moption.real_dir);
  }else{
    lprintf(0, "base dir  : %s\n", moption.base_dir);
  }
  lprintf(0, "multicast : %s\n", inet_ntoa(moption.maddr.sin_addr));
  lprintf(0, "interface : %s\n", inet_ntoa(moption.iaddr.sin_addr));
  lprintf(0, "port      : %d\n", ntohs(moption.maddr.sin_port));
  lprintf(0, "uid       : %d(%s)\n", moption.uid, moption.user_name);
  lprintf(0, "gid       : %d(%s)"  , moption.gid, moption.group_name);
  if(moption.gids){
    for(i=0;i<moption.gidn;i++){
      lprintf(0, ", %d(%s)", moption.gids[i], moption.grnames[i]);
    }
  }
  lprintf(0, "\n");
  lprintf(0, "rcvbuf    : %d\n", moption.recvsize);
  lprintf(0, "sndbuf    : %d\n", moption.sendsize);
  lprintf(0, "parallel  : %d\n", moption.parallel);
  lprintf(0, "don't recv: %s\n", yesno(moption.dontrecv));
  lprintf(0, "don't send: %s\n", yesno(moption.dontsend));
  lprintf(0, "don't fork: %s\n", yesno(moption.dontfork));
  lprintf(0, "encrypt   : %s\n", yesno(moption.cryptena));
  lprintf(0, "console   : %s\n", yesno(moption.comm_ena));
  lprintf(0, "passwoed  : %s\n", yesno(moption.commpass));
  lprintf(0, "ownermatch: %s\n", yesno(moption.ownmatch));
  if(moption.sendrate){
    lprintf(0, "rate      : %d[Mbps]\n", moption.sendrate * 8 / 1024 / 1024);
  }
  if(moption.comm_ena){
    if(moption.uaddr.sun_path[0]){
      lprintf(0,"listen    : %s\n", moption.uaddr.sun_path);
    }else{
      lprintf(0,"listen    : %s\n", inet_ntoa(moption.laddr.sin_addr));
    }
  }
}

/*
 *  まくお初期化関数
 *  mainから呼び出される
 */
void minit(int argc, char *argv[])
{
  if(argc == 1){
    usage(); /* and exit */
  }
  minit_option_setdefault(); /* 各オプションのデフォルト値を設定   */
  minit_option_getenv();     /* 環境変数からオプションを読み込む   */
  minit_getopt(argc, argv);  /* コマンドラインオプションを読み込む */
  minit_syslog();            /* syslogの使用を開始                 */
  minit_socket();            /* マルチキャストソケットの初期化     */
  minit_console();           /* コンソールソケットの初期化         */
  minit_signal();            /* シグナルハンドラを設定             */
  minit_chdir();             /* カレントディレクトリを変更         */
  minit_getguid();           /*                                    */
  minit_chroot();            /*                                    */
  minit_setguid();           /*                                    */
  minit_bootlog();           /* ブートメッセージを出力する         */
  minit_daemonize();         /*                                    */
}


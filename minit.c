/*
 *  minit.c
 *  まくお起動時の処理
 *  各関数の役割は最後のminit()関数のコメント参照
 *
 */
#include "makuosan.h"

void signal_handler(int n)
{
  switch(n){
    case SIGINT:
    case SIGTERM:
      loop_flag = 0;
      break;
    case SIGPIPE:
      break;
    case SIGUSR1:
      if(moption.loglevel<9){
        moption.loglevel++;
        lprintf(0,"signal_handler: loglevel=%d\n", moption.loglevel);
      }
      break;
    case SIGUSR2:
      if(moption.loglevel>0){
        moption.loglevel--;
        lprintf(0,"signal_handler: loglevel=%d\n", moption.loglevel);
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
  moption.laddr.sin_family      = AF_INET;
  moption.laddr.sin_addr.s_addr = INADDR_ANY;
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
  moption.chroot                = 0;
  moption.uid                   = geteuid();
  moption.gid                   = getegid();
  getcwd(moption.base_dir, PATH_MAX);
  for(i=0;i<MAX_COMM;i++){
    moption.comm[i].fd[0] = -1;
    moption.comm[i].fd[1] = -1;
  }
}

static void minit_option_getenv()
{
  char *env;
  struct passwd *pw;
  struct group  *gr;

  if(env=getenv("MAKUOSAN_PORT")){
    moption.maddr.sin_port = htons(atoi(env));
    moption.laddr.sin_port = htons(atoi(env));
  }
  if(env=getenv("MAKUOSAN_USER")){
    if(*env >= '0' && *env <='9'){
      moption.uid = atoi(env);
    }else{
      if(pw = getpwnam(env)){
        moption.uid = pw->pw_uid;
        moption.gid = pw->pw_gid;
      }else{
        lprintf(0,"minit_option_getenv: getpwnam error %s\n", env);
        exit(1);
      }
    }
  }
  if(env=getenv("MAKUOSAN_GROUP")){
    if(*env >= '0' && *env <='9'){
      moption.gid = atoi(env);
    }else{
      if(gr = getgrnam(env)){
        moption.gid = gr->gr_gid;
      }else{
        lprintf(0,"minit_option_getenv: getgrnam error %s\n", env);
        exit(1);
      }
    }
  }
  if(env=getenv("MAKUOSAN_SOCK")){
    strcpy(moption.uaddr.sun_path, env);
  }
}

static void minit_signal()
{
  struct sigaction sig;
  memset(&sig, 0, sizeof(sig));
  sig.sa_handler = signal_handler;
  if(sigaction(SIGINT,  &sig, NULL) == -1){
    lprintf(0, "minit_signal: sigaction error SIGINT\n");
    exit(1);
  }
  if(sigaction(SIGTERM, &sig, NULL) == -1){
    lprintf(0, "minit_signal: sigaction error SIGTERM\n");
    exit(1);
  }
  if(sigaction(SIGPIPE, &sig, NULL) == -1){
    lprintf(0, "minit_signal: sigaction error SIGPIPE\n");
    exit(1);
  }
  if(sigaction(SIGUSR1, &sig, NULL) == -1){
    lprintf(0, "minit_signal: sigaction error SIGUSR1\n");
    exit(1);
  }
  if(sigaction(SIGUSR2, &sig, NULL) == -1){
    lprintf(0, "minit_signal: sigaction error SIGUSR2\n");
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
    lprintf(0, "minit_password: file open error %s\n", optarg);
    exit(1);
  }
  memset(buff, 0, sizeof(buff));
  i = read(f, buff, sizeof(buff) - 1);
  if(i == -1){
    lprintf(0, "minit_password: file read error %s\n", optarg);
    exit(1);
  }
  if(i < 4){
    lprintf(0, "minit_password: password too short %s\n", optarg);
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
  MD5_Final(moption.password[n], &ctx);
  if(read(f, buff, sizeof(buff))){
    lprintf(0, "minit_password: password too long %s\n", optarg);
    exit(1);
  }
  close(f);
}

static void minit_getopt(int argc, char *argv[])
{
  int r;
  struct passwd *pw;
  struct group  *gr;

  while((r=getopt(argc, argv, "u:g:d:b:p:m:l:U:k:K:hnsroc")) != -1){
    switch(r){
      case 'h':
        usage();

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
        if(*optarg >= '0' && *optarg <='9'){
          moption.uid = atoi(optarg);
        }else{
          if(pw = getpwnam(optarg)){
            moption.uid = pw->pw_uid;
            moption.gid = pw->pw_gid;
          }
        }
        break;

      case 'g':
        if(*optarg >= '0' && *optarg <='9'){
          moption.gid = atoi(optarg);
        }else{
         if(gr = getgrnam(optarg)){
            moption.gid = gr->gr_gid;
          }
        }
        break;

      case 'b':
        realpath(optarg, moption.base_dir);
        break;

      case 'm':
        moption.maddr.sin_addr.s_addr = inet_addr(optarg);
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

      case '?':
        exit(1);
    }
  }
  if(pw=getpwuid(moption.uid)){
    strcpy(moption.user_name, pw->pw_name);
  }
  if(gr=getgrgid(moption.gid)){
    strcpy(moption.group_name,gr->gr_name);
  }
}

static void minit_syslog()
{
  openlog("makuosan", LOG_NDELAY, LOG_DAEMON);
}

static void minit_socket()
{
  int  s;
  int  reuse =  1;
  char lpen  =  0;
  char mttl  =  1;
  struct ip_mreq mg;
  struct sockaddr_in addr;
  mg.imr_multiaddr.s_addr = moption.maddr.sin_addr.s_addr;
  mg.imr_interface.s_addr = INADDR_ANY;
  addr.sin_family         = AF_INET;
  addr.sin_port           = moption.maddr.sin_port; 
  addr.sin_addr.s_addr    = INADDR_ANY;

  s=socket(AF_INET, SOCK_DGRAM, 0);
  if(s == -1){
    lprintf(0, "minit_socket: can't create multicast socket\n");
    exit(1);
  }
  if(bind(s, (struct sockaddr*)&addr, sizeof(addr)) == -1){
    lprintf(0, "minit_socket: bind error\n");
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mg, sizeof(mg)) == -1){
    lprintf(0, "minit_socket: IP_ADD_MEMBERSHIP error\n");
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,   (void *)&mg.imr_interface.s_addr, sizeof(mg.imr_interface.s_addr)) == -1){
    lprintf(0, "minit_socket: IP_MULTICAST_IF error\n");
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (void *)&lpen, sizeof(lpen)) == -1){
    lprintf(0, "minit_socket: IP_MULTICAST_LOOP error\n");
    exit(1);
  }
  if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,  (void *)&mttl, sizeof(mttl)) == -1){
    lprintf(0, "minit_socket: IP_MULTICAST_TTL error\n");
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
      lprintf(0, "minit_console: can't create %s\n", moption.uaddr.sun_path);
      exit(1);
    }
    close(s);
    unlink(moption.uaddr.sun_path);
    s=socket(AF_UNIX,SOCK_STREAM,0);
    if(s == -1){
      lprintf(0, "minit_console: can't create listen socket\n");
      exit(1);
    }
    if(bind(s, (struct sockaddr*)&moption.uaddr, sizeof(moption.uaddr)) == -1){
      lprintf(0, "minit_console: bind error\n");
      exit(1);
    }
    chmod(moption.uaddr.sun_path , S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
    chown(moption.uaddr.sun_path , moption.uid, moption.gid);
  }else{
    s=socket(AF_INET,SOCK_STREAM,0);
    if(s == -1){
      lprintf(0, "minit_console: can't create listen socket\n");
      exit(1);
    }
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(reuse)) == -1){
      lprintf(0, "minit_console: SO_REUSEADDR error\n");
      exit(1);
    }
    if(bind(s, (struct sockaddr*)&moption.laddr, sizeof(moption.laddr)) == -1){
      lprintf(0, "minit_console: bind error\n");
      exit(1);
    }
  }
  if(listen(s,5) == -1){
    lprintf(0, "minit_console: listen error\n");
    exit(1);
  }
  moption.lisocket = s;
}

static void minit_chdir()
{
  if(chdir(moption.base_dir) == -1){
    lprintf(0, "minit_chdir: can't chdir %s\n", moption.base_dir);
    exit(1);
  }
  getcwd(moption.real_dir, PATH_MAX);
}

static void minit_chroot()
{
  if(moption.chroot){
    tzset();
    sprintf(TZ,"%s%d",tzname[0],timezone/3600);
    setenv("TZ",TZ,0);
    if(chroot(moption.base_dir) == -1){
      lprintf(0, "minit_chroot: can't chroot %s\n", moption.base_dir);
      exit(0);
    }
  }
  getcwd(moption.base_dir, PATH_MAX);
}

static void minit_setguid()
{
  if(setguid(moption.uid, moption.gid) == -1){
    lprintf(0, "minit_setguid: can't setguid %d:%d\n", moption.uid, moption.gid);
    exit(0);
  }
}

static void minit_daemonize()
{
  int pid;
  if(moption.dontfork)
    return;

  pid = fork();
  if(pid == -1){
    lprintf(0,"minit_daemonize: can't fork()\n");
    exit(1); 
  }
  if(pid)
    _exit(0);
  setsid();
  pid=fork();
  if(pid == -1){
    lprintf(0,"minit_daemonize: can't fork()\n");
    exit(1); 
  }
  if(pid)
    _exit(0);

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
  char *yesno[2]={"No","Yes"};
  lprintf(0,"makuosan version %s\n",MAKUOSAN_VERSION);
  lprintf(0,"loglevel  : %d\n", moption.loglevel);
if(moption.chroot)
  lprintf(0,"chroot    : %s\n", moption.real_dir);
  lprintf(0,"base dir  : %s\n", moption.base_dir);
  lprintf(0,"multicast : %s\n", inet_ntoa(moption.maddr.sin_addr));
  lprintf(0,"port      : %d\n", ntohs(moption.maddr.sin_port));
  lprintf(0,"uid       : %d\n", geteuid());
  lprintf(0,"gid       : %d\n", getegid());
  lprintf(0,"don't recv: %s\n", yesno[moption.dontrecv]);
  lprintf(0,"don't send: %s\n", yesno[moption.dontsend]);
  lprintf(0,"don't fork: %s\n", yesno[moption.dontfork]);
  lprintf(0,"encrypt   : %s\n", yesno[moption.cryptena]);
  lprintf(0,"console   : %s\n", yesno[moption.comm_ena]);
  lprintf(0,"passwoed  : %s\n", yesno[moption.commpass]);
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
 *  main関数から呼び出される
 */
void minit(int argc, char *argv[])
{
  minit_option_setdefault(); /* 各オプションのデフォルト値を設定 */
  minit_option_getenv();     /* 環境変数からオプションを読み込む */
  minit_getopt(argc, argv);  /* コマンドラインパラメータを解析   */
  minit_syslog();            /* syslogの使用を開始(openlog)      */
  minit_socket();            /* マルチキャストソケットの初期化   */
  minit_console();           /* コンソールソケットの初期化       */
  minit_signal();            /* シグナルハンドラを設定           */
  minit_chdir();             /* カレントディレクトリを変更       */
  minit_chroot();            /*                                  */
  minit_setguid();           /*                                  */
  minit_daemonize();         /*                                  */
  minit_bootlog();           /* ブートメッセージを出力する       */
}



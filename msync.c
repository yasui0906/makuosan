/*
 * msync.c
 * Copyright (C) 2008 KLab Inc. 
 */
#include "makuosan.h"

typedef struct msyncdata
{
  int s;                /* */
  int loopflag;         /* */
  int loglevel;         /* */
  int sendflag;         /* */
  int delflag;          /* */
  int grpflag;          /* */
  char scfile[256];     /* */
  char passwd[256];     /* */
  char target[256];     /* */
  char mcmd[256];       /* */
  char mopt[256];       /* */
  char sopt[256];       /* */
  char path[PATH_MAX];  /* */
  excludeitem *exclude; /* */
} msyncdata;

void usage()
{
  printf("msync version %s (CLI for makuosan)\n", PACKAGE_VERSION);
  printf("usage: msync [OPTION] [FILENAME]\n");
  printf("\n");
  printf("  OPTION\n");
  printf("    --status            # show makuosan status\n");
  printf("    --members           # show makuosan members\n");
  printf("    --check             # file check use md5\n");
  printf("    --delete            # \n");
  printf("    --sync              # \n");
  printf("    --exclude=PATTERN   # \n"); 
  printf("    --exclude-from=FILE # \n");
  printf("\n");
  printf("    -l LOGLEVEL(0-9)    # log level select. default=0\n");
  printf("    -c MSYNC_TARGET     # \n");
  printf("    -f SCRIPT_FILE      # \n");
  printf("    -t HOSTNAME         # distnation hostname\n");
  printf("    -v                  # log level increment\n");
  printf("    -n                  # dry run\n");
  printf("    -r                  # recurse into directories\n");
  printf("\n");
  printf("  MSYNC_TARGET\n");
  printf("    tcp:HOST:PORT  ex) tcp:127.0.0.1:5000\n");
  printf("    unix:SOCKET    ex) unix:makuosan.sock\n");
  printf("\n");
  printf("  SCRIPT_FILE\n");
  printf("    (It writes later)\n");
  printf("\n");
}

excludeitem *add_exclude(msyncdata *md, char *pattern)
{
  excludeitem *item = malloc(sizeof(excludeitem));
  item->pattern = malloc(strlen(pattern) + 1);
  strcpy(item->pattern, pattern);
  item->prev = NULL;
  item->next = NULL;
  if(md->exclude){
    md->exclude->prev = item;
    item->next = md->exclude;
  }
  md->exclude = item;
  return(item);
}

int connect_socket_tcp(char *host, char *port)
{
  int s;
  struct addrinfo hint;
  struct addrinfo *res;
  if(!host || !port){
    return(-1);
  }
  memset(&hint, 0, sizeof(struct addrinfo));
  hint. ai_family  = AF_INET;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = IPPROTO_TCP;
  if(getaddrinfo(host, port, &hint, &res)){
    return(-1);
  }
  if(!res){
    return(-1);
  }
  s = socket(AF_INET, SOCK_STREAM, 0);
  if(s == -1){
    freeaddrinfo(res);
    return(-1);
  }
  if(connect(s, res->ai_addr, res->ai_addrlen) == -1){
    freeaddrinfo(res);
    close(s);
    return(-1);
  }
  freeaddrinfo(res);
  return(s);  
}

int connect_socket_unix(char *path)
{
  int s;
  struct sockaddr_un sa;
  if(!path){
    return(-1);
  }
  if(strlen(path) >= sizeof(sa.sun_path)){
	  return(-1);
  }
  s = socket(AF_UNIX, SOCK_STREAM, 0);
  if(s == -1){
    return(-1);
  }
  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path,path);
  if(connect(s, (struct sockaddr *)&sa, sizeof(sa)) == -1){
    close(s);
    return(-1);
  }
  return(s);
}

int connect_socket(char *target)
{
  char *h;
  char *p;
  char buff[256];

  strcpy(buff, target);
  p = strtok(buff,":");
  if(!p){
    usage();
    exit(1);
  }
  if(!strcmp(p, "tcp")){
    h = strtok(NULL,":");
    p = strtok(NULL,":");
    return(connect_socket_tcp(h,p));
  }
  if(!strcmp(p, "unix")){
    p = strtok(NULL,":");
    return(connect_socket_unix(p));
  }
  return(connect_socket_unix(buff));
}

int writeline(int s, char *buff)
{
  int r; 
  int clen;
  int size;

  clen = strlen(buff);
  size = clen;
  while(size){
    r = write(s, buff + clen - size, size);
    if(r == -1){
      return(-1);
    }
    size -= r;
  }
  return(0);
}

int check_prompt(int s, char *buff, char *passwd)
{
  if(!strcmp(buff, "> ")){
    return(1);
  }
  if(!strcmp(buff, "password: \x1b]E") && passwd){
    writeline(s, passwd);
    writeline(s, "\r\n");
    return(2);
  }
  return(0);
}

int readline(int s, char *buff, int size, int prompt, char *passwd)
{
  char  d = 0;
  char *p = buff;

  while(p < buff + size){
    *p = 0;
    if(prompt){
      switch(check_prompt(s, buff, passwd)){
        case 1:
          return(-2);
        case 2:
          p = buff;
          continue;
      }
    }
    switch(read(s, &d, 1)){
      case 0:
        return(p - buff);
      case -1:
        return(-1);
        break;
      default:
        if(d == '\r'){
          break;
        }
        if((d == '\n') && (p != buff)){
          return(p - buff);
        }
        *(p++) = d;
        break;
    }
  }
  return(-1); /* over flow */
}

int wait_prompt(int s, char *passwd, int view, int *line){
  int  r;
  char buff[8192];
  while(r = readline(s, buff, sizeof(buff), 1, passwd)){
    if(r == -1){
      /* read error */
      r = -1;
      break;
    }
    if(r == -2){
      /* return prompt */
      r = 1;
      break;
    }
    if(!strcmp(buff, "alive")){
      continue;
    }
    if(line){
      (*line)++;
    }
    if(view){
      if(!memcmp(buff, "error:", 6)){
        fprintf(stderr, "%s\n", buff);
      }else{
        fprintf(stdout, "%s\n", buff);
      }
    }
  }
  return(r);
} 

int makuo(int s, char *c, int view)
{
  int  r;
  int  line = 1;
  char buff[256];
  if(sizeof(buff) < strlen(c) + 2){
    fprintf(stderr, "error: command too long\n");
    return(-1);
  }
  sprintf(buff, "%s\r\n", c);
  if(writeline(s, buff) == -1){
    fprintf(stderr, "error: can't write socket\n");
    return(-1);
  }
  r = wait_prompt(s, NULL, view, &line);
  if(r == -1){
    fprintf(stderr, "error: can't read socket\n");
    return(-1);
  }
  if(r == 0){
    return(0);
  }
  return(line);
}

void makuo_aliveon(msyncdata *md)
{
  int r;
  char cmd[256];
  struct timeval tv;
  sprintf(cmd, "alive on");
  r = makuo(md->s, cmd, 0);
  if(r == 0){
    exit(1);
  }
  if(r == -1){
    exit(1);
  }
  if(r == 1){
    tv.tv_sec  = 30;
    tv.tv_usec = 0;
  }else{
    tv.tv_sec  = 0;
    tv.tv_usec = 0;
  }
  setsockopt(md->s, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
}

void makuo_log(msyncdata *md)
{
  int r;
  char cmd[256];
  sprintf(cmd, "loglevel %d", md->loglevel);
  r = makuo(md->s, cmd, 0);
  if(r == 0){
    fprintf(stderr, "error: remote close\n");
    exit(1);
  }
  if(r == -1){
    exit(1);
  }
}

void makuo_exclude(msyncdata *md)
{
  int r;
  char cmd[1024];
  excludeitem *item;
  for(item=md->exclude;item;item=item->next){
    sprintf(cmd, "exclude add %s", item->pattern);
    r = makuo(md->s, cmd, 0);
    if(r == 0){
      fprintf(stderr, "error: makuosan remote close. (%s)\n", cmd);
      exit(1);
    }
    if(r == -1){
      fprintf(stderr, "error: makuosan socket error. (%s)\n", cmd);
      exit(1);
    }
  }
}

int makuo_exec(int s, char *cmd)
{ 
  int r = makuo(s, cmd, 1);
  if(r == 0){
    fprintf(stderr, "error: makuosan remote close. (%s)\n", cmd);
    return(1);
  }
  if(r == -1){
    fprintf(stderr, "error: makuosan socket error. (%s)\n", cmd);
    return(1);
  }
  return(0);
}

void makuo_send(msyncdata *md)
{
  char cmd[1024];
  if(md->delflag){
    sprintf(cmd, "dsync%s %s", md->mopt, md->path);
    if(makuo_exec(md->s, cmd)){
      close(md->s);
      exit(1);
    }
  }
  if(md->sendflag){
    sprintf(cmd, "%s%s%s %s", md->mcmd, md->mopt, md->sopt, md->path);
  }else{
    sprintf(cmd, "%s%s %s", md->mcmd, md->mopt, md->path);
  }
  if(makuo_exec(md->s, cmd)){
    close(md->s);
    exit(1);
  }
}

int makuo_quit(msyncdata *md)
{ 
  int r = makuo(md->s, "quit", 0);
  close(md->s);
  if(r == 0){
    return(0); /* success */
  }
  if(r == -1){
    return(1);
  }
  fprintf(stderr, "quit error?!\n");
  return(1);
}

int exclude_from(msyncdata *md, char *filename)
{
  int  f;
  int  r;
  char line[256];

  if(!strcmp(filename, "-")){
    f = dup(0);
  }else{
    f = open(filename, O_RDONLY);
  }
  if(f == -1){
    fprintf(stderr,"can't open: %s\n", filename);
    return(1);
  }
  while(r = readline(f, line, sizeof(line), 0, NULL)){
    if(r == -1){
      fprintf(stderr, "file read error: %s\n", filename);
      close(f);
      return(1);
    }
    if((*line != '\r') && (*line != '\n') && (*line !=0)){
      add_exclude(md, line);
    }
  }
  close(f);
  return(0);
}

int makuo_file(msyncdata *md)
{
  int  f;
  int  r;
  char line[256];
  char *filename;

  filename = md->scfile;
  if(!strlen(filename)){
    return(0);
  }
  if(!strcmp(filename, "-")){
    /* f = stdin */
    f = dup(0);
  }else{
    f = open(filename, O_RDONLY);
  }
  if(f == -1){
    fprintf(stderr,"can't open: %s\n", filename);
    return(1);
  }

  /* command read loop */
  while(r = readline(f, line, sizeof(line), 0, NULL)){
    if(r == -1){
      fprintf(stderr, "file read error: %s\n", filename);
      break;
    }
    if(makuo_exec(md->s, line)){
      close(f);
      exit(1);
    }
  }
  close(f);
  return(1);
}

int loadpass(char *filename, char *passwd, int size)
{
  int f;

  f = open(filename, O_RDONLY);
  if(f == -1){
    fprintf(stderr, "file open error %s\n", filename);
    return(-1);
  }
  if(readline(f, passwd, size, 0, NULL) == -1){
    fprintf(stderr, "file read error %s\n", filename);
    close(f);
    return(-1);
  }
  close(f);
  return(0);
}

void get_envopt(msyncdata *md)
{
  char *p;
  if(p = getenv("MSYNC_TARGET")){
    if(strlen(p) < sizeof(md->target)){
      strcpy(md->target, p);
    }else{
      fprintf(stderr, "MSYNC_TARGET too long. %s\n");
      exit(1);
    }
  }
}

struct option *optinit()
{
  static struct option longopt[9];
  longopt[0].name    = "help";
  longopt[0].has_arg = 0;
  longopt[0].flag    = NULL;
  longopt[0].val     = 'h';
  longopt[1].name    = "status";
  longopt[1].has_arg = 0;
  longopt[1].flag    = NULL;
  longopt[1].val     = 'S';
  longopt[2].name    = "members";
  longopt[2].has_arg = 0;
  longopt[2].flag    = NULL;
  longopt[2].val     = 'M';
  longopt[3].name    = "check";
  longopt[3].has_arg = 0;
  longopt[3].flag    = NULL;
  longopt[3].val     = 'C';
  longopt[4].name    = "exclude";
  longopt[4].has_arg = 1;
  longopt[4].flag    = NULL;
  longopt[4].val     = 'E';
  longopt[5].name    = "exclude-from";
  longopt[5].has_arg = 1;
  longopt[5].flag    = NULL;
  longopt[5].val     = 'F';
  longopt[6].name    = "delete";
  longopt[6].has_arg = 0;
  longopt[6].flag    = NULL;
  longopt[6].val     = 'D';
  longopt[7].name    = "sync";
  longopt[7].has_arg = 0;
  longopt[7].flag    = NULL;
  longopt[7].val     = 'd';
  longopt[8].name    = NULL;
  longopt[8].has_arg = 0;
  longopt[8].flag    = NULL;
  longopt[8].val     = 0;
  return(longopt);
}

void parse_opt(int argc, char *argv[], struct option *opt, msyncdata *md)
{
  int r;
  while((r = getopt_long(argc, argv, "g:c:f:t:K:l:hvrn", opt, NULL)) != -1){
    switch(r){
      case 'h':
        usage();
        exit(0);

      case 'D':
        md->delflag = 1;
        break;

      case 'd':
        strcpy(md->mcmd, "sync");
        break;

      case 'S':
        strcpy(md->mcmd, "status");
        md->loopflag = 0;
        md->sendflag = 0;
        break;

      case 'M':
        strcpy(md->mcmd, "members");
        md->loopflag = 0;
        md->sendflag = 0;
        break;

      case 'C':
        strcpy(md->mcmd, "check");
        md->sendflag = 0;
        break;

      case 'E':
        add_exclude(md, optarg);
        break;

      case 'F':
        if(exclude_from(md, optarg)){
          exit(1);
        }
        break;

      case 'r':
        strcat(md->mopt," -r");
        break;

      case 'n':
        strcat(md->mopt," -n");
        break;

      case 't':
        strcat(md->mopt," -t ");
        strcat(md->mopt,optarg);
        break;

      case 'g':
        md->grpflag = 1;
        strcat(md->sopt," -g ");
        strcat(md->sopt,optarg);
        break;

      case 'v':
        md->loglevel++;
        break;

      case 'l':
        md->loglevel = atoi(optarg);
        break;

      case 'f':
        if(strlen(optarg) < sizeof(md->scfile)){
          strcpy(md->scfile, optarg);
        }else{
          fprintf(stderr, "filename too long\n");
          exit(1);
        }
        break;

      case 'c':
        if(strlen(optarg) < sizeof(md->target)){
          strcpy(md->target, optarg);
        }else{
          fprintf(stderr, "target too long\n");
          exit(1);
        }
        break;

      case 'K':
        if(loadpass(optarg, md->passwd, sizeof(md->passwd)) == -1){
          exit(1);
        }
        break;

      case '?':
        usage();
        exit(1);
        break;
    }
  }
  if(md->delflag && !md->sendflag){
    usage();
    exit(1);
  }
  if(md->grpflag && !md->sendflag){
    usage();
    exit(1);
  }
  if(argc == optind){
    md->loopflag = 0;
  }
}

int connect_wait(msyncdata *md)
{
  int r;
  r = wait_prompt(md->s, md->passwd, 0, NULL);
  if(r == 0){
    fprintf(stderr, "remote socket close\n");
    return(1);
  }
  if(r == -1){
    fprintf(stderr, "socket read error\n");
    return(1);
  }
  return(0);
}

void connect_target(msyncdata *md)
{
  struct timeval tv;
  md->s = connect_socket(md->target);
  if(md->s == -1){
    fprintf(stderr, "can't connect %s\n", md->target);
    exit(1);
  }
  tv.tv_sec  = 5;
  tv.tv_usec = 0;
  setsockopt(md->s, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
  if(connect_wait(md)){
    close(md->s);
    exit(1);
  } 
}

void msync_init(msyncdata *md)
{
  memset(md, 0, sizeof(msyncdata));
  md->loopflag = 1;
  md->sendflag = 1;
  strcpy(md->mcmd, "send");
  strcpy(md->target, "tcp:127.0.0.1:5000");
}

int main(int argc, char *argv[])
{
  int i;
  msyncdata md;

  if(argc == 1){
    usage();
    exit(1);
  }

  msync_init(&md);
  get_envopt(&md);
  parse_opt(argc, argv, optinit(), &md);
  connect_target(&md);

  makuo_aliveon(&md);
  makuo_log(&md);
  makuo_exclude(&md);

  if(!makuo_file(&md)){
    if(!md.loopflag){
      md.path[0] = 0;
      makuo_send(&md);
    }else{
      for(i=optind;i<argc;i++){
        strcpy(md.path, argv[i]);
        makuo_send(&md);
      }
    }
  }
  return(makuo_quit(&md));
}


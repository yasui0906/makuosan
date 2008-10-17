#include "makuosan.h"

void usage()
{
  printf("usage: makuo [-v] [-c TARGET] [-K PASSWORDFILE] COMMAND [OPT] \n");
  printf("       makuo [-v] [-c TARGET] [-K PASSWORDFILE] -f SCRIPT_FILE\n");
  printf("\n");
  printf("  TARGET\n");
  printf("    tcp:HOST:PORT     ex) tcp:127.0.0.1:5000\n");
  printf("    unix:SOCKET       ex) tcp:/tmp/makuo.sock\n");
  printf("\n");
  printf("  COMMAND\n");
  printf("    send [-n] [-r] [-t HOST] [FILENAME]\n");
  printf("    md5  [-r] [FILENAME]\n");
  printf("    status\n");
  printf("    members\n");
  exit(0);
}

int connect_socket_tcp()
{
  char *p;
  char host[256];
  char port[128];
  struct sockaddr_in sa;
  struct hostent *hn;

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if(s == -1){
    return(-1);
  }
  p = strtok(NULL,":");
  if(!p){
    close(s);
    return(-1);
  }
  strcpy(host, p);
  p = strtok(NULL,":");
  if(!p){
    close(s);
    return(-1);
  }
  strcpy(port, p);
  sa.sin_family = AF_INET;
  sa.sin_port   = htons(atoi(port));
  if(!inet_aton(host, &(sa.sin_addr))){
    if(hn = gethostbyname(host)){
      memcpy(&(sa.sin_addr), hn->h_addr_list[0], hn->h_length);
    }else{
      close(s);
      fprintf(stderr,"not found %s\n", host);
      return(-1);
    }
  }
  if(connect(s, (struct sockaddr *)&sa, sizeof(sa)) == -1){
    close(s);
    fprintf(stderr,"connect error tcp:%s:%s\n", host, port);
    return(-1);
  }
  return(s);  
}

int connect_socket_unix()
{
  char *p;
  struct sockaddr_un sa;
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if(s != -1){
    p = strtok(NULL,":");
    if(!p){
      close(s);
      return(-1);
    }
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, p);
    if(connect(s, (struct sockaddr *)&sa, sizeof(sa)) == -1){
      fprintf(stderr, "can't connect %s\n", sa.sun_path);
      close(s);
      return(-1);
    }
  }
  return(s);
}

int connect_socket(char *target)
{
  char buff[256];
  char *p = buff;

  strcpy(buff, target);
  p = strtok(buff,":");
  if(!p){
    usage();
  }
  if(!strcmp(p, "tcp")){
    return(connect_socket_tcp());
  }
  if(!strcmp(p, "unix")){
    return(connect_socket_unix());
  }
  fprintf(stderr,"can't connect %s\n", target);
  return(-1);
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

int readline(int s, char *buff, int size, int prompt, char *passwd)
{
  int   c = 0;
  int   r = 0;
  char  d = 0;
  char *p = buff;
  fd_set fds;
  struct timeval tv;

  while(c < size){
    FD_ZERO(&fds);
    FD_SET(s,&fds);
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    if(select(1024, &fds, NULL, NULL, &tv) < 0){
      continue;
    }
    r = read(s, &d, 1);
    if(r == -1){
      return(-1);
    }
    if(r == 0){
      *p = 0;
      return(0);
    }
    if(d == '\r'){
      continue;
    }
    if(d == '\n'){
      *p = 0;
      return(c);
    }
    *(p++) = d;
    c++;
    if(c < size){ 
      *p = 0;
      if(prompt && !strcmp(buff, "> ")){
        return(-2);
      }
      if(prompt && !strcmp(buff, "password: \x1b]E") && passwd){
        writeline(s, passwd);
        writeline(s, "\r\n");
        c = 0;
        p = buff;
      }
    }
  }
  return(-1);
}

int wait_prompt(int s, char *passwd){
  int  r;
  char buff[1024];

  while(r = readline(s, buff, sizeof(buff), 1, passwd)){
    if(r == -1){
      /* read error */
      return(-1);
    }
    if(r == -2){
      /* return prompt */
      return(1);
    }
    fprintf(stderr, "%s\n", buff);
  }
  return(0);
} 

int makuo(int s, char *c)
{
  char buff[256];
  sprintf(buff, "%s\r\n", c);
  if(writeline(s, buff) == -1){
    fprintf(stderr, "write error\n");
    return(-1);
  }
  wait_prompt(s, NULL);
  return(0);
}

int fromfile(int s, char *filename)
{
  int  f;
  int  r;
  char line[256];

  if(!strcmp(filename, "-")){
    /* f = stdin */
    f = 0;
  }else{
    f = open(filename, O_RDONLY);
    if(f == -1){
      fprintf(stderr,"can't open: %s\n", filename);
      return(-1);
    }
  }

  while(r = readline(f, line, sizeof(line), 0, NULL)){
    if(r == -1){
      fprintf(stderr, "file read error: %s\n", filename);
      break;
    }
    r = makuo(s, line);
    if(r == -1){
      fprintf(stderr, "makuo error\n");
      break;
    }
  }
  close(f);
  return(r);
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

void defaulttarget(char *target)
{
  char *p;
  if(p = getenv("MAKUO_TARGET")){
    strcpy(target, p);
  }else{
    strcpy(target, "tcp:127.0.0.1:5000");
  }
}

int fromargv(int s, int argc, char *argv[], int start)
{
  int  i;
  char cmd[256];

  cmd[0] = 0;
  for(i=start;i<argc;i++){
    if(cmd[0]){
      strcat(cmd, " ");
    }
    strcat(cmd, argv[i]);
  }
  return(makuo(s, cmd));
}


int main(int argc, char *argv[])
{
  int r;
  int s;
  char cmd[256];

  /* option */
  int loglevel = 0;
  char scfile[256];
  char passwd[256];
  char target[256];

  /* default */
  scfile[0] = 0;
  passwd[0] = 0;
  defaulttarget(target);

  while((r = getopt(argc, argv, "+c:f:K:hv")) != -1){
    switch(r){
      case 'h':
        usage();
      case 'v':
        loglevel++; 
        break;
      case 'f':
        strcpy(scfile, optarg);
        break;
      case 'c':
        strcpy(target, optarg);
        break;
      case 'K':
        if(loadpass(optarg, passwd, sizeof(passwd)) == -1){
          return(1);
        }
        break;
    }
  }

  if(!scfile[0] && optind == argc){
    usage();
  }

  s = connect_socket(target);
  if(s == -1){
    return(1);
  }
  r = wait_prompt(s, passwd);

  if(r == 1){
    sprintf(cmd, "loglevel %d", loglevel);
    makuo(s, cmd);
    if(scfile[0]){
      r = fromfile(s, scfile);
    }else{
      r = fromargv(s, argc, argv, optind);
    }
    makuo(s, "quit");
  }
  close(s);
  return(r);
}


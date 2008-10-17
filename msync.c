#include "makuosan.h"

void usage()
{
  printf("usage: makuo [-c TARGET] COMMAND [OPT]...\n");
  printf("       makuo [-c TARGET] -f SCRIPT_FILE\n");
  printf("\n");
  printf("  TARGET\n");
  printf("    tcp:HOST:PORT     ex) tcp:127.0.0.1:5000\n");
  printf("    unix:SOCKET       ex) tcp:/tmp/makuo.sock\n");
  printf("\n");
  printf("  COMMAND\n");
  printf("    send [-n] [-r] [-t HOST] [FILENAME]\n");
  printf("    md5  [-r] [FILENAME]\n");
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

int main(int argc, char *argv[])
{
  int  i;
  int  r;
  int  f;
  int  s;
  char makuoc[256];
  char target[256];
  char scfile[256];
  struct sockaddr   *sa;
  struct sockaddr_in si;
  struct sockaddr_un su;

  if(argc < 2){
    usage();
  }

  /* option default */
  strcpy(target, "tcp:127.0.0.1:5000");
  scfile[0] = 0;
  makuoc[0] = 0;

  while((r=getopt(argc, argv, "+c:f:h")) != -1){
    switch(r){
      case 'h':
        usage();
      case 'f':
        strcpy(makuoc, optarg);
        break;
      case 'c':
        strcpy(target, optarg);
        break;
    }
  }
  s = connect_socket(target);
  if(s == -1){
    return(1);
  }
  if(scfile[0]){
    if(!strcmp(scfile, "-")){
    }else{
    }
  }else{
    for(i=optind;i<argc;i++){
      if(makuoc[0]){
        strcat(makuoc, " ");
      }
      strcat(makuoc, argv[i]);
    }
    makuo(s, makuoc);
  }
  return(0);
}

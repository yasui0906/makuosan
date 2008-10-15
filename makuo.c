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

int connect_socket(char *target)
{
  char buff[256];
  char *p = buff;
  strcpy(buff, target);
  p = strtok(target,":");
  if(!p){
    usage();
  }
  if(!strcmp(p, "tcp")){
  }
  if(!strcmp(p, "unix")){
  }

  return(0);
} 

int main(int argc, char *argv[])
{
  int  i;
  int  r;
  int  s;
  char cmd[256];
  char target[256];
  struct sockaddr   *sa;
  struct sockaddr_in si;
  struct sockaddr_un su;

  if(argc < 2){
    usage();
  }

  /* option default */
  strcpy(target, "tcp:127.0.0.1:5000");

  while((r=getopt(argc, argv, "c:f:h")) != -1){
    switch(r){
      case 'h':
        usage();
      case 'f':
        break;
      case 'c':
        break;
    }
  }
  s = connect_socket(target);
  if(s == -1){

  }
  return(0);
}



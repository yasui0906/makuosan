#include "makuosan.h"

void usage()
{
  printf("usage: makuo TARGET COMMAND [OPT],,,,,\n");
  printf("\n");
  printf("  TARGET\n");
  printf("    TCP:hostname:port:loglevel      ex) TCP:127.0.0.1:5000:0\n");
  printf("    UNIX:unixdomainsocket:loglevel  ex) UNIX:/tmp/makuosan.sock:0\n");
  printf("\n");
  printf("  COMMAND\n");
  printf("    send [-n] [-r] [-t HOST] [FILENAME]\n");
  printf("    md5  [-r] [FILENAME]\n");
} 

int main(int argc, char *argv[])
{
  int  i;
  char cmd[256];

  if(argc < 2){
    usage();
  }

  return(0);
}

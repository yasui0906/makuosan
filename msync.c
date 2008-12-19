/*
 * msync.c
 * Copyright (C) 2008 KLab Inc. 
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "makuosan.h"

excludeitem *exclude = NULL;

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

excludeitem *add_exclude(char *pattern)
{
  excludeitem *item = malloc(sizeof(excludeitem));
  item->pattern = malloc(strlen(pattern) + 1);
  strcpy(item->pattern, pattern);
  item->prev    = NULL;
  item->next    = NULL;
  if(exclude){
    exclude->prev = item;
    item->next = exclude;
  }
  exclude = item;
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

int wait_prompt(int s, char *passwd){
  int  r;
  char buff[8192];

  while(r = readline(s, buff, sizeof(buff), 1, passwd)){
    if(r == -1){
      /* read error */
      return(-1);
    }
    if(r == -2){
      /* return prompt */
      return(1);
    }
    if(!memcmp(buff, "error:", 6)){
      fprintf(stderr, "%s\n", buff);
    }else{
      fprintf(stdout, "%s\n", buff);
    }
  }
  return(0);
} 

int makuo(int s, char *c)
{
  int  r;
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
  r = wait_prompt(s, NULL);
  if(r == -1){
    fprintf(stderr, "error: can't read socket\n");
    return(-1);
  }
  return(r);
}

int makuo_log(int s, int l)
{
  int r;
  char cmd[256];
  sprintf(cmd, "loglevel %d", l);
  r = makuo(s, cmd);
  if(r == 0){
    fprintf(stderr, "error: remote close\n");
    return(1);
  }
  if(r == -1){
    return(1);
  }
  return(0);
}

int makuo_exclude(int s)
{
  int r;
  char cmd[1024];
  excludeitem *item;
  for(item=exclude;item;item=item->next){
    sprintf(cmd, "exclude add %s", item->pattern);
    r = makuo(s, cmd);
    if(r == 0){
      fprintf(stderr, "error: makuosan remote close. (%s)\n", cmd);
      return(1);
    }
    if(r == -1){
      fprintf(stderr, "error: makuosan socket error. (%s)\n", cmd);
      return(1);
    }
  }
  return(0);
}


int makuo_exec(int s, char *cmd)
{ 
  int r = makuo(s, cmd);
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

int makuo_quit(int s)
{ 
  int r = makuo(s, "quit");
  close(s);
  if(r == 0){
    return(0); /* success */
  }
  if(r == -1){
    return(1);
  }
  fprintf(stderr, "quit error?!\n");
  return(1);
}

int exclude_from(char *filename)
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
      add_exclude(line);
    }
  }
  close(f);
  return(0);
}

int fromfile(int s, char *filename)
{
  int  f;
  int  r;
  char line[256];

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
      close(f);
      return(1);
    }
    if(makuo_exec(s, line)){
      close(f);
      return(1);
    }
  }
  close(f);
  return(makuo_quit(s));
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

void defaulttarget(char *target, int size)
{
  char *p = getenv("MSYNC_TARGET");
  strcpy(target, "tcp:127.0.0.1:5000");
  if(p && (strlen(p) < size)){
    strcpy(target, p);
  }
}

int main(int argc, char *argv[])
{
  int i;
  int r;
  int s;

  if(argc == 1){
    usage();
    return(1);
  }

  /* makuo command */
  char cmd[1024];
  char mcmd[256];
  char mopt[256];
  char sopt[256];
  strcpy(mcmd,"send");
  strcpy(mopt,"");
  strcpy(sopt,"");

  /* option */
  int loopflag = 1;
  int loglevel = 0;
  int sendflag = 1;
  int delflag  = 0;
  int grpflag  = 0;
  char scfile[256];
  char passwd[256];
  char target[256];

  /* long option */
  struct option longopt[8];
  memset(longopt, 0, sizeof(longopt));
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

  /* default */
  scfile[0] = 0;
  passwd[0] = 0;
  defaulttarget(target, sizeof(target));

  while((r = getopt_long(argc, argv, "g:c:f:t:K:l:hvrn", longopt, NULL)) != -1){
    switch(r){
      case 'h':
        usage();
        return(0);

      case 'D':
        delflag = 1;
        break;

      case 'd':
        strcpy(mcmd, "sync");
        break;

      case 'S':
        strcpy(mcmd, "status");
        loopflag = 0;
        sendflag = 0;
        break;

      case 'M':
        strcpy(mcmd, "members");
        loopflag = 0;
        sendflag = 0;
        break;

      case 'C':
        strcpy(mcmd, "check");
        sendflag = 0;
        break;

      case 'E':
        add_exclude(optarg);
        break;

      case 'F':
        if(exclude_from(optarg)){
          return(1);
        }
        break;

      case 'r':
        strcat(mopt," -r");
        break;

      case 'n':
        strcat(mopt," -n");
        break;

      case 't':
        strcat(mopt," -t ");
        strcat(mopt,optarg);
        break;

      case 'g':
        grpflag = 1;
        strcat(sopt," -g ");
        strcat(sopt,optarg);
        break;

      case 'v':
        loglevel++;
        break;

      case 'l':
        loglevel = atoi(optarg);
        break;

      case 'f':
        if(strlen(optarg) < sizeof(scfile)){
          strcpy(scfile, optarg);
        }else{
          fprintf(stderr, "filename too long\n");
          return(1);
        }
        break;

      case 'c':
        if(strlen(optarg) < sizeof(target)){
          strcpy(target, optarg);
        }else{
          fprintf(stderr, "target too long\n");
          return(1);
        }
        break;

      case 'K':
        if(loadpass(optarg, passwd, sizeof(passwd)) == -1){
          return(1);
        }
        break;

      case '?':
        usage();
        return(1);
        break;
    }
  }

  if(delflag && !sendflag){
    usage();
    return(1);
  }

  if(grpflag && !sendflag){
    usage();
    return(1);
  }

  s = connect_socket(target);
  if(s == -1){
    fprintf(stderr, "can't connect %s\n", target);
    return(1);
  }

  r = wait_prompt(s, passwd);
  if(r == 0){
    fprintf(stderr, "remote socket close\n");
    close(s);
    return(1);
  }

  if(r == -1){
    fprintf(stderr, "socket read error\n");
    close(s);
    return(1);
  }

  if(makuo_log(s, loglevel)){
    close(s);
    return(1);
  }

  if(makuo_exclude(s)){
    close(s);
    return(1);
  }

  if(scfile[0]){
    return(fromfile(s, scfile));
  }

  if(loopflag && (optind < argc)){
    for(i=optind;i<argc;i++){
      if(delflag){
        sprintf(cmd, "dsync%s %s", mopt, argv[i]);
        if(makuo_exec(s, cmd)){
          close(s);
          return(1);
        }
      }
      sprintf(cmd, "%s%s%s %s", mcmd, mopt, sopt, argv[i]);
      if(makuo_exec(s, cmd)){
        close(s);
        return(1);
      }
    }
  }else{
    if(delflag){
      sprintf(cmd, "dsync%s", mopt);
      for(i=optind;i<argc;i++){
        strcat(cmd, " ");
        strcat(cmd, argv[i]);
      }
      if(makuo_exec(s, cmd)){
        close(s);
        return(1);
      }
    }
    sprintf(cmd, "%s%s%s", mcmd, mopt, sopt);
    for(i=optind;i<argc;i++){
      strcat(cmd, " ");
      strcat(cmd, argv[i]);
    }
    if(makuo_exec(s, cmd)){
      close(s);
      return(1);
    }
  }
  return(makuo_quit(s));
}


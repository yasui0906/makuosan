/*
 * msync.c
 * Copyright (C) 2008 KLab Inc. 
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
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

void usage()
{
  printf("usage: msync [-l loglevel] [-c TARGET] [-K PASSWORDFILE] COMMAND [OPT] \n");
  printf("       msync [-l loglevel] [-c TARGET] [-K PASSWORDFILE] -f SCRIPT_FILE\n");
  printf("\n");
  printf("  TARGET\n");
  printf("    tcp:HOST:PORT     ex) tcp:127.0.0.1:5000\n");
  printf("    unix:SOCKET       ex) unix:makuosan.sock\n");
  printf("\n");
  printf("  COMMAND\n");
  printf("    send [-n] [-r] [-t HOST] [FILENAME]\n");
  printf("    md5  [-r] [FILENAME]\n");
  printf("    status\n");
  printf("    members\n");
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
  hint.ai_family = AF_INET;
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

int makuolog(int s, int l)
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

int makuoquit(int s)
{ 
  int r = makuo(s, "quit");
  if(r == 0){
    return(0); /* success */
  }
  if(r == -1){
    return(1);
  }
  fprintf(stderr, "quit error?!\n");
  return(1);
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
    r = makuo(s, line);
    if(r == 0){
      fprintf(stderr, "error: makuosan remote close\n");
      close(f);
      return(1);
    }
    if(r == -1){
      close(f);
      return(1); /* socket error */
    }
  }

  /* quit */
  return(makuoquit(s));
}

int fromargv(int s, int argc, char *argv[], int start)
{
  int i;
  int r;
  char cmd[256];

  cmd[0] = 0;
  for(i=start;i<argc;i++){
    if(strlen(cmd) + strlen(argv[i]) + 2 > sizeof(cmd)){
      fprintf(stderr, "error: command too long\n");
      return(1);
    }
    if(cmd[0]){
      strcat(cmd, " ");
    }
    strcat(cmd, argv[i]);
  }

  /* command execute */
  r = makuo(s, cmd);
  if(r == 0){
    fprintf(stderr, "error: makuosan remote close\n");
    return(1);
  }
  if(r == -1){
    return(1); /* socket error */
  }

  /* quit */
  return(makuoquit(s));
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
  int r;
  int s;

  /* option */
  int loglevel = 0;
  char scfile[256];
  char passwd[256];
  char target[256];

  /* default */
  scfile[0] = 0;
  passwd[0] = 0;
  defaulttarget(target, sizeof(target));

  while((r = getopt(argc, argv, "+c:f:K:l:h")) != -1){
    switch(r){
      case 'h':
        usage();
        return(0);

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
    }
  }

  if(!scfile[0] && optind == argc){
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

  if(makuolog(s, loglevel)){
    close(s);
    return(1);
  }

  if(scfile[0]){
    r = fromfile(s, scfile);
  }else{
    r = fromargv(s, argc, argv, optind);
  }
  close(s);
  return(r);
}


/* 
 * makuosan.h
 * Copyright (C) 2008 KLab Inc. 
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#define PROTOCOL_VERSION 7
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <utime.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <libgen.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/md5.h>
#include <openssl/blowfish.h>

/*----- limit -----*/
#define MAX_COMM               8
#define MAKUO_PARALLEL_MAX     8
#define MAKUO_BUFFER_SIZE   1024
#define MAKUO_HOSTNAME_MAX   255
#define MAKUO_STATE_MAX      255
#define MAKUO_OPCODE_MAX     255
#define MAKUO_HOSTSTATE_SIZE (MAKUO_PARALLEL_MAX * MAX_COMM * 2)

/*----- default -----*/
#define MAKUO_LOCAL_ADDR  "127.0.0.1"
#define MAKUO_MCAST_ADDR  "224.0.0.108"
#define MAKUO_MCAST_PORT  5000

/*----- timeout -----*/
#define MAKUO_SEND_TIMEOUT  500    /* 再送間隔(ms)                                 */
#define MAKUO_SEND_RETRYCNT 120    /* 再送回数                                     */
#define MAKUO_PONG_TIMEOUT  300000 /* メンバから除外するまでの時間(ms)             */
#define MAKUO_PONG_INTERVAL 45000  /* PONG送信間隔(ms)                             */
#define MAKUO_RECV_GCWAIT   180000 /* 消し損ねたオブジェクトを開放する待ち時間(ms) */

/*----- operation -----*/
#define MAKUO_OP_PING  0
#define MAKUO_OP_EXIT  1
#define MAKUO_OP_SEND  2
#define MAKUO_OP_MD5   3
#define MAKUO_OP_DSYNC 4
#define MAKUO_OP_DEL   5

/*----- flags -----*/
#define MAKUO_FLAG_ACK    1
#define MAKUO_FLAG_CRYPT  2
#define MAKUO_FLAG_DRYRUN 4
#define MAKUO_FLAG_RECURS 8
#define MAKUO_FLAG_SYNC   16

/*----- const -----*/
#define MFSEND 0
#define MFRECV 1

/*----- sendstatus -----*/
#define MAKUO_SENDSTATE_STAT       0  /* 更新確認待 */
#define MAKUO_SENDSTATE_OPEN       1  /* オープン待 */
#define MAKUO_SENDSTATE_DATA       2  /* データ送信 */
#define MAKUO_SENDSTATE_MARK       3  /* 再送確認待 */
#define MAKUO_SENDSTATE_CLOSE      4  /* クローズ待 */
#define MAKUO_SENDSTATE_LAST       5  /* 送信完了   */
#define MAKUO_SENDSTATE_ERROR      6  /* エラー発生 */
#define MAKUO_SENDSTATE_BREAK      7  /* 送信中断   */
#define MAKUO_SENDSTATE_WAIT       8  /* 送信待機   */

/*----- recvstatus -----*/
#define MAKUO_RECVSTATE_NONE       0
#define MAKUO_RECVSTATE_UPDATE     1
#define MAKUO_RECVSTATE_SKIP       2
#define MAKUO_RECVSTATE_OPEN       3
#define MAKUO_RECVSTATE_MARK       4
#define MAKUO_RECVSTATE_CLOSE      5
#define MAKUO_RECVSTATE_IGNORE     6
#define MAKUO_RECVSTATE_READONLY   7
#define MAKUO_RECVSTATE_BREAK      8
#define MAKUO_RECVSTATE_LAST       9
#define MAKUO_RECVSTATE_MD5OK      10
#define MAKUO_RECVSTATE_MD5NG      11
#define MAKUO_RECVSTATE_DELETEOK   12
#define MAKUO_RECVSTATE_DELETENG   13
#define MAKUO_RECVSTATE_OPENERROR  90
#define MAKUO_RECVSTATE_READERROR  91
#define MAKUO_RECVSTATE_WRITEERROR 92
#define MAKUO_RECVSTATE_CLOSEERROR 93

/*----- mexec mode -----*/
#define MAKUO_MEXEC_SEND 0
#define MAKUO_MEXEC_DRY  1
#define MAKUO_MEXEC_MD5  2

/*----- macro -----*/
#ifndef timeradd
#define timeradd(a, b, r)                       \
  do {                                          \
    (r)->tv_sec  = (a)->tv_sec  + (b)->tv_sec;  \
    (r)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
    if ((r)->tv_usec >= 1000000)                \
    {                                           \
      (r)->tv_sec  += 1;                        \
      (r)->tv_usec -= 1000000;                  \
    }                                           \
  }while(0)
#endif

/*----- struct -----*/
typedef struct
{
  uint8_t  vproto;
  uint8_t  opcode;
  uint8_t  nstate;
  uint8_t  ostate;
  uint16_t szdata;
  uint16_t flags;
  uint32_t reqid;
  uint32_t seqno;
  uint32_t maddr;
  uint16_t mport;
  uint32_t error;
  uint8_t  hash[16];
}__attribute__((packed)) mhead;

typedef struct
{
  uint32_t mode;
  uint16_t uid; 
  uint16_t gid;
  uint32_t sizel;
  uint32_t sizeh;
  uint32_t mtime; 
  uint32_t ctime;
  uint16_t fnlen;
  uint16_t lnlen; 
}__attribute__((packed)) mstat;

typedef struct
{
  uint8_t  hash[16];
  uint16_t fnlen;
  uint8_t  filename[0];
}__attribute__((packed)) mhash;

typedef struct
{
  uint16_t hostnamelen;
  uint16_t versionlen;
  uint8_t  data[0];
}__attribute__((packed)) mping;

typedef struct
{
  mhead head;
  uint8_t data[MAKUO_BUFFER_SIZE];
  uint8_t *p;
}__attribute__((packed)) mdata;

typedef struct excludeitem
{
  char *pattern;
  struct excludeitem *prev;
  struct excludeitem *next;
} excludeitem;

typedef struct
{
  int no;
  int cpid;
  int fd[2];
  int size[2];
  int argc[2];
  int check[2];
  int loglevel;
  int working;
  int authchk;
  int isalive;
  int logflag;
  int logover;
  char cmdline[2][MAKUO_BUFFER_SIZE];
  char parse[2][8][MAKUO_BUFFER_SIZE];
  char readbuff[2][MAKUO_BUFFER_SIZE];
  excludeitem *exclude;
  struct timeval tv;
} mcomm;

typedef struct mmark
{
  uint32_t l;
  uint32_t h;
  struct mmark *prev;
  struct mmark *next;
} mmark;

typedef struct mfile
{
  int  fd;
  char fn[PATH_MAX];
  char tn[PATH_MAX];
  char ln[PATH_MAX];
  uint16_t len;
  uint32_t mod;
  uint32_t sendto;
  uint32_t dryrun;
  uint32_t recurs;
  uint32_t retrycnt;
  uint32_t sendwait;
  uint32_t lickflag;
  uint32_t initstate;
  uint32_t recvcount;
  uint32_t markcount;
  uint32_t seqnonow;
  uint32_t seqnomax;
  int pid;
  int pipe;
  mdata mdata;
  mcomm *comm;
  mmark *mark;
  struct stat fs;
  struct sockaddr_in addr;
  struct timeval lastsend;
  struct timeval lastrecv;
  struct mfile *prev;
  struct mfile *next;
  struct mfile *link;
  excludeitem *exclude;
  char cmdline[MAKUO_BUFFER_SIZE];
  MD5_CTX md5;
} mfile;

typedef struct
{
  uint8_t state[MAKUO_HOSTSTATE_SIZE];
  mfile *mflist[MAKUO_HOSTSTATE_SIZE];
  char hostname[MAKUO_HOSTNAME_MAX];
  char version[32];
  struct in_addr ad;
  struct timeval lastrecv;
  void *prev;
  void *next;
} mhost;

typedef struct
{
  int chroot;
  int dontrecv;
  int dontsend;
  int dontfork;
  int loglevel;
  int mcsocket;
  int lisocket;
  int cryptena;
  int comm_ena;
  int commpass;
  int ownmatch;
  int parallel;
  int recvsize;
  int sendsize;
  int sendready;
  int sendrate;
  struct utsname uts;  
  struct sockaddr_in maddr;
  struct sockaddr_in laddr;
  struct sockaddr_un uaddr;
  char base_dir[PATH_MAX];
  char real_dir[PATH_MAX];
  uid_t uid;
  gid_t gid;
  gid_t *gids;
  size_t gidn;
  char group_name[64];
  char user_name[64];
  char grnames[32][64];
  char password[2][16];
  mcomm comm[MAX_COMM];
} mopt;

extern mfile *mftop[2];
extern mfile *mfreeobj;
extern mhost *members;
extern mopt moption;
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;
extern int optreset;
extern int loop_flag;
extern int send_rate;
extern int view_rate;
extern time_t send_time;
extern char *tzname[2];
extern int daylight;
extern char TZ[256];
extern struct timeval curtime;
extern struct timeval lastpong;
extern BF_KEY EncKey;

/*----- report -----*/
char *strsstate(uint8_t n);
char *strrstate(uint8_t n);
char *strmstate(mdata *data);
char *stropcode(mdata *data);
char *strackreq(mdata *data);
void mprintf(int l, const char *func, mfile *m);
void lprintf(int l, char *fmt, ...);
int  cprintf(int l, mcomm *c, char *fmt, ...);
void fdprintf(int s, char *fmt, ...);

/*----- packet data access -----*/
int data_safeget(mdata *data, void *buff, size_t size);
int data_safeget16(mdata *data, uint16_t *buff);
int data_safeget32(mdata *data, uint32_t *buff);
int data_safeset(mdata *data, void *buff, size_t size);
int data_safeset16(mdata *data, uint16_t val);
int data_safeset32(mdata *data, uint32_t val);

/*----- file object operation -----*/
void mfdel(mfile *m);
mfile *mfadd(int n);
mfile *mfins(int n);
mfile *mkreq(mdata *data, struct sockaddr_in *addr, uint8_t state);
mfile *mkack(mdata *data, struct sockaddr_in *addr, uint8_t state);

/*----- exclude functions -----*/
excludeitem *exclude_add(excludeitem *exclude, char *pattern);  /* add list */
excludeitem *exclude_del(excludeitem *e);                       /* del list */
excludeitem *mfnmatch(char *str, excludeitem *exclude);         /* is match */
int isexclude(char *fn, excludeitem *exclude, int dir);         /*          */

/*----- filesystem operation -----*/
int linkcmp(mfile *m);
int statcmp(struct stat *s1, struct stat *s2);
int mremove(char *base, char *name);
int mcreatedir(char  *base, char *name, mode_t mode);
int mcreatefile(char *base, char *name, mode_t mode);
int mcreatelink(char *base, char *name, char *link);
int atomic_read(int fd, void *buff, int size, int nb);
void set_filestat(char *path, uid_t uid, gid_t gid, mode_t mode);

/*----- uid/gid -----*/
int set_guid(uid_t uid, gid_t gid, size_t gidn, gid_t *gids);

/*----- member operation -----*/
void   member_del(mhost *h);
mhost *member_get(struct in_addr *addr);
mhost *member_add(struct in_addr *addr, mdata *recvdata);
void   member_del_message(int err, mhost *t, char *mess);

/*----- mark operation -----*/
mmark   *delmark(mmark *mm);
uint32_t seq_getmark(mfile *m);
void     seq_setmark(mfile *m, uint32_t lseq, uint32_t useq);
void     seq_addmark(mfile *m, uint32_t lseq, uint32_t useq);
int      seq_delmark(mfile *m, uint32_t seq);

/*----- status operation -----*/
int      ack_clear(mfile *m, int state);
int      ack_check(mfile *m, int state);
void     clr_hoststate(mfile *m);
uint8_t *get_hoststate(mhost *t, mfile *m);
uint8_t *set_hoststate(mhost *t, mfile *m, uint8_t state);

/*----- send/receive -----*/
void mrecv_clean();
void msend_clean();
int  mrecv();
void msend(mfile *m);

/*----- time -----*/
int mtimeget(struct timeval *tv);
int mtimeout(struct timeval *tf, uint32_t msec);

/*----- other -----*/
uint32_t getrid();
int space_escape(char *str);
int workend(mcomm *c);
char *yesno(int n);


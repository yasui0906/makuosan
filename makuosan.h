/*
 * [MAKUOSAN]
 *  multicast file synchronization system
 */
#define MAKUOSAN_VERSION "0.8.8"
#define PROTOCOL_VERSION 3
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
#include <poll.h>
#include <libgen.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <openssl/blowfish.h>

/*----- limit -----*/
#define MAX_COMM             8
#define MAKUO_BUFFER_SIZE 1024
#define MAKUO_HOSTNAME_MAX 255

/*----- default -----*/
#define MAKUO_LOCAL_ADDR  "127.0.0.1"
#define MAKUO_MCAST_ADDR  "224.0.0.108"
#define MAKUO_MCAST_PORT  5000

/*----- timeout -----*/
#define MAKUO_SEND_TIMEOUT  500    /* 再送間隔(ms)                     */
#define MAKUO_SEND_RETRYCNT 120    /* 再送回数                         */
#define MAKUO_PONG_TIMEOUT  180000 /* メンバから除外するまでの時間(ms) */
#define MAKUO_PONG_INTERVAL 45000  /* PING送信間隔(ms)                 */
#define MAKUO_RECV_GCWAIT   300000

/*----- operation -----*/
#define MAKUO_OP_PING 0
#define MAKUO_OP_EXIT 1
#define MAKUO_OP_SEND 2
#define MAKUO_OP_MD5  3

/*----- flags -----*/
#define MAKUO_FLAG_ACK   1
#define MAKUO_FLAG_CRYPT 2

/*----- sendstatus -----*/
#define MAKUO_SENDSTATE_STAT       0  /* 更新確認待 */
#define MAKUO_SENDSTATE_OPEN       1  /* オープン待 */
#define MAKUO_SENDSTATE_DATA       2  /* データ送信 */
#define MAKUO_SENDSTATE_MARK       3  /* 再送確認待 */
#define MAKUO_SENDSTATE_CLOSE      4  /* クローズ待 */
#define MAKUO_SENDSTATE_LAST       5  /* 送信完了   */
#define MAKUO_SENDSTATE_ERROR      6  /* エラー発生 */
#define MAKUO_SENDSTATE_BREAK      7  /* 送信中断   */

/*----- recvstatus -----*/
#define MAKUO_RECVSTATE_NONE       0
#define MAKUO_RECVSTATE_UPDATE     1
#define MAKUO_RECVSTATE_SKIP       2
#define MAKUO_RECVSTATE_OPEN       3
#define MAKUO_RECVSTATE_MARK       4
#define MAKUO_RECVSTATE_CLOSE      5
#define MAKUO_RECVSTATE_IGNORE     6
#define MAKUO_RECVSTATE_READONLY   7
#define MAKUO_RECVSTATE_MD5OK      10
#define MAKUO_RECVSTATE_MD5NG      11
#define MAKUO_RECVSTATE_OPENERROR  90
#define MAKUO_RECVSTATE_READERROR  91
#define MAKUO_RECVSTATE_WRITEERROR 92
#define MAKUO_RECVSTATE_CLOSEERROR 93

/*----- mexec mode -----*/
#define MAKUO_MEXEC_SEND 0
#define MAKUO_MEXEC_DRY  1
#define MAKUO_MEXEC_MD5  2

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
  char  data[MAKUO_BUFFER_SIZE];
  char *p;
}__attribute__((packed)) mdata;

typedef struct
{
  char *pattern;
  void *prev;
  void *next;
} excludeitem;

typedef struct
{
  int cpid;
  int fd[2];
  int size[2];
  int argc[2];
  int check[2];
  int loglevel;
  int working;
  int authchk;
  char cmdline[2][MAKUO_BUFFER_SIZE];
  char parse[2][8][MAKUO_BUFFER_SIZE];
  char readbuff[2][MAKUO_BUFFER_SIZE];
  struct sockaddr_in addr;
  socklen_t addrlen;
  excludeitem *exclude;
} mcomm;

typedef struct
{
  int   fd;
  char  fn[PATH_MAX];
  char  tn[PATH_MAX];
  char  ln[PATH_MAX];
  uint32_t sendto;
  uint32_t dryrun;
  uint32_t retrycnt;
  uint32_t sendwait;
  uint32_t lickflag;
  uint32_t initstate;
  uint32_t recvcount;
  uint32_t markcount;
  uint32_t marksize;
  uint32_t seqnomax;
  mdata mdata;
  mcomm *comm;
  uint32_t *mark;
  void  *prev;
  void  *next;
  struct stat fs;
  struct sockaddr_in addr;
  struct timeval lastsend;
  struct timeval lastrecv;
} mfile;

typedef struct
{
  int state;
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
  struct sockaddr_in maddr;
  struct sockaddr_in laddr;
  struct sockaddr_un uaddr;
  char base_dir[PATH_MAX];
  char real_dir[PATH_MAX];
  uid_t uid;
  gid_t gid;
  char group_name[64];
  char user_name[64];
  char password[2][16];
  mcomm comm[MAX_COMM];
} mopt;

extern mfile *mftop[2];
extern mhost *members;
extern mopt moption;
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;
extern int loop_flag;
extern char *tzname[2];
extern long timezone;
extern int daylight;
extern char TZ[256];
extern struct timeval curtime;
extern BF_KEY EncKey;

/*----- function -----*/
void   lprintf(int l, char *fmt, ...);
void   cprintf(int l, mcomm *c, char *fmt, ...);
void   fdprintf(int s, char *fmt, ...);
int    getrid();
void   mfdel(mfile *m);
mfile *mfadd(int n);
mfile *mfins(int n);
mhost *member_add(struct in_addr *addr, mdata *recvdata);
void   member_del(mhost *h);
void   mrecv(int s);
void   msend(int s, mfile *m);
int    seq_popmark(mfile *m, int n);
int    seq_delmark(mfile *m, uint32_t seq);
int    seq_addmark(mfile *m, uint32_t lseq, uint32_t useq);
int    linkcmp(mfile *m);
int    statcmp(struct stat *s1, struct stat *s2);
int    mremove(char *base, char *name);
int    mcreate(char *base, char *name, mode_t mode);
int    mcreatedir(char *base, char *name, mode_t mode);
int    space_escape(char *str);
int    workend(mcomm *c);
int    ack_clear(mfile *m, int state);
int    ack_check(mfile *m, int state);
int    mtimeget(struct timeval *tv);
int    mtimeout(struct timeval *tf, uint32_t msec);
excludeitem *mfnmatch(char *str, excludeitem *exclude);


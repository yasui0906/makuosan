#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT(makuosan, 1.3.4.1, info-makuosan@klab.jp)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([common.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB(crypto, MD5_Init)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_addr)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h sys/timeb.h syslog.h unistd.h utime.h])
AC_CHECK_HEADERS(openssl/md5.h openssl/blowfish.h,,[AC_MSG_ERROR([Can't found openssl header file])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.

AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_REPLACE_FNMATCH
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getcwd gethostname gettimeofday inet_ntoa lchown memmove memset mkdir realpath rmdir select setenv socket strchr strerror tzset uname utime])
AC_CACHE_CHECK([whether getopt has optreset support], ac_cv_have_getopt_optreset,[
	AC_TRY_LINK([#include <unistd.h>], extern int optreset; optreset = 0;, [ ac_cv_have_getopt_optreset="yes" ], [ ac_cv_have_getopt_optreset="no" ])
])
if test "x$ac_cv_have_getopt_optreset" = "xyes" ; then
	AC_DEFINE(HAVE_GETOPT_OPTRESET, 1, [getopt has optreset support])
fi
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# configure.ac for sniffit
# Copyright 1997-1998 Brecht Claerhout
# Copyright 2016      Joao Eriberto Mota Filho
# Under BSD-3-CLause license.

AC_PREREQ([2.69])
AC_INIT([sniffit], [0.4.0], [https://github.com/eribertomota/sniffit/issues])
AC_CONFIG_SRCDIR([src/sn_generation.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(ncurses, main, , [AC_MSG_ERROR([Couldn't find libncurses])])
AC_CHECK_LIB(pcap, pcap_open_live, , [AC_MSG_ERROR([Couldn't find libpcap])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h termios.h unistd.h])
AC_CHECK_HEADERS([ncurses.h], AC_DEFINE([HAVE_NCURSES_H], 1, [none]), AC_MSG_ERROR([ncurses.h not found]))
AC_CHECK_HEADERS([pcap.h], , AC_MSG_ERROR([pcap.h not found]))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm bzero gethostbyname socket strchr strdup strstr])

dnl Check Shared Memory support
AC_CHECK_FUNCS(shmget)

dnl exit function check
AC_CHECK_FUNCS(atexit)

# Other checks

dnl Check the datalength
AC_CHECK_SIZEOF(unsigned short int)
if test $ac_cv_sizeof_unsigned_short_int -ne 2; then
    echo "unsigned short is NOT 2 bytes... quiting"
    exit
fi

AC_CHECK_SIZEOF(unsigned long int)
if test $ac_cv_sizeof_unsigned_long_int -eq 4; then
AC_DEFINE(USE_32_LONG_INT, 1, [none])
else
    echo "unsigned long is NOT 4 bytes... hmmm..."
    AC_CHECK_SIZEOF(unsigned int)
    if test $ac_cv_sizeof_unsigned_int -ne 4; then
        echo "unsigned int is NOT 4 bytes either... quiting"
        exit
    else
        AC_DEFINE(USE_32_INT, 1, [none])
    fi
fi

AC_CONFIG_FILES([Makefile src/Makefile])
AM_INIT_AUTOMAKE([foreign])

AC_OUTPUT

# configure.ac for sniffit
# Copyright 1997-1998 Brecht Claerhout
# Copyright 2016-2020 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br.
# Copyright 2024      Denis Ovsienko <denis@ovsienko.info>
# Under BSD-3-CLause license.

AC_PREREQ([2.69])
AC_INIT([sniffit], [0.6], [https://github.com/resurrecting-open-source-projects/sniffit/issues])
AC_CONFIG_SRCDIR([src/sn_generation.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: sniffit links with libncurses when it is available, even if it does
# not use it because src/sn_config.h does not define INCLUDE_INTERFACE because
# other conditions are not met.  It would be better to move that logic entirely
# to Autoconf and to define (or not) INCLUDE_INTERFACE only here.
AC_CHECK_LIB(ncurses, initscr)
AC_CHECK_LIB(pcap, pcap_open_live, , [AC_MSG_ERROR([Couldn't find libpcap])])

# Checks for header files.
AC_CHECK_HEADERS([ncurses.h])
AC_CHECK_HEADERS([pcap.h], , AC_MSG_ERROR([pcap.h not found]))

dnl Check Shared Memory support
AC_CHECK_FUNCS(shmget)

dnl exit function check
AC_CHECK_FUNCS(atexit)

# Other checks
# On Haiku sendto(), socket(), setservent() and inet_addr() are in libnetwork.
AC_CHECK_FUNC(setservent, ,
	[
		AC_CHECK_LIB(network,
			setservent,
			[LIBS="-lnetwork $LIBS"],
			[AC_MSG_ERROR([setservent() is required, but wasn't found])]
		)
	]
)

dnl Check the datalength
AC_CHECK_SIZEOF(unsigned short int)
if test $ac_cv_sizeof_unsigned_short_int -ne 2; then
    AC_MSG_ERROR([unsigned short is NOT 2 bytes... quiting])
fi

AC_CHECK_SIZEOF(unsigned long int)
if test $ac_cv_sizeof_unsigned_long_int -eq 4; then
AC_DEFINE(USE_32_LONG_INT, 1, [none])
else
    echo "unsigned long is NOT 4 bytes... hmmm..."
    AC_CHECK_SIZEOF(unsigned int)
    if test $ac_cv_sizeof_unsigned_int -ne 4; then
        AC_MSG_ERROR([unsigned int is NOT 4 bytes either... quiting])
    else
        AC_DEFINE(USE_32_INT, 1, [none])
    fi
fi

AC_CONFIG_FILES([Makefile src/Makefile])
AM_INIT_AUTOMAKE([foreign])

AC_OUTPUT

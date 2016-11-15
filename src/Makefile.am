# Makefile.am for sniffit
# Copyright 2016 Joao Eriberto Mota Filho
# Under BSD-3-CLause license.

sbin_PROGRAMS = sniffit
sniffit_SOURCES = sn_packets.c sn_generation.c sn_interface.c sn_cfgfile.c sn_logfile.c sn_resolv.c sniffit.c

AM_CPPFLAGS = -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" \
              -DPACKAGE_URL=\"\" -DHAVE_LIBNCURSES=1 -DHAVE_SHMGET=1 -DHAVE_ATEXIT=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 \
              -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 \
              -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DSIZEOF_UNSIGNED_SHORT_INT=2 -DSIZEOF_UNSIGNED_LONG_INT=8 -DSIZEOF_UNSIGNED_INT=4 \
              -DUSE_32_INT=1 -DLINUX=1
AM_CFLAGS = -lncurses -lpcap

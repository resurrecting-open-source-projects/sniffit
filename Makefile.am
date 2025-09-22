# Makefile.am for sniffit
# Copyright 2016 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
# Copyright 2024 Denis Ovsienko <denis@ovsienko.info>
# Under BSD-3-CLause license.

SUBDIRS = src

man_MANS = man/sniffit.5 man/sniffit.8

distclean-local:
	rm -rf autom4te.cache
	rm -f aclocal.m4 compile config.h* configure depcomp install-sh \
              Makefile.in missing src/Makefile.in

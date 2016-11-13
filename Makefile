# Sniffit Makefile -- Brecht Claerhout

#Don't change this
.PHONY : clean
.PHONY : config
.PHONY : no_arguments
.PHONY : all
.PHONY : sniffit

#This is executed when just typing Make, don't change

no_arguments:
	@echo 'Please read the README.* and IMPORTANT files'
	@echo 'use: make system'
	@echo 'where system can be: linux, sunos, irix, freebsd'
	@echo '(sunos: compiles for SunOS/Solaris)'
	@echo '(freebsd: first make the patch!!!!! read IMPORTANT)' 
sniffit:
	@echo 'Please read the README.* and IMPORTANT files'
	@echo 'use: make system'
	@echo 'where system can be: linux, sunos, irix, freebsd'
	@echo '(sunos: compiles for SunOS/Solaris)'
	@echo '(freebsd: first make the patch!!!!! read IMPORTANT)' 
all:
	@echo 'Please read the README.* and IMPORTANT files'
	@echo 'use: make system'
	@echo 'where system can be: linux, sunos, irix, freebsd'
	@echo '(sunos: compiles for SunOS/Solaris)'
	@echo '(freebsd: first make the patch!!!!! read IMPORTANT)' 

#Some Vars (you could change if you know what y'r doing)
CC         = gcc
SNIFFIT    = sniffit.0.3.2.c
DEP_FILES  = config.h sn_packets.h pcap.h sn_data.h sn_defines.h \
             sn_interface.h sn_oldether.h sn_cfgfile.h sn_logfile.h
HELP_FILES = detect_system 
GEN_FLAG   = -w -O2 -o sniffit
GEN_OPT    = -I./libpcap -L./libpcap -lpcap
#GEN_OPT    = -I./libpcap -L./libpcap -lpcap -DDEBUG

#Clean up everthing, don't change 
clean:
	cd libpcap; make clean; cd ..
	rm -f *.o sniffit

#Config the libpcap, don't change 
config:
	cd libpcap; ./configure; cd ..
	@echo 'You can now "make system"'

# Linux
SYSTEM_OPT_LINUX := -DLINUX -USUNOS -UIRIX -UFREEBSD -UBSDI -I/usr/include/ncurses -L/usr/include/ncurses -lncurses
linux:	$(SNIFFIT) $(DEP_FILES) $(HELP_FILES)
	cd libpcap; ./configure; make; cd .. 
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) $(SYSTEM_OPT_LINUX) 
	strip sniffit

# SunOS/Solaris
SYSTEM_OPT_SUNOS := -ULINUX -DSUNOS -UIRIX -UFREEBSD -UBSDI -lsocket -lnsl -lncurses 
# If SunOS/Solaris compile doesn't work, try this...
#SYSTEM_OPT_SUNOS := -ULINUX -DSUNOS -UIRIX -UFREEBSD -UBSDI -lnsl -lncurses
sunos:	$(SNIFFIT) $(DEP_FILES) $(HELP_FILES)
	cd libpcap; ./configure; make; cd .. 
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) $(SYSTEM_OPT_SUNOS) 
	strip sniffit

# IRIX
SYSTEM_OPT_IRIX := -ULINUX -USUNOS -DIRIX -UFREEBSD -UBSDI 
irix:	$(SNIFFIT) $(DEP_FILES) $(HELP_FILES)
	cd libpcap; ./configure; make; cd .. 
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) $(SYSTEM_OPT_IRIX) 
	strip sniffit
# BSDI
#SYSTEM_OPT_BSDI := -ULINUX -USUNOS -UIRIX -UFREEBSD -DBSDI
#bsdi:	$(SNIFFIT) $(DEP_FILES) $(HELP_FILES)
#	cd libpcap; ./configure; make; cd .. 
#	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) $(SYSTEM_OPT_BSDI) 
#	strip sniffit

#FreeBSD
SYSTEM_OPT_FREEBSD = -ULINUX -USUNOS -UIRIX -UBSDI -DFREEBSD -lncurses  
freebsd:$(SNIFFIT) $(DEP_FILES) $(HELP_FILES)
	cd libpcap; ./configure; make; cd ..
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) $(SYSTEM_OPT_FREEBSD)
	strip sniffit

#adjust this section for experimental compiling
sniffit_manual: $(SNIFFIT) $(DEP_FILES)
	cd libpcap; ./configure; make; cd ..
#add y'r flags to this line...
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) 


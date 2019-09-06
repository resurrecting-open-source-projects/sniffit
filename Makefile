# Sniffit Makefile -- Brecht Claerhout

#Don't change this
.PHONY : clean
.PHONY : config
.PHONY : no_arguments

#This is executed when just typing Make, don't change
no_arguments:
	@echo 'Please read the README.FIRST and IMPORTANT files'
	@echo 'use "make clean", "make config" and "make sniffit"'
	@echo 'or "make all" for a full recompile.'
	@echo 'use "make freebsd" for FreeBSD, after you applied the patch' 
	@echo '(read IMPORTANT)' 

#Some Vars (you could change if you know what y'r doing)
CC         = gcc
SNIFFIT    = sniffit.0.3.0.c
DEP_FILES  = config.h sn_packets.h pcap.h sn_data.h sn_defines.h \
             sn_interface.h sn_oldether.h
HELP_FILES = detect_system 
GEN_FLAG   = -w -O2 -o sniffit
GEN_OPT    = -I./libpcap -L./libpcap -lpcap
#GEN_OPT    = -I./libpcap -L./libpcap -lpcap -DDEBUG

#Clean up everthing, don't change 
clean:
	cd libpcap; make clean; cd ..
	rm -f *.o sniffit

#start from zero, don't change
all: clean config sniffit

#Config the libpcap, don't change 
config:
	cd libpcap; ./configure; cd ..
	@echo 'You can now "make sniffit"'

#auto compilation, don't modify
SYSTEM_OPT := $(shell ./detect_system)  
sniffit: $(SNIFFIT) $(DEP_FILES) $(HELP_FILES)
	cd libpcap; make; cd .. 
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) $(SYSTEM_OPT) 
	strip sniffit

#FreeBSD compilation, don't modify
SYSTEM_OPT_FREEBSD = -ULINUX -USUNOS -UIRIX -DFREEBSD -lncurses  
freebsd:$(SNIFFIT) $(DEP_FILES) $(HELP_FILES)
	cd libpcap; make; cd ..
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) $(SYSTEM_OPT_FREEBSD)
	strip sniffit

#adjust this section for experimental compiling
sniffit_manual: $(SNIFFIT) $(DEP_FILES)
	cd libpcap; make; cd ..
#add y'r flags to this line...
	$(CC) $(GEN_FLAG) $(SNIFFIT) $(GEN_OPT) 


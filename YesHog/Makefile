#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

YHROOT = YesHog
PWD = $(shell pwd)
export TOPDIR := $(patsubst %$(YHROOT)%, %$(YHROOT), $(PWD))
# When you modify this also modify variable includes
# in config-AVR.mak and config-x86.mak
SUBDIRS=avr common bignum crypto pkcs apps/http net

all:
	@echo $(TOPDIR)
	@for i in $(SUBDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; make all); done

clean:
	@for i in $(SUBDIRS); do \
	echo "whacking $$i..."; \
	(cd $$i; make clean); done
	rm -rf x86 atmega128


#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#
ifeq ($(TOOLCHAIN),x86)
else
 SRCS = yhtest.c
 TARGET = yhtest.hex
 #LIBS = $(TOPDIR)/crypto/ec.o $(TOPDIR)/crypto/sha1.o  -lbignum -lcommon -luart
 LIBS =  -luart
 include $(TOPDIR)/config-AVR.mak
endif


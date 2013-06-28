#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#
ifeq ($(TOOLCHAIN),x86)
 TSRCS = test.c
 SRCS = asn.c
 TARGET = libasn.a
 LIBS = -lyhcrypto -lbignum -lcommon
 include $(TOPDIR)/config-x86.mak
else
 SRCS = asn.c avr_ecc.c $(TOPDIR)/crypto/ec_verify.c
 TARGET = avr_ecc.hex
 LIBS = $(TOPDIR)/crypto/ec.o $(TOPDIR)/crypto/sha1.o  -lbignum -lcommon -luart
 include $(TOPDIR)/config-AVR.mak
endif


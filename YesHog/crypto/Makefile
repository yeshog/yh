#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

SRCS = sha1.c md5.c ec.c aes.c tlsv1-prf.c tls_handshake.c
TARGET = libyhcrypto.a
LIBS = -lbignum -lcommon
ifeq ($(TOOLCHAIN),x86)
 SRCS += ec_verify.c
 TSRCS = test.c
 LIBS += -lcrypto
 include $(TOPDIR)/config-x86.mak
else
 include $(TOPDIR)/config-AVR.mak
endif

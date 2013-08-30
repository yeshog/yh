#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

## Highly conditional compilation
LIBS = -lcommon
#SRCS = bufops.c mul.c div.c modinv.c sqr.c modexp.c
SRCS = bufops.c mul.c  sqr.c div.c modinv.c
TARGET = libbignum.a

ifeq ($(TOOLCHAIN),x86)
SRCS = bufops.c mul.c div.c modinv.c sqr.c modexp.c
TSRCS = test_interactive.c test.c
include $(TOPDIR)/config-x86.mak

endif

ifeq ($(TOOLCHAIN),AVR)
SRCS += bn-inline-avr-asm.c
LIBS += -luart
include $(TOPDIR)/config-AVR.mak
endif

ifeq ($(TOOLCHAIN),ARM)
SRCS = bufops.c mul.c div.c modinv.c sqr.c modexp.c
TSRCS = test_interactive.c test.c
include $(TOPDIR)/config-ARM.mak
endif


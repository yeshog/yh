#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

SRCS = common.c yhmemory.c log.c memfind.c
TSRCS = test.c
TARGET = libcommon.a
ifeq ($(TOOLCHAIN),x86)
 SRCS += fileops.c
 include $(TOPDIR)/config-x86.mak
else
 include $(TOPDIR)/config-AVR.mak
endif

#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

LIBS = -lyhcrypto -lbignum -lcommon -lhttp

ifeq ($(TOOLCHAIN),x86)
TARGET = libnet.a
SRCS = l23.c arp.c ip.c ip.c tcp.c
LIBS += -lpcap
TSRCS = test.c pcap.c test_live.c
include $(TOPDIR)/config-x86.mak
endif

ifeq ($(TOOLCHAIN),AVR)
TARGET = rtl_test.hex
SRCS = l23.c arp.c ip.c rtl_drv.c rtl_test.c ip.c tcp.c
#SRCS = easyethavr.c
LIBS += -luart
include $(shell pwd)/../config-AVR.mak
endif


ifeq ($(TOOLCHAIN),ARM)
#TARGET = libnet.a
#SRCS = l23.c arp.c ip.c ip.c tcp.c
#include $(TOPDIR)/config-ARM.mak
endif

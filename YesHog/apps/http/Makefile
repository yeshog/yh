SRCS = http_srv.c
TARGET = libhttp.a
LIBS = -lcommon
ifeq ($(TOOLCHAIN),x86)
 TSRCS = test.c
 include $(TOPDIR)/config-x86.mak
endif
ifeq ($(TOOLCHAIN),ARM)
 TSRCS = test.c
 include $(TOPDIR)/config-ARM.mak
endif
ifeq ($(TOOLCHAIN),AVR)
 include $(TOPDIR)/config-AVR.mak
endif

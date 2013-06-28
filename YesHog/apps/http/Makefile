SRCS = http_srv.c
TARGET = libhttp.a
LIBS = -lcommon
ifeq ($(TOOLCHAIN),x86)
 TSRCS = test.c
 include $(TOPDIR)/config-x86.mak
else
 include $(TOPDIR)/config-AVR.mak
endif

#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

ifeq ($(TOOLCHAIN),AVR)
#ifeq ($(MCU), atxmega128a1 )
#    # USART driver for xmega
#SRCS = uart_atxmega2.c
#endif
#ifeq ($(MCU), atmega128 )
#    #UART driver for atmega128
SRCS = uart_at128.c
#endif
 TARGET = libuart.a
 include $(shell pwd)/../config-AVR.mak
endif

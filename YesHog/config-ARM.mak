#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

# Individual makefiles define:
# TARGET, SRCS, ASRCS, LIBS, TSRCS

# vars
TARGETBASE = $(basename $(TARGET))
DEPDIR = .dep
MCU = arm

DEBUG = -g3 -gdwarf-2 -O0
INCLUDES = common avr net crypto bignum pkcs apps/http
CSTANDARD = -std=gnu99

CDEFS = -D_ARCH_BE=1 -D_ARM_
BINDIR = $(TOPDIR)/$(MCU)/bin
LIBDIR = $(TOPDIR)/$(MCU)/lib
LIBPATHS = -L$(LIBDIR)

# messages
MSG_END = Build complete

# Generate assembler listings from .c, .o, .S
OCFLAGS = -Wa,-adhlns=$(<:.c=.lst)
TCFLAGS = -Wa,-adhlns=$(<:.o=.lst)
ASFLAGS = -Wa,-adhlns=$(<:.S=.lst),-gstabs 

CCFLAGS =  $(DEBUG)
CCFLAGS += $(CDEFS)
CCFLAGS += -funsigned-char -funsigned-bitfields
CCFLAGS += -fpack-struct -fno-short-enums
CCFLAGS += -Wall -Wstrict-prototypes
CCFLAGS += $(patsubst %,-I$(TOPDIR)/%,$(INCLUDES))
CCFLAGS += $(CSTANDARD)
CFLAGS = $(CCFLAGS) $(OCFLAGS)
TFLAGS = $(CCFLAGS) $(TCFLAGS)
GENDEPFLAGS = -MD -MP -MF .dep/$(@F).d
ALL_CFLAGS = -I. $(CFLAGS) $(GENDEPFLAGS)
ALL_TFLAGS = -I. $(TFLAGS) $(GENDEPFLAGS)

LDFLAGS = -Wl,-Map=$(TARGETBASE).map,--cref
LDFLAGS += $(LIBPATHS) $(LIBS)

# Finally
CC = arm-linux-gnueabi-gcc
OBJCOPY = arm-linux-gnueabi-objcopy
OBJDUMP = arm-linux-gnueabi-objdump
NM = arm-linux-gnueabi-nm
AR = arm-linux-gnueabi-ar
COPY = cp -f
REMOVE = rm -rf
MKDIR = mkdir -p

# when building libs dont add any more output
ifeq ($(suffix $(TARGET)),.a)
EXTRA_AOUTPUT_TYPES =
TLIBS = $(patsubst lib%.a,-l%,$(TARGET))
LDFLAGS = -Wl,-Map=test.map,--cref
LDFLAGS += $(LIBPATHS)
CFLAGS = $(CCFLAGS)
else
endif

all : begin $(TARGET) test

begin :
	@echo ---- Building -------
	$(MKDIR) $(BINDIR)
	$(MKDIR) $(LIBDIR)
	$(MKDIR) $(DEPDIR)
	@echo ---------------------
    
OBJ = $(SRCS:.c=.o) $(ASRCS:.S=.o) $(LSRCS:.c=.o)
TOBJ = $(TSRCS:.c=.o)

.PRECIOUS : $(OBJ)

test : $(TARGET) $(TOBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $(TOBJ) $(TLIBS) $(LIBS)

%.a : $(OBJ)
	$(AR) rcs $@ $(OBJ)
	$(COPY) $@ $(LIBDIR)

%.o : %.c
	$(CC) -c $(ALL_CFLAGS) $< -o $@

clean :
	$(REMOVE) *.hex *.eep *.lst *.cof *.lss *.sym *.o *.map .eeprom.dep *.elf *.a .dep test

distclean : clean
	$(REMOVE) $(BINDIR)
	$(REMOVE) $(LIBDIR)


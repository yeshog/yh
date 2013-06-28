#
#   Author: Yogesh Nagarkar
#   Copyright: YesHog (www.yeshog.com)
#

# Individual makefiles define:
# TARGET, SRCS, ASRCS, LIBS, TSRCS

# vars
TARGETBASE = $(basename $(TARGET))
DEPDIR = .dep
MCU = atmega128
F_CPU = 8000000
FORMAT = ihex
DEBUG = -g3 -gdwarf-2 -Os
INCLUDES = common avr net crypto bignum pkcs apps/http avr/avr-test
CSTANDARD = -std=gnu99
CDEFS = -D_ARCH_LE=1 -D_AVR_ -DF_CPU=$(F_CPU)UL
BINDIR = $(TOPDIR)/$(MCU)/bin
LIBDIR = $(TOPDIR)/$(MCU)/lib
LIBPATHS = $(LIBDIR)

# messages
MSG_END = Build complete

# Generate assembler listings from .c, .o, .S
OCFLAGS = -Wa,-adhlns=$(<:.c=.lst)
TCFLAGS = -Wa,-adhlns=$(<:.o=.lst)
ASFLAGS = -Wa,-adhlns=$(<:.S=.lst),-gstabs 

CCFLAGS =  $(DEBUG)
CCFLAGS += $(CDEFS)
CCFLAGS += -funsigned-char -funsigned-bitfields
CCFLAGS += -fpack-struct -fshort-enums
CCFLAGS += -Wall -Wstrict-prototypes
CCFLAGS += $(patsubst %,-I$(TOPDIR)/%,$(INCLUDES))
CCFLAGS += $(CSTANDARD)
CFLAGS = $(CCFLAGS) $(OCFLAGS)
TFLAGS = $(CCFLAGS) $(TCFLAGS)
GENDEPFLAGS = -MD -MP -MF .dep/$(@F).d
ALL_CFLAGS = -mmcu=$(MCU) -I. $(CFLAGS) $(GENDEPFLAGS)
ALL_TFLAGS = -mmcu=$(MCU) -I. $(TFLAGS) $(GENDEPFLAGS)
ALL_ASFLAGS = -mmcu=$(MCU) -I. -x assembler-with-cpp $(ASFLAGS)

# Since the full implementation of all the mentioned features
# becomes fairly large, three different flavours of
# vfprintf() can be selected using linker options. 
# The default vfprintf() implements all the mentioned
# functionality except floating point conversions. A minimized-I/home/yogesh/workspace/svn/YesHog/pkcs/../crypto
# version of vfprintf() is available that only implements the very
# basic integer and string conversion facilities, but only the
# additional option can be specified using conversion flags
# (these flags are parsed correctly from the format specification,
# but then simply ignored). This version can 
# be requested using the following compiler options:

PRINTF_LIB_MIN = -Wl,-u,vfprintf -lprintf_min
PRINTF_LIB_FLOAT = -Wl,-u,vfprintf -lprintf_flt
PRINTF_LIB = 
SCANF_LIB_MIN = -Wl,-u,vfscanf -lscanf_min
SCANF_LIB_FLOAT = -Wl,-u,vfscanf -lscanf_flt
SCANF_LIB = 
MATH_LIB = -lm

# EXTMEMOPTS External memory options 
# http://www.nongnu.org/avr-libc/user-manual/malloc.html
# -Wl,--section-start,.data=0x801100,--defsym=__heap_end=0x80ffff

EXTMEMOPTS = 
LDFLAGS = -Wl,-Map=$(TARGETBASE).map,--cref
LDFLAGS += $(EXTMEMOPTS)
LDFLAGS += $(PRINTF_LIB) $(SCANF_LIB) $(MATH_LIB) -L$(LIBPATHS) $(LIBS)

# Finally
CC = avr-gcc
OBJCOPY = avr-objcopy
OBJDUMP = avr-objdump
SIZE = avr-size
NM = avr-nm
AR = avr-ar
COPY = cp -f
REMOVE = rm -rf
MKDIR = mkdir -p

# when building libs dont add any more output
ifeq ($(suffix $(TARGET)),.a)
EXTRA_AOUTPUT_TYPES =
else
endif

ifeq ($(suffix $(TARGET)),.hex)
EXTRA_AOUTPUT_TYPES = eep lss sym
endif

# Size matters
AVRMEM = avr-mem.sh $(TARGETBASE).elf $(MCU)
HEXSIZE = $(SIZE) --target=$(FORMAT) $(TARGETBASE).hex
ELFSIZE = $(SIZE) -A $(TARGETBASE).elf

EXTRA_OUTPUTS = $(foreach xout, $(EXTRA_AOUTPUT_TYPES),$(TARGETBASE).$(xout))

# all prereqs
all : begin gccversion sizebefore build sizeafter end

begin :
	@echo ---- Building -------
	$(MKDIR) $(BINDIR)
	$(MKDIR) $(LIBDIR)
	$(MKDIR) $(DEPDIR)
	@echo ---------------------

gccversion :
	@echo "Gcc version"
	@$(CC) --version

sizebefore :
	@if test -f $(TARGETBASE).elf; then echo; echo\
	$(MSG_SIZE_BEFORE); $(ELFSIZE); \
	$(AVRMEM) 2>/dev/null; echo; fi

# The main build deps/prereqs
build: $(TARGET) $(EXTRA_OUTPUTS)

# SRCS = sources ASRCS = Assembly sources
# LSRCS = Lib extra sources apart from srcs
# TSRCS = test sources
OBJ = $(SRCS:.c=.o) $(ASRCS:.S=.o) $(LSRCS:.c=.o) $(TSRCS:.c=.o)

%.hex : $(TARGETBASE).elf
	$(OBJCOPY) -O $(FORMAT) -R .eeprom $< $@
	$(COPY) $@ $(BINDIR)

# .PRECIOUS
# The targets which .PRECIOUS depends on are given the 
# following special treatment: if make is killed or
# interrupted during the execution of their recipes,
# the target is not deleted.
.SECONDARY : $(TARGETBASE).elf
.PRECIOUS : $(OBJ)
%.elf : $(OBJ)
	$(CC) $(ALL_TFLAGS) $^ --output $@ $(LDFLAGS)
	$(COPY) $@ $(BINDIR)

%.eep : $(TARGETBASE).elf
	$(OBJCOPY) -j .eeprom --set-section-flags=.eeprom="alloc,load" \
	--change-section-lma .eeprom=0 -O $(FORMAT) $< $@

%.lss : $(TARGETBASE).elf
	$(OBJDUMP) -DFSl $< > $@

%.sym: $(TARGETBASE).elf
	$(NM) -n $< > $@

COFFCONVERT=$(OBJCOPY) --debugging \
--change-section-address .data-0x800000 \
--change-section-address .bss-0x800000 \
--change-section-address .noinit-0x800000 \
--change-section-address .eeprom-0x810000

coff : $(TARGET)
	$(COFFCONVERT) -O coff-avr $< $(TARGETBASE).cof

extcoff : $(TARGET)
	$(COFFCONVERT) -O coff-ext-avr $< $(TARGETBASE).cof

%.o : %.c
	$(CC) -c $(ALL_CFLAGS) $< -o $@

%.s : %.c
	$(CC) -S $(ALL_CFLAGS) $< -o $@

%.o : %.S
	$(CC) -c $(ALL_ASFLAGS) $< -o $@

%.i : %.c
	$(CC) -E -mmcu=$(MCU) -I. $(CFLAGS) $< -o $@

%.a : $(OBJ)
	$(AR) rcs $@ $(OBJ)
	$(COPY) $@ $(LIBDIR)

# Application size
sizeafter : 
	@if test -f $(TARGETBASE).elf; then echo; echo $(MSG_SIZE_AFTER); $(ELFSIZE); \
	$(AVRMEM) 2>/dev/null; echo; fi

end :
	@echo $(MSG_END)

clean :
	$(REMOVE) *.hex *.eep *.lst *.cof *.lss *.sym *.o *.map .eeprom.dep *.elf *.a .dep

distclean : clean
	$(REMOVE) $(BINDIR)
	$(REMOVE) $(LIBDIR)

.PHONY: all begin finish end sizebefore sizeafter gccversion \
		build elf hex eep lss sym coff extcoff clean

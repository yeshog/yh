include user.mak
CC=gcc
LDFLAGS=
SRCS=log.c fileops.c
OBJS=$(SRCS:.c=.o)
PROJ=libcommon.a

.c.o:
	$(CC) $(CFLAGS) $(OFLAGS) $< -o $@

makelib: $(OBJS)
	$(AR) rcs $(PROJ) $(OBJS)

all: makelib

clean:
	rm -rf *.o *.a *~


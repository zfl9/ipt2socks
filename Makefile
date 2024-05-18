CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wvla -pthread -O3 -flto -fno-strict-aliasing -ffunction-sections -fdata-sections -DNDEBUG
LDFLAGS = -pthread -O3 -flto -fno-strict-aliasing -Wl,--gc-sections -s
LIBS = -lm
SRCS = src/ipt2socks.c src/lrucache.c src/netutils.c src/protocol.c libev/ev.c
OBJS = $(SRCS:.c=.o)
MAIN = ipt2socks
DESTDIR = /usr/local/bin

.PHONY: all install clean

all: $(MAIN)

install: $(MAIN)
	mkdir -p $(DESTDIR)
	install -m 0755 $(MAIN) $(DESTDIR)

clean:
	$(RM) $(MAIN) *.o libev/*.o

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(MAIN) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

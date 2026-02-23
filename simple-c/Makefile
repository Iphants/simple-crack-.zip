CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lzip -lpthread
MOD_OBJS = main.o attack.o password.o charset.o
noyba: $(MOD_OBJS)
	$(CC) $(CFLAGS) -o noyba $(MOD_OBJS) $(LDFLAGS)

main.o: main.c config.h charset.h attack.h
attack.o: attack.c config.h password.h attack.h
password.o: password.c config.h password.h
charset.o: charset.c charset.h

all: noyba belajar

clean:
	rm -f noyba belajar $(MOD_OBJS)

.PHONY: all clean

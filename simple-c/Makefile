CC = gcc
CFLAGS = -Wall -Wextra -O2

# Platform detection
ifeq ($(OS),Windows_NT)
    # Windows/MinGW
    PLATFORM_SRC = platform_win32.c
    LDFLAGS = -lzip -lws2_32
    EXE = noyba.exe
else
    # Linux/Unix/macOS
    PLATFORM_SRC = platform_posix.c
    LDFLAGS = -lzip -lpthread
    EXE = noyba
endif

MOD_OBJS = main.o attack.o password.o charset.o platform.o
TARGET = $(EXE)

$(TARGET): $(MOD_OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(MOD_OBJS) $(LDFLAGS)

main.o: main.c config.h charset.h attack.h platform.h
attack.o: attack.c config.h password.h attack.h platform.h
password.o: password.c config.h password.h
charset.o: charset.c charset.h
platform.o: $(PLATFORM_SRC) platform.h

all: $(TARGET)

clean:
	rm -f $(TARGET) $(MOD_OBJS)

.PHONY: all clean

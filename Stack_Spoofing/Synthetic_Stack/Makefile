CC = x86_64-w64-mingw32-gcc.exe
NASM = nasm.exe
CFLAGS = -Wall -O2
NFLAGS = -f win64
LDFLAGS = -luser32

TARGET = spoofer.exe
OBJS = main.o spoofer.o spoof.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	-del /Q $(OBJS) 2>NUL

main.o: main.c spoofer.h structs.h
	$(CC) $(CFLAGS) -c $< -o $@

spoofer.o: spoofer.c spoofer.h structs.h
	$(CC) $(CFLAGS) -c $< -o $@

spoof.o: spoof.asm
	$(NASM) $(NFLAGS) $< -o $@

clean:
ifeq ($(OS),Windows_NT)
	-del /Q *.o $(TARGET) 2>NUL
else
	$(RM) *.o $(TARGET)
endif

.PHONY: all clean

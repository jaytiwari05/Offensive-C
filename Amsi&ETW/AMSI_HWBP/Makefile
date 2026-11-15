CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lole32
TARGET  = amsi_hwbp.exe
SRC     = amsi_hwbp.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
ifeq ($(OS),Windows_NT)
	- cmd /c "del /Q $(TARGET) 2>NUL"
else
	$(RM) $(TARGET)
endif

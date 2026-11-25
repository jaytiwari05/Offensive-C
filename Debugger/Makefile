CC = x86_64-w64-mingw32-gcc.exe
CFLAGS = -static-libgcc -ffunction-sections -fdata-sections -Wl,--gc-sections -fno-ident -s
TARGET = main.exe
SRC = main.c

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) -o $(TARGET) $(SRC) $(CFLAGS)

clean:
ifeq ($(OS),Windows_NT)
	- cmd /c "del /Q $(TARGET) 2>NUL"
else
	$(RM) $(TARGET)
endif

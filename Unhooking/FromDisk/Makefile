CC = x86_64-w64-mingw32-gcc.exe
TARGET = unhook.exe
SRC = main.c read.c map.c unhook.c
CFLAGS = -static-libgcc -ffunction-sections -fdata-sections -Wl,--gc-sections -fno-ident -s

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) -o $(TARGET) $(SRC) $(CFLAGS)

clean:
ifeq ($(OS),Windows_NT)
	- cmd /c "del /Q $(TARGET) 2>NUL"
else
	$(RM) $(TARGET)
endif

CC = x86_64-w64-mingw32-gcc.exe
TARGET = dde_callback_hijack.exe
SRC = dde_callback_hijack.c
# CFLAGS = 

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC)

clean:
ifeq ($(OS), Windows_NT)
	- cmd /c "del /Q $(TARGET) 2>NUL"
else
	- rm -f $(TARGET)
endif

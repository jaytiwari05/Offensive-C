CC = x86_64-w64-mingw32-g++
TARGET = dyncall.exe
SRC = dyncall.c
# CFLAGES = 
# LIBS = 

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET)

# just a clean way to delete file on linux and windows both
clean:
ifeq ($(OS),Windows_NT)
	- cmd /c "del /Q $(TARGET) 2>NUL"
else
	$(RM) $(TARGET)
endif
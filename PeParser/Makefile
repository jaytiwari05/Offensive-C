CC_64 = x86_64-w64-mingw32-gcc
TARGET = peparser.exe
SRC = peparser.c
CFLAGES_64 = -Wall -m64 -s -Os -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libgcc -fno-keep-inline-dllexport -Wl,--gc-sections -Wno-missing-braces
CFLAGS_DLL=-DBUILD_DLL -shared
# LIBS = 

boxreflect:
	$(CC_64) -o boxreflect.dll boxreflect.c loader.c $(CFLAGES_64) $(CFLAGS_DLL)

e_boxreflect:
	$(CC_64) -o boxreflect.dll boxreflect.c evasive_loader.c $(CFLAGES_64) $(CFLAGS_DLL)

peparser:
	$(CC_64) peParser.c -o $(TARGET)

shortpeparser:
	$(CC_64) short_peparser.c -o $(TARGET)

# just a clean way to delete file on linux and windows both
clean:
ifeq ($(OS),Windows_NT)
	- cmd /c "del /Q $(TARGET) 2>NUL"
else
	$(RM) $(TARGET)
endif
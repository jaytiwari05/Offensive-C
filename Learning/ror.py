import sys

def encodeSymbols(rorType, symbolName):
    function_hash = 0
    for c in str(symbolName):
        function_hash = ror(function_hash, int(rorType))
        function_hash = (function_hash + ord(c))

    print("%s 0x%08X" % (symbolName, function_hash))


def main():
    if len(sys.argv) < 3:
        print("Usage: ./%s <rorType> <functionName>" % sys.argv[0])
        print("Usage: ./%s <rorType> -f <symbolFileName>" % sys.argv[0])
        return

    rorType = sys.argv[1]
    symbolName = ""

    if (sys.argv[2] == "-f"):
        if len(sys.argv) < 4:
            print("Usage: ./%s <rorType> -f <symbolFileName>" % sys.argv[0])
            return
        with open(sys.argv[3]) as symbolFile:
            symbolName = symbolFile.readline()
            while symbolName:
                # print(symbolName.strip())
                if (symbolName != "\n"):
                    encodeSymbols(rorType, symbolName.strip())
                symbolName = symbolFile.readline()
            return
    else:
        symbolName = sys.argv[2]
        encodeSymbols(rorType, symbolName)


def ror(dword, rorType):
    return ((dword >> rorType | dword << (32 - rorType)) & 0xFFFFFFFF)

if __name__ == "__main__":
    main()

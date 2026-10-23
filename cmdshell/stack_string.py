# Author : PaiN05
# String for Functions                : python stack_string.py VirtualAlloc
# -> CHAR VirtualAlloc_s[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0};

# String that have special character : python stack_string.py -n connected_fmt "Connected to %s: %d"
# -> CHAR connected_fmt[] = {'C', 'o', 'n', 'n', 'e', 'c', 't', 'e', 'd', ' ', 't', 'o', ' ', '%', 's', ':', ' ', '%', 'd', 0};

import sys

def make_stack_string(text, wide=False, var_name=None):
    if var_name is None:
        var_name = f"{text}_s"

    if wide:
        chars = ", ".join(f"L'{c}'" for c in text)
        return f"WCHAR {var_name}[] = {{{chars}, 0}};"
    else:
        chars = ", ".join(f"'{c}'" for c in text)
        return f"CHAR {var_name}[] = {{{chars}, 0}};"


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    wide = False
    var_name = None
    names = []

    i = 0
    while i < len(args):
        a = args[i]
        if a == "-w":
            wide = True
        elif a == "-n" and i + 1 < len(args):
            var_name = args[i + 1]
            i += 1
        else:
            names.append(a)
        i += 1

    if not names:
        print("error: no function name given", file=sys.stderr)
        sys.exit(1)

    for name in names:
        print(make_stack_string(name, wide=wide, var_name=var_name))


if __name__ == "__main__":
    main()
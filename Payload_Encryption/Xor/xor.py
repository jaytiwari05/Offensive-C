import sys

KEY = b"mysecretkey"

def xor(data, key):
    l = len(key)
    output = bytearray()
    for i in range(len(data)):
        output.append(data[i] ^ key[i % l])
    return bytes(output)

if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} <shellcode.bin>")
    sys.exit(1)

# Read raw shellcode
plaintext = open(sys.argv[1], "rb").read()
print(f"[*] Read {len(plaintext)} bytes from {sys.argv[1]}")

# XOR encrypt
ciphertext = xor(plaintext, KEY)

# Output as C hex format
hex_output = "".join(f"\\x{byte:02x}" for byte in ciphertext)
print(f"[*] XOR encrypted with key: {KEY.decode()}")
print(f"\n{hex_output}")

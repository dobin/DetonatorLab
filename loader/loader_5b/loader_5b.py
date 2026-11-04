import sys
import os

xor_key = "XORKEY"


def xor_bytes(input_text, key):
    len_key = len(key)
    encoded = []
    for i in range(0, len(input_text)):
        encoded.append(input_text[i] ^ key[i % len_key])
    return bytes(encoded)


def format_bytes_c(data: bytes, line_length=24):
    lines = [
        '"' + ''.join(f'\\x{b:02X}' for b in data[i:i+line_length]) + '"'
        for i in range(0, len(data), line_length)
    ]
    return '\n'.join(lines)


def get_rc_file(shellcode_raw):
    # Write the .rc file
    rc_content = f'''#define IDR_SHELLCODE 101
IDR_SHELLCODE RCDATA "payload.bin"
'''
    
    key_bytes = bytes(xor_key, 'UTF8')
    encrypted_shellcode = xor_bytes(shellcode_raw, key_bytes)

    return rc_content, encrypted_shellcode

		
def convert(shellcode_raw):
    ret = ""
    ret += '\tchar xorkey[] = "{}";\n'.format(xor_key)

    return ret

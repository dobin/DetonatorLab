import sys


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

		
def convert(shellcode_raw):
    xor_key = "XORKEY"
    key_bytes = bytes(xor_key, 'UTF8')
    encrypted_shellcode = xor_bytes(shellcode_raw, key_bytes)
    final_shellcode = format_bytes_c(encrypted_shellcode)

    ret = ""
    ret += 'char shellcode[{}] = {};\n'.format(
        str(len(shellcode_raw)),
        '{' + '{}'.format(final_shellcode) + '}') 
    ret += '\tchar xorkey[] = "{}";\n'.format(xor_key)

    return ret

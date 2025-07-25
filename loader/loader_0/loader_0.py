import sys


def format_bytes_c(data: bytes, line_length=24):
    lines = [
        '"' + ''.join(f'\\x{b:02X}' for b in data[i:i+line_length]) + '"'
        for i in range(0, len(data), line_length)
    ]
    return '\n'.join(lines)


def convert(shellcode_raw: bytes) -> str:
    shellcode: str = format_bytes_c(shellcode_raw)
    ret = ""
    ret += 'char shellcode[{}] = {};\n'.format(
        str(len(shellcode_raw)),
        '{' + '{}'.format(shellcode) + '}') 

    return ret

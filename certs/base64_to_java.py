#! /usr/bin/python

import sys
import base64

b64str = sys.argv[1]
b16str = base64.decodestring(b64str).encode('hex')

if len(sys.argv) == 3 and sys.argv[2] == 'yes':
    file_output = True
    fh = open('base16.hex', 'wb')
else:
    file_output = False

idx = 0
output = 'new byte[]{'
while idx < len(b16str):
    c1 = b16str[idx]
    c2 = b16str[idx + 1]
    output += '(byte)0x' + c1 + c2 + ', '
    if file_output:
        fh.write(chr(int(c1 + c2, 16)))
    idx += 2
output = output[:-2]
output += '}'
print output

if file_output:
    fh.close()

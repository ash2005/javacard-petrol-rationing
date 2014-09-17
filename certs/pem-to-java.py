#! /usr/bin/python

import os, sys

der = os.popen("./pem-to-der.sh " + sys.argv[1]).read()
der = der.replace('\n', '')
firsts = []
seconds = []
for i in range(len(der)):
    if i % 2 == 0:
        firsts.append(der[i])
    else:
        seconds.append(der[i])

output = 'new byte[]{'
for c1, c2 in zip(firsts, seconds):
    output += '(byte)0x' + c1 + c2 + ', '
output = output[:-2]
output += '}'
print output

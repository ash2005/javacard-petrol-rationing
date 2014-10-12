#! /usr/bin/python

import sys

if len(sys.argv) < 2:
	print 'You need to specify output file as first argument.'
	exit(0)

if len(sys.argv) == 3:
	count = int(sys.argv[2])
else:
	count = 512

b = bytearray()
while count > 0:
	vals = raw_input()
	vals = vals.split(':')
	for val in vals:
		val = val.replace(' ', '')
		if val != '' and count > 0:
			b.append(int(val, 16))
			count -= 8
f = open(sys.argv[1], 'wb')
f.write(b)
f.close()

#! /usr/bin/python

import sys

if len(sys.argv) < 2:
	print 'You need to specify output file as first argument.'
	exit(0)

if len(sys.argv) == 3:
	count = int(sys.argv[2])
else:
	count = 49 * 8

b = bytearray()
done = False
while not done:
	vals = raw_input()
	vals = vals.split(':')
	for val in vals:
		val = val.replace(' ', '')
		if val != '':
			b.append(int(val, 16))
			count -= 8
			if count == 0:
				done = True
				break
	print 'Need ' + str(count / 8) + ' more bytes...'
f = open(sys.argv[1], 'wb')
f.write(b)
f.close()

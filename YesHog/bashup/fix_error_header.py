import re
import sys
regex = re.compile('(#define)\s+(\w+)\s+(\w+)')
with open("../common/error.h") as f:
    n = 0xFFF0
    for line in f:
        match = regex.match(line)
        if match:
            sys.stdout.write( regex.sub( '{:<10} {:<45} {}'.\
                              format( \
                                (match.group(1)),
                                (match.group(2)),
                                ('0x'+hex(n)[2:].upper())),
                             line ) )
            n = n -1
        else:
            n = n - 0x0F
            sys.stdout.write(line)


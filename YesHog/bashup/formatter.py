import re
import sys
regex = re.compile('(#define)\s+(\w+)\s+(\w+)')
with open("./tmp.c") as f:
    for line in f:
        match = regex.match(line)
        if match:
            sys.stdout.write( regex.sub( '{:<10} {:<30} {}'.\
                              format( \
                                (match.group(1)),
                                (match.group(2)),
                                (match.group(3))),
                             line ) )
        else:
            sys.stdout.write(line)

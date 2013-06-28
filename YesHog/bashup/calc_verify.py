import sys
import getopt
import os
import re
import subprocess

regex = re.compile('(.*)(hexcalc ".+") ?= ?(.+)')

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

def runcmd(c):    
    p = subprocess.check_output( c,  \
           stderr=subprocess.STDOUT, \
           shell=True )
    return p

def get_calc_list( fil ):
    with open(fil) as f:
        for line in f:
            match = regex.match( line )
            if match:
                r = runcmd(match.group(2))
                #print 'Result: ', match.group(2), r
                c = ('hexcalc "(%s-(%s))"') % \
                      (r.strip(), match.group(3))
                x = runcmd( c )
                print c, '=', x

def main(argv=None):
    fil = None
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:],
                               "f:", ["--file"])
        except getopt.error, msg:
            raise Usage(msg)
        for o, a in opts:
            if o in ("-f", "--file"):
                fil = a
        if fil and (os.path.exists(fil)):
            get_calc_list(fil)
        else:
            print __doc__
    except Usage, err:
        print >>sys.stderr, err.msg
        print >>sys.stderr, "Usage calc_verify -f filename"
        return 2

if __name__ == "__main__":
    sys.exit(main())




#!/usr/bin/env python
# Author Yogesh Nagarkar
"""
pcap2hex.py OPTIONS

Description: dump the packets in a pcap file

OPTIONS
-f <filename>       : file name
-c                  : generate c code
-p <initial pkt num>: only useful with option
   -c, initial pkt num for c code

Example: pcap2hex.py -f /path/to/file.pcap -f fil.pcap -c -p 10
"""
import socket
import dpkt
import sys
import getopt
import os
spcr = lambda num,z: ('{:>%d}'%num).format(z)
spacer = lambda num: spcr(num, ' ')

def dumpcap( f ):
    pcapReader = dpkt.pcap.Reader(open(f))
    for ts, data in pcapReader:
        ether = dpkt.ethernet.Ethernet(data)
        print dpkt.hexdump(str(ether))

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

def generate_c( f, num=0 ):
    pcapReader = dpkt.pcap.Reader(open(f))
    for ts, data in pcapReader:
        ether = dpkt.ethernet.Ethernet(data)
        print cstring( str(ether), pktno=num )
        num += 1

def cstring( src, length=8, pktno=0 ):
    N=0; result='static unsigned char pkt_%d[] = {\n' % pktno
    while src:
        s,src = src[:length],src[length:]
        hexa = ', '.join(['0x%02X'%ord(x) for x in s])
        result += ('%s%s,\n') % (spacer(16), hexa)
        N+=length
    result = '%s};\n' % result
    return result

def main(argv=None):
    fil = None
    cst = False
    pktnum = 0
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:],
                        "hf:cp:", ["help", "--file",
                                 "--generate-c",
                        "--initial-packet-num"])
        except getopt.error, msg:
            raise Usage(msg)
        for o, a in opts:
            if o in ("-h", "--help"):
                print __doc__
            if o in ("-f", "--file"):
                fil = a
            if o in ( "-c", "--generate-c" ):
                cst = True
            if o in ( "-p", "--initial-packet-num"):
                pktnum = int(a)
        if fil and (os.path.exists(fil)) and (cst is False):
            dumpcap( fil  )
        elif fil and os.path.exists(fil) and cst:
            generate_c( fil, pktnum )
        else:
            print __doc__
    except Usage, err:
        print >>sys.stderr, err.msg
        print >>sys.stderr, "for help use --help"
        return 2

if __name__ == "__main__":
    sys.exit(main())


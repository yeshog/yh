import sys
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64
from Crypto.Hash import SHA
pem = open(sys.argv[1]).read()
lines = pem.replace(" ",'').split()
der = a2b_base64(''.join(lines[1:-1]))
cert = DerSequence()
cert.decode(der)
h = SHA.new()
print len(cert[0])
h.update(cert[0])
print h.hexdigest()


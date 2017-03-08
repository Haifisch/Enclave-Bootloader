#!/usr/bin/env python
import ed25519
import hashlib
import sys
import array
import os
from binascii import unhexlify

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

def sha256_checksum(filename, block_size=8):
    sha256 = hashlib.sha256()
    #f = open(filename, 'a')
    #f.write(Dump(0xfeedface))
    #f.close()
    f = open(filename, 'rb+')
    for block in iter(lambda: f.read(block_size), b''):
        sha256.update(block)
    sha256.update("FF566725748887167142607")
    #sha256.update(b"41414141414141414141414")
    f.close()
    return sha256.hexdigest()

def sha256_checksum_special(filename, block_size=4):
    sha256 = hashlib.sha256()
    f = open(filename, 'rb')
    f.seek(0x800, 0)
    block = f.read(block_size)
    sha256.update(block)
    f.close()
    return sha256.hexdigest()

def Dump(n): 
  s = '%x' % n
  if len(s) & 1:
    s = '0' + s
  return s.decode('hex')

def main():
    for f in sys.argv[1:]:
        checksum = sha256_checksum(f)
        print(f + '\t' + checksum)
        size = os.stat(f).st_size 
        print("file size: "+ hex(size))

    original = open(sys.argv[1], "r")
    firmware_buffer = original.read()
    dfuFile = open(sys.argv[1]+".dfu.bin", "wb")
    dfuFile.write(unhexlify(checksum))

    keydata = open("dev_signing_key","rb").read()
    signing_key = ed25519.SigningKey(keydata)
    arry = array.array('B', signing_key.to_bytes())
    print "Private key: "
    print ''.join('0x{:02x},'.format(x) for x in arry)

    vkey_hex = signing_key.get_verifying_key().to_bytes()
    print len(vkey_hex)
    print "Public key: "
    arry = array.array('B', vkey_hex)
    print ''.join('0x{:02x},'.format(x) for x in arry)

    signature = signing_key.sign(unhexlify(checksum))
    print len(signature)
    arry = array.array('B', signature)
    print ''.join('0x{:02x},'.format(x) for x in arry)
    dfuFile.write(signature)

    dfuFile.write(Dump(size)) 

    for x in xrange(0,18):
            dfuFile.write(Dump(0x00));

    try:
	  signing_key.get_verifying_key().verify(signature, unhexlify(checksum))
	  print "signature is good"
    except ed25519.BadSignatureError:
	  print "signature is bad!"
    
    dfuFile.write(firmware_buffer)
    dfuFile.close()    
    
if __name__ == '__main__':
    main()
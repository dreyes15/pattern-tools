#!/usr/bin/env python

##pattern_create original description###################
# Author: phillips321
# Site: www.phillips321.co.uk
# Version 0.1
# Credits: metasploit project
# About: Replicates msf pattern_create.rb
########################################################

##pattern_offset########################################
# Author: DrEyes
# Version 0.2
# Credits: Metasploit project
# About: Replicates msf pattern_offset.rb
########################################################

import sys
import re
import struct

def pattern_create(length=8192, set_a=None, set_b=None, set_c=None):
    if not isinstance(length, int):
        raise Exception('[-] Length must be an integer')
        sys.exit(1)

    if not set_a: seta="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if not set_b: setb="abcdefghijklmnopqrstuvwxyz"
    if not set_c: setc="0123456789"

    string="" ; a=0 ; b=0 ; c=0

    while len(string) < length:
        if not set_a and not set_b and not set_c:
            string += seta[a] + setb[b] + setc[c]
            c+=1
            if c == len(setc):c=0;b+=1
            if b == len(setb):b=0;a+=1
            if a == len(seta):a=0
        elif set_a and not set_b and not set_c:
            raise Exception('[-] Error, cannot work with just one set!')
            sys.exit(1)
        elif set_a and set_b and not set_c:
            string += seta[a] + setb[b]
            b+=1
            if b == len(setb):b=0;a+=1
            if a == len(seta):a=0
        elif set_a and set_b and set_c:
            string += seta[a] + setb[b] + setc[c]
            c+=1
            if c == len(setc):c=0;b+=1
            if b == len(setb):b=0;a+=1
            if a == len(seta):a=0
        else:
            raise Exception('[-] Input error, please check your parameters')
            sys.exit(1)
    return string[:length]

def pattern_offset(value, length=8192):
    if value.startswith('0x') and len(value) >= 8:
            value = struct.pack('<I', int(value, 16)).strip('\x00')
            find_pattern(value, length)
    elif (value.startswith('0x') and len(value) < 8) or (len(value) < 3 ):
        print "[-] Value too short"
    else:
        find_pattern(value,length)

def find_pattern(value, length):
    buf = pattern_create(length)
    matches = [match.start() for match in re.finditer(value, buf)]
    if not matches:
        print "[-] No matches for value"
    else:
        for found in matches:
            print "[*] Exact match at offset: %i" % (found)

if __name__ == '__main__':
    pattern_create(50000)
    #0x416f3841 = Ao8A Big eandian
    #0x41386f41 = A8oA little eandian
    pattern_offset('0x41386f41', 50000)

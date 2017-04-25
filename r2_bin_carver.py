#!/usr/bin/env python
#
# r2 Bin Carver
#


import argparse
import os
import sys
from binascii import hexlify

try:
    import r2pipe
except ImportError as err:
    print("Error while importing module r2pipe: %s" % str(err))
    sys.exit(0)


def carve(file_path, offset, size, magic=None):
    r2 = r2pipe.open(file_path, ['-z'])
    if magic:
        magic_bytes = hexlify(bytes(magic, 'ascii'))
        print('[+] Checking for magic: %s - %x' % (magic, int(magic_bytes, 16)))
        header = r2.cmd("p8 %x @ %s" % (len(magic), offset))
        if bytes(header, 'ascii') != magic_bytes:
            print("[+] No magic found, exiting...")
            exit()
        else:
            print("[+] Magic found, carving...")

    r2.cmd("s %s" % (offset))
    r2.cmd('wtf %s.%s %s' % (file_path, offset, size))
    print("[+] Carving to %s.%s" % (file_path, offset))
    return '%s.%s' % (file_path, offset)


def patch(file_path):
    r2 = r2pipe.open(file_path)
    info = r2.cmdj('ij')
    if info['bin']['bintype'] != 'pe':
        print("[+] Patching not possible, only PE files supported!")
        exit()
    r2 = r2pipe.open(file_path, ['-w', '-nn'])

    print('[+] Patching...')
    # FIXME: The pf structs don't exist at the time of writing! And pfsj does
    # not exist. For these reasons lets just seek and be lazy
    # pf [8]zxxxxxxwwx
    e_elfnew_addr = r2.cmdj('pfj x @ 0x3c')[0]['value']
    numberOfSections = r2.cmdj('pfj w @ %i' % (e_elfnew_addr + 0x6))[0]['value']
    sizeOfOptionalHeader = r2.cmdj('pfj w @ %i' % (e_elfnew_addr + 0x14))[0]['value']
    base_addr = e_elfnew_addr + 24 + sizeOfOptionalHeader

    print('[+] Found %i sections to patch' % (numberOfSections))
    for i in range(0, numberOfSections):
        addr = base_addr + 40 * i
        print('[+] Patching Section %i.' % (i))
        VirtualSize = r2.cmdj('pfj x @ %i' % (addr + 0x08))[0]['value']
        print('\tSetting VirtualSize to 0x%x' % (VirtualSize))
        r2.cmd('wv %i @ %i' % (VirtualSize, addr + 0x10))
        VirtualAddress = r2.cmdj('pfj x @ %i' % (addr + 0x0c))[0]['value']
        print('\tSetting PointerToRawData to 0x%x' % (VirtualAddress))
        r2.cmd('wv %i @ %i' % (VirtualAddress, addr + 0x14))

    print('[+] Pathing done')


def main():
    parser = argparse.ArgumentParser(description='Carve binaries from MiniDumps.')
    parser.add_argument('dmp', help='The MiniDump file to carve from')
    parser.add_argument('offset', help='Offset to carve from')
    parser.add_argument('size', help='Size of binary to carve')
    parser.add_argument('-b', type=str, help='Magic bytes to check for, e.g. MZ')
    parser.add_argument('-p', '--patch', action='store_true', help='Patch carved PE files')
    args = parser.parse_args()

    # FIXME: Won't redirect r2pipe, will have to 2>/dev/null for now!
    f = open(os.devnull, 'w')
    sys.stderr = f

    output_file = carve(args.dmp, args.offset, args.size, args.b)

    if args.patch:
        patch(output_file)


if __name__ == "__main__":
    main()

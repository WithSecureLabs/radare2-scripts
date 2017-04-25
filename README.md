# radare2 Scripts

## Summary

A 'collection' of scripts to be used with [radare2](https://github.com/radare/radare2).

- r2_bin_carver.py - A script used to carve files from memory dumps.
- r2_hash_func_decoder.py - A script used to decode hashed functions, commonly found in shellcode.

## Scripts

### Binary Carver

This script will carver files from memory dumps (MDMP), given an offset and a size.
In addition to carving it also supports basic patching for carved PE files.

Sample output with default arguments:

#### Examples

```
$ python2 ./r2_bin_carver.py ./memory.dmp 0x04af0000 0x2f000
[+] Carving to ./memory.dmp.0x04af0000
```

Sample output for binary carving using magic checking and patching:

```
$ python2 ./r2_bin_carver.py -p -b MZ ./memory.dmp 0x04af0000 0x2f000
[+] Checking for magic: MZ - 4d5a
[+] Magic found, carving...
[+] Carving to ./memory.dmp.0x04af0000
[+] Patching...
[+] Found 3 sections to patch
[+] Patching Section 0.
	Setting VirtualSize to 0x1fb0
	Setting PointerToRawData to 0x1000
[+] Patching Section 1.
	Setting VirtualSize to 0x5b7f
	Setting PointerToRawData to 0x3000
[+] Patching Section 2.
	Setting VirtualSize to 0x254d2
	Setting PointerToRawData to 0x9000
[+] Pathing done

```

### Hashed Function Decoder

This script will decode function hashes via lookup using a pre-generated database of hashes.
It will handle the generation, searching and analysis for the supported hashing techniques.

#### Supported Techniques

The currently supported hashing techniques.

```
$ python2 ./r2_hash_func_decoder.py -l
Suported Hashing Techniques:
- doublepulsar
- metasploit
```

#### Generating the Database

This will create hashes for all exported functions of a DLL or EXE, for all supported hashing techniques.

```
$ python2 ./r2_hash_func_decoder.py -g ntdll.dll
Generating Hashes:
Processing ./ntdll.dll...
```

#### Searching the Database

Manually searching the database for a given hash.

```
$ python2 ./r2_hash_func_decoder.py -s 0x6f721347
Searching for 0x6F721347...
- metasploit: ntdll.dll!RtlExitUserThread()
```

#### Auto Analysis in radare2

This will search all defined funtions within radare2 for hashes to decode for a given technique.

```
$ r2 shellcode
> af @ 0x0
> afl
0x00000000   31 931          fcn.00000000
> #!pipe python2 ./r2_hash_func_decoder.py -a doublepulsar
Analysing:
Function: fcn.00000000 0x0 931
|_ 0x0000001f		movabs rcx, 0x3e1481df		ntoskrnl.exe!PsLookupProcessByProcessId
|_ 0x0000003e		movabs rcx, 0xa0031eba		ntoskrnl.exe!PsGetProcessImageFileName
|_ 0x0000005d		movabs rcx, 0xfffffffff9e70684		ntoskrnl.exe!KeStackAttachProcess
|_ 0x0000007c		movabs rcx, 0x15ebfe4f		ntoskrnl.exe!PsGetProcessPeb
|_ 0x0000009b		movabs rcx, 0xa4ac30f9		ntoskrnl.exe!KeUnstackDetachProcess
|_ 0x000000ba		movabs rcx, 0xecd0beca		ntoskrnl.exe!ObfDereferenceObject
|_ 0x000000d9		movabs rcx, 0xffffffff5d9fb8ae		ntdll.dll!ZwAllocateVirtualMemory
|_ 0x000000f8		movabs rcx, 0xffffffffe3690194		ntoskrnl.exe!ExAllocatePool
|_ 0x00000117		movabs rcx, 0xffffffffb80010f6		ntoskrnl.exe!KeInitializeApc
|_ 0x00000136		movabs rcx, 0xffffffffd25fd6ca		ntoskrnl.exe!KeInsertQueueApc
|_ 0x00000155		movabs rcx, 0x1124a879		ntoskrnl.exe!KeGetCurrentThread
|_ 0x00000174		movabs rcx, 0x4f90c637		ntoskrnl.exe!PsGetCurrentProcess
|_ 0x00000193		movabs rcx, 0x10fee76c		ntoskrnl.exe!PsGetThreadTeb
```

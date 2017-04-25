# radare2 Scripts

## Summary

A 'collection' of scripts to be used with [radare2](https://github.com/radare/radare2).

- [r2_bin_carver.py](#binary-carver) - A script used to carve files from memory dumps.
- [r2_hash_func_decoder.py](#hashed-function-decoder) - A script used to decode hashed functions, commonly found in shellcode.

## Scripts

### Binary Carver

This script will carve files from memory dumps (MDMP), given an offset and a size.
In addition to carving it also supports basic patching for carved PE files.
At the time of writing this will patch the offsets within the PE sections headers.

**Requirements**

```
pip install r2pipe
```

Sample output with default arguments:

**Examples**

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

**Requirements**

```
pip install pefile r2pipe sqlite3
```

**Supported Techniques**

The currently supported hashing techniques.

```
$ python2 ./r2_hash_func_decoder.py -l
Suported Hashing Techniques:
- doublepulsar
- metasploit
```

**Generating the Database**

This will create hashes for all exported functions of a DLL or EXE, for all supported hashing techniques.

```
$ python2 ./r2_hash_func_decoder.py -g ntdll.dll
Generating Hashes:
Processing ./ntdll.dll...
```

**Searching the Database**

Manually searching the database for a given hash.

```
$ python2 ./r2_hash_func_decoder.py -s 0x6f721347
Searching for 0x6F721347...
- metasploit: ntdll.dll!RtlExitUserThread()
```

**Auto analysis in radare2**

This will search all defined funtions within radare2 for hashes to decode for a given technique.

```
$ r2 shellcode
> af @ 0x0
> afl
0x00000000   31 931          fcn.00000000
> #!pipe python2 ./r2_hash_func_decoder.py -a doublepulsar
Analysing:
Function: fcn.00000000 0x0 931
|_ 0x0000001f   movabs rcx, 0x3e1481df    ntoskrnl.exe!PsLookupProcessByProcessId
|_ 0x0000003e   movabs rcx, 0xa0031eba    ntoskrnl.exe!PsGetProcessImageFileName
|_ 0x0000005d   movabs rcx, 0xfffffffff9e70684    ntoskrnl.exe!KeStackAttachProcess
|_ 0x0000007c   movabs rcx, 0x15ebfe4f    ntoskrnl.exe!PsGetProcessPeb
|_ 0x0000009b   movabs rcx, 0xa4ac30f9    ntoskrnl.exe!KeUnstackDetachProcess
|_ 0x000000ba   movabs rcx, 0xecd0beca    ntoskrnl.exe!ObfDereferenceObject
|_ 0x000000d9   movabs rcx, 0xffffffff5d9fb8ae    ntdll.dll!ZwAllocateVirtualMemory
|_ 0x000000f8   movabs rcx, 0xffffffffe3690194    ntoskrnl.exe!ExAllocatePool
|_ 0x00000117   movabs rcx, 0xffffffffb80010f6    ntoskrnl.exe!KeInitializeApc
|_ 0x00000136   movabs rcx, 0xffffffffd25fd6ca    ntoskrnl.exe!KeInsertQueueApc
|_ 0x00000155   movabs rcx, 0x1124a879    ntoskrnl.exe!KeGetCurrentThread
|_ 0x00000174   movabs rcx, 0x4f90c637    ntoskrnl.exe!PsGetCurrentProcess
|_ 0x00000193   movabs rcx, 0x10fee76c    ntoskrnl.exe!PsGetThreadTeb
```

In addition to the above it will add comments to the appropriate lines:
```
[snip]
           0x00000017      e8bc060000     call 0x6d8                  ;[1]
│           0x0000001c      4889c3         mov rbx, rax
│           0x0000001f      48b9df81143e.  movabs rcx, 0x3e1481df      ; ntoskrnl.exe!PsLookupProcessByProcessId
│           0x00000029      e826050000     call 0x554                  ;[2]
│           0x0000002e      4885c0         test rax, rax
│       ┌─< 0x00000031      0f8455030000   je 0x38c                    ;[3]
│       │   0x00000037      4889059c0700.  mov qword [0x000007da], rax ; [0x7da:8]=0
│       │   0x0000003e      48b9ba1e03a0.  movabs rcx, 0xa0031eba      ; ntoskrnl.exe!PsGetProcessImageFileName
│       │   0x00000048      e807050000     call 0x554                  ;[2]
│       │   0x0000004d      4885c0         test rax, rax
│      ┌──< 0x00000050      0f8436030000   je 0x38c                    ;[3]
│      ││   0x00000056      488905850700.  mov qword [0x000007e2], rax ; [0x7e2:8]=0
│      ││   0x0000005d      48b98406e7f9.  movabs rcx, 0xfffffffff9e70684 ; ntoskrnl.exe!KeStackAttachProcess
│      ││   0x00000067      e8e8040000     call 0x554                  ;[2]
[snip]
```

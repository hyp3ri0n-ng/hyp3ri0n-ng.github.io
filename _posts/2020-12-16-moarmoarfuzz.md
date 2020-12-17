---
layout: post
title: Moar Fuzz!!!
tags: [hacking]
---

Alright back at it on 12/16/2020. I had a thought while I was away (side note: sometimes it helps to step away for a few hours or the rest of the day and come back to a problem. You'll always think of something good, trust me on this.). By the way I'm also going to go back and document all of these vulnerabilities a little more carefully and start giving them identifiers (e.g. HGV-0, HGV-1). Why? Because it's cool af and I also am not a fan of the current CVE system, which (I think) requires "responsible disclosure" (rant about that to come) which I do not believe in. Anyway, let's get back to hacking.

The thought that I had was that I'm getting a bunch of less interesting null ptr derefs whenever I give explorer.exe a "bad character" (chars disallowed by typical path names). Make no mistake, these are still vulnerabilities, there are plenty of examples out there of exploiting null page derefs, they are just far more rare than things like overflows and memory disclosure bugs. Anyway, my thinking is this: I'm looking for a vuln that fits a particular model, in particular one that allows me to take remote control of a machine without the user having to even click on the file. This seems do-able since even the functions that just list contents of a folder appear to be vulnerable to pretty much anything except for standard ascii characters (bit of an exaggeration but you get it). So instead of gathering a ton of crashes that will be with illegal characters, let's strip out the illegal chars one by one and see what happens, until we find a vuln that is not based on illegal characters. I'm going to try this, but also keep in the back of my mind that there is *possibly* an avenue to create files with illegal characters in them, the standard API doesn't seem to allow it (it causes a null deref), but perhaps editing some metadata somewhere in the system will allow me to do this, again let's put a pin in that and come back to it. For now let's strip 0x0A and 0x0D (line break, carriage return) which I know are illegal chars in a filename.

Interestingly enough as I was building this I found a different kind of crash while testing the fuzzer, this is with identical code to the one as before:

```
C:\Users\Garrett McParrot\Desktop\0day\shell32an
λ .\shell32_pwn_absexp.exe CORPUS\
INFO: Seed: 2877529473
INFO: Loaded 1 modules   (2 inline 8-bit counters): 2 [00007FF679419088, 00007FF67941908A),
INFO: Loaded 1 PC tables (2 PCs): 2 [00007FF6793C4710,00007FF6793C4730),
INFO:        8 files found in CORPUS\
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
=================================================================
==16392==ERROR: AddressSanitizer: heap-use-after-free on address 0x102480020440 at pc 0x7ff6792711d7 bp 0x00000014f520 sp 0x00000014f568
WRITE of size 2 at 0x102480020440 thread T0
    #0 0x7ff6792711d6 in fuzzMeDrZaus(unsigned char const *, unsigned __int64) C:\Users\Garrett McParrot\Desktop\0day\shell32an\shell32_pwn_absexp.cpp:15
    #1 0x7ff67927133a in LLVMFuzzerTestOneInput C:\Users\Garrett McParrot\Desktop\0day\shell32an\shell32_pwn_absexp.cpp:25
    #2 0x7ff6792d9bfa in fuzzer::Fuzzer::ExecuteCallback(unsigned char const *, unsigned __int64) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:559
    #3 0x7ff6792db686 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(class std::vector<struct fuzzer::SizedFile, class fuzzer::fuzzer_allocator<struct fuzzer::SizedFile>> &) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:749
    #4 0x7ff6792dbb3a in fuzzer::Fuzzer::Loop(class std::vector<struct fuzzer::SizedFile, class fuzzer::fuzzer_allocator<struct fuzzer::SizedFile>> &) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:800
    #5 0x7ff6792f25d0 in fuzzer::FuzzerDriver(int *, char ***, int (__cdecl *)(unsigned char const *, unsigned __int64)) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:847
    #6 0x7ff6792b4302 in main C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerMain.cpp:20
    #7 0x7ff6792f9f7f in __scrt_common_main_seh d:\agent\_work\2\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #8 0x7ff879377c23  (C:\Windows\System32\KERNEL32.DLL+0x180017c23)
    #9 0x7ff87a70d4d0  (C:\Windows\SYSTEM32\ntdll.dll+0x18006d4d0)

0x102480020440 is located 256 bytes inside of 288-byte region [0x102480020340,0x102480020460)
freed by thread T0 here:
    #0 0x7ff6792b3bab in operator delete(void *, unsigned __int64) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\asan\asan_new_delete.cpp:172
    #1 0x7ff6792b7781 in std::vector<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class fuzzer::fuzzer_allocator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>>::_Tidy(void) C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC\14.23.28105\include\vector:1652
    #2 0x7ff6792e46ae in fuzzer::GetSizedFilesFromDir(class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const &, class std::vector<struct fuzzer::SizedFile, class fuzzer::fuzzer_allocator<struct fuzzer::SizedFile>> *) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerIO.cpp:105
    #3 0x7ff6792f2a9c in fuzzer::ReadCorpora C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:597
    #4 0x7ff6792f25bb in fuzzer::FuzzerDriver(int *, char ***, int (__cdecl *)(unsigned char const *, unsigned __int64)) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:846
    #5 0x7ff6792b4302 in main C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerMain.cpp:20
    #6 0x7ff6792f9f7f in __scrt_common_main_seh d:\agent\_work\2\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #7 0x7ff879377c23  (C:\Windows\System32\KERNEL32.DLL+0x180017c23)
    #8 0x7ff87a70d4d0  (C:\Windows\SYSTEM32\ntdll.dll+0x18006d4d0)

previously allocated by thread T0 here:
    #0 0x7ff6792b2fe4 in operator new(unsigned __int64) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\asan\asan_new_delete.cpp:99
    #1 0x7ff6792cd68d in std::vector<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class fuzzer::fuzzer_allocator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>>::_Emplace_reallocate<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const &>(class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> *const, class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const &) C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC\14.23.28105\include\vector:695
    #2 0x7ff6792e2961 in fuzzer::ListFilesInDirRecursive(class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const &, long *, class std::vector<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class fuzzer::fuzzer_allocator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>> *, bool) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerIOWindows.cpp:137
    #3 0x7ff6792e45ca in fuzzer::GetSizedFilesFromDir(class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const &, class std::vector<struct fuzzer::SizedFile, class fuzzer::fuzzer_allocator<struct fuzzer::SizedFile>> *) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerIO.cpp:101
    #4 0x7ff6792f2a9c in fuzzer::ReadCorpora C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:597
    #5 0x7ff6792f25bb in fuzzer::FuzzerDriver(int *, char ***, int (__cdecl *)(unsigned char const *, unsigned __int64)) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:846
    #6 0x7ff6792b4302 in main C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerMain.cpp:20
    #7 0x7ff6792f9f7f in __scrt_common_main_seh d:\agent\_work\2\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #8 0x7ff879377c23  (C:\Windows\System32\KERNEL32.DLL+0x180017c23)
    #9 0x7ff87a70d4d0  (C:\Windows\SYSTEM32\ntdll.dll+0x18006d4d0)

SUMMARY: AddressSanitizer: heap-use-after-free C:\Users\Garrett McParrot\Desktop\0day\shell32an\shell32_pwn_absexp.cpp:15 in fuzzMeDrZaus(unsigned char const *, unsigned __int64)
Shadow bytes around the buggy address:
  0x020510004030: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x020510004040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x020510004050: 00 00 00 00 00 00 00 00 00 00 00 00 fa fa fa fa
  0x020510004060: fa fa fa fa fa fa fa fa fd fd fd fd fd fd fd fd
  0x020510004070: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
=>0x020510004080: fd fd fd fd fd fd fd fd[fd]fd fd fd fa fa fa fa
  0x020510004090: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0205100040a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0205100040b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0205100040c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0205100040d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==16392==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000


artifact_prefix='./'; Test unit written to ./crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
Base64:
```

A UAF! OK, but now I'm confused... that crash file seems to have no data in it, which is both disallowed by my code, and shouldn't be a thing... so what's up? Well, I need to be more careful. My C++ is not amazing, I can get by, I can look stuff up, I know the logic and patterns of C++ in Windows, but I'm by no means an expert. So even though this "UAF" appears like an amazing win it's not. I recompiled my code with a simple main() function instead of the LLVMFuzzer* function and ran it - it crashed. There was an access violation on the Null page. So clearly this was a me error. After spending some time and ensuring I wasn't causing memory errors from my own code, but instead from the Windows API, I came to the following, along with a simple idea to improve my fuzz power:

```
#include <shlobj.h>
#include <shlobj_core.h>
#include <shlwapi.h>
#include <iostream>
#include <objbase.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int fuzzMeDrZaus(LPCWSTR path, const uint8_t *Data, size_t size)
{
    //LPITEMIDLIST *itemlist;
    ITEMIDLIST *itemlist;
    SHParseDisplayName(path, NULL, &itemlist, NULL, NULL);
    SHGetFolderLocation(0, NULL, 0, 0, &itemlist);
    return 0;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
  LPCWSTR _str = L"C:\\DDDDDDDDDDDDDDDDDDDDDDD\\";
  fuzzMeDrZaus(_str, Data, Size);
  return 0;
};
```

Basically all this does is generate an LPCITEMIDLIST to give to SHGetFolderLocation from a human readable string, in this case C:\DDDDDDDDDDDDDDDDDDDDDDD\. I do run the risk of crashing SHParseDisplayName, but perhaps if I let it run long enough I can get a crash in SHGetFolderLocation. We'll see, so far the problem has been too many, as opposed to not enough, crashes. And boom goes the dynamite:

```
C:\Users\Garrett McParrot\Desktop\0day\shell32an
λ .\shell32_pwn_abs_explicit.exe
INFO: Seed: 1336545127
INFO: Loaded 1 modules   (2 inline 8-bit counters): 2 [00007FF668BE90C8, 00007FF668BE90CA),
INFO: Loaded 1 PC tables (2 PCs): 2 [00007FF668B94718,00007FF668B94738),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 2 ft: 2 corp: 1/1b exec/s: 0 rss: 78Mb
#16384  pulse  cov: 2 ft: 2 corp: 1/1b lim: 163 exec/s: 5461 rss: 87Mb
#32768  pulse  cov: 2 ft: 2 corp: 1/1b lim: 325 exec/s: 6553 rss: 89Mb
#65536  pulse  cov: 2 ft: 2 corp: 1/1b lim: 652 exec/s: 5957 rss: 97Mb
#131072 pulse  cov: 2 ft: 2 corp: 1/1b lim: 1300 exec/s: 5957 rss: 120Mb
#262144 pulse  cov: 2 ft: 2 corp: 1/1b lim: 2611 exec/s: 5957 rss: 196Mb
#524288 pulse  cov: 2 ft: 2 corp: 1/1b lim: 4096 exec/s: 6096 rss: 468Mb
```
Pretty good exec speed so far, let's keep it going. Now I'm kinda curious to run this under WinAFL. It seems all I'd need to do is grab....fuck wait. OK look at my code again, shame on you for not noticing. Do you see anything? Well, as it turns out I forgot to do anything with Data (the variable libFuzzer constantly mutates), so all I was doing was parsing C:\DDDDDDDDDDDDDDDD\ a fuckton of times. That's useless. However I want to somewhat preserve what I'm doing, have a C:\ to start out, and some normal letters after. So I came up with this code:

```
#include <shlobj.h>
#include <shlobj_core.h>
#include <shlwapi.h>
#include <iostream>
#include <objbase.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int fuzzMeDrZaus(LPCWSTR path, const uint8_t *Data, size_t size)
{
    //LPITEMIDLIST *itemlist;
    ITEMIDLIST *itemlist;
    int dataSize = sizeof(Data);
    memcpy(path+0x7, Data, size);
    SHParseDisplayName(path, NULL, &itemlist, NULL, NULL);
    SHGetFolderLocation(0, NULL, 0, 0, &itemlist);
    return 0;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
  LPCWSTR _str = L"C:\\DDDDDDDDDDDDDDDDDDDDDDD\\";
  fuzzMeDrZaus(_str, Data, Size);
  return 0;
};
```

What's that do? Notice the memcpy, that's saying write to an address at 7 bytes into the string using the data provided via the Data variable. The write will be of a size size, which is the variable that holds the size of libFuzzer's data. Let's try that now. I'm out for the night though, picking back up in next post.



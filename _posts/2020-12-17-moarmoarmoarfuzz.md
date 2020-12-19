---
layout: post
title: Moar Fuzz 3 - Electric Tree!!!
tags: [hacking]
---

Sorry for the nonsensical title. I'm a little drunk. Anyway, here's a crash:

```
==15384==ERROR: AddressSanitizer: attempting to call malloc_usable_size() for pointer which is not owned: 0x0000004df3e0
    #0 0x7ff6c5231fd4 in __sanitizer::BufferedStackTrace::UnwindImpl(unsigned __int64, unsigned __int64, void *, bool, unsigned int) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\asan\asan_stack.cpp:77
    #1 0x7ff6c524d646 in __asan::asan_malloc_usable_size(void const *, unsigned __int64, unsigned __int64) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\asan\asan_allocator.cpp:986
    #2 0x7ffeb1b536e8  (C:\Windows\System32\ucrtbase.dll+0x1800136e8)
    #3 0x7ffeb1b53603  (C:\Windows\System32\ucrtbase.dll+0x180013603)
    #4 0x7ffeb1b5349a  (C:\Windows\System32\ucrtbase.dll+0x18001349a)
    #5 0x7ffeb1b5344f  (C:\Windows\System32\ucrtbase.dll+0x18001344f)
    #6 0x7ffeb1b5ab60  (C:\Windows\System32\ucrtbase.dll+0x18001ab60)
    #7 0x7ffeb22d63b1  (C:\Windows\System32\SHELL32.dll+0x1801063b1)
    #8 0x7ffeb22d63d4  (C:\Windows\System32\SHELL32.dll+0x1801063d4)
    #9 0x7ffeb22641f6  (C:\Windows\System32\SHELL32.dll+0x1800941f6)
    #10 0x7ffeb22354a9  (C:\Windows\System32\SHELL32.dll+0x1800654a9)
    #11 0x7ffeb22e11a4  (C:\Windows\System32\SHELL32.dll+0x1801111a4)
    #12 0x7ffeb22e11fb  (C:\Windows\System32\SHELL32.dll+0x1801111fb)
    #13 0x7ffeb222309c  (C:\Windows\System32\SHELL32.dll+0x18005309c)
    #14 0x7ffeb149370f  (C:\Windows\System32\windows.storage.dll+0x1800e370f)
    #15 0x7ffeb14ae1a4  (C:\Windows\System32\windows.storage.dll+0x1800fe1a4)
    #16 0x7ffeb14adaf4  (C:\Windows\System32\windows.storage.dll+0x1800fdaf4)
    #17 0x7ffeb14b0b5e  (C:\Windows\System32\windows.storage.dll+0x180100b5e)
    #18 0x7ffeb14b6a8b  (C:\Windows\System32\windows.storage.dll+0x180106a8b)
    #19 0x7ffeb222b8bb  (C:\Windows\System32\SHELL32.dll+0x18005b8bb)
    #20 0x7ffeb241d731  (C:\Windows\System32\SHELL32.dll+0x18024d731)
    #21 0x7ffeb241d69e  (C:\Windows\System32\SHELL32.dll+0x18024d69e)
    #22 0x7ff6c5211564 in fuzzMeDrZaus(unsigned char const *, unsigned __int64) C:\Users\Garrett McParrot\Desktop\0day\shell32an\shell32_pwn_targeted.cpp:38
    #23 0x7ff6c521173a in LLVMFuzzerTestOneInput C:\Users\Garrett McParrot\Desktop\0day\shell32an\shell32_pwn_targeted.cpp:66
    #24 0x7ff6c5279ffa in fuzzer::Fuzzer::ExecuteCallback(unsigned char const *, unsigned __int64) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:559
    #25 0x7ff6c5279476 in fuzzer::Fuzzer::RunOne(unsigned char const *, unsigned __int64, bool, struct fuzzer::InputInfo *, bool *) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:471
    #26 0x7ff6c527b701 in fuzzer::Fuzzer::MutateAndTestOne(void) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:702
    #27 0x7ff6c527c305 in fuzzer::Fuzzer::Loop(class std::vector<struct fuzzer::SizedFile, class fuzzer::fuzzer_allocator<struct fuzzer::SizedFile>> &) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:838
    #28 0x7ff6c52929d0 in fuzzer::FuzzerDriver(int *, char ***, int (__cdecl *)(unsigned char const *, unsigned __int64)) C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:847
    #29 0x7ff6c5254702 in main C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\fuzzer\FuzzerMain.cpp:20
    #30 0x7ff6c529a38f in __scrt_common_main_seh d:\agent\_work\2\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #31 0x7ffeb2a27c23  (C:\Windows\System32\KERNEL32.DLL+0x180017c23)
    #32 0x7ffeb3e6d4d0  (C:\Windows\SYSTEM32\ntdll.dll+0x18006d4d0)

Address 0x0000004df3e0 is a wild pointer.
SUMMARY: AddressSanitizer: bad-malloc_usable_size C:\src\llvm_package_1100-final\llvm-project\compiler-rt\lib\asan\asan_stack.cpp:77 in __sanitizer::BufferedStackTrace::UnwindImpl(unsigned __int64, unsigned __int64, void *, bool, unsigned int)
==15384==ABORTING
MS: 3 ChangeBit-CopyPart-InsertRepeatedBytes-; base unit: 11f4de6b8b45cf8051b1d17fa4cde9ad935cea41
0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x2d,
\\\\\\\\\\\\\\\\-
artifact_prefix='./'; Test unit written to ./crash-fe9de6e469a7d1a0de1808e18716996947ee2935
Base64: XFxcXFxcXFwt
```

I've confirmed this one, with the simple code:

```
#include <shlobj_core.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <objbase.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//clang-cl.exe /Zi -fsanitize=fuzzer,address -fsanitize-recover=address shell32_pwn.cpp ole32.lib shell32.lib shlwapi.lib

int fuzzMeDrZaus(const uint8_t *Data, size_t size)
{
    //std::cout << size;

    uint8_t new_data_array[size+1];
    PIDLIST_ABSOLUTE pidlAbsolute;
    for(int i = 0; i < size; i++) {

        /*if(Data[i] == 0x00){
            std::cout << "GOT NULL BYTE AT" << i << " SIZE IS" << size;
            break;
        }*/

        if(Data[i] == 0x0a || Data[i] == 0x0d){
            new_data_array[i] = 0x41;
        }
        else {
            new_data_array[i] = Data[i];
        }
    }

    /*for(int i = 0; i < size; i++) {
        std::cout << new_data_array[i]; 
    }*/
    try{
        //std::cout << "GOING TO TRY: " << new_data_array << " TO CREATE PATH";
        pidlAbsolute = ILCreateFromPath((PCTSTR) new_data_array);
    }
    catch(...){
        printf("FAIL");
        return 1;
    }
    SHGetFolderLocation(0, 5, 0, 0, &pidlAbsolute);
    ILFree(pidlAbsolute);

    //printf("RETURNING");
    return 0;
};


int main() {
    //const uint8_t *Data = (const uint8_t *) "C:\\AAA" "\x0a" "\x0d" "AA\\BBBBB\\\x0a";
    //const uint8_t *Data = (const uint8_t *) "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\..";
    const uint8_t Data[] = {0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x41};
    std::cout << sizeof(Data) << "\n\n\n";
    size_t size = sizeof(Data);
    fuzzMeDrZaus(Data, size);
    return 0;
};
/*

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  fuzzMeDrZaus(Data, Size);
  return 0;
}
*/
```

In other words, a bunch of \\'s crashes the ILCreateFromPath API call. Neat. Looks like.. a heap null deref? I dunno, gotta do more research. Anyway enjoy the 0-day!

Anyway I kick this puppy off (wait why am I talking about kicking puppies???):

```
#44650  REDUCE cov: 7 ft: 35 corp: 29/988b lim: 325 exec/s: 2126 rss: 44Mb L: 161/281 MS: 5 EraseBytes-ChangeBinInt-EraseBytes-InsertByte-CopyPart-
#45986  REDUCE cov: 7 ft: 35 corp: 29/984b lim: 333 exec/s: 2189 rss: 44Mb L: 157/281 MS: 1 EraseBytes-
#49814  REDUCE cov: 7 ft: 35 corp: 29/983b lim: 365 exec/s: 2264 rss: 44Mb L: 8/281 MS: 3 EraseBytes-EraseBytes-CopyPart-
#50651  REDUCE cov: 7 ft: 35 corp: 29/969b lim: 373 exec/s: 2302 rss: 44Mb L: 267/267 MS: 2 CrossOver-CopyPart-
#52125  REDUCE cov: 7 ft: 35 corp: 29/955b lim: 381 exec/s: 2266 rss: 44Mb L: 253/253 MS: 4 InsertByte-PersAutoDict-ChangeByte-EraseBytes- DE: "\x09\x00\x00\x00\x00\x00\x00\x00"-
#52464  REDUCE cov: 7 ft: 35 corp: 29/946b lim: 381 exec/s: 2281 rss: 44Mb L: 148/253 MS: 4 ChangeBinInt-PersAutoDict-ShuffleBytes-EraseBytes- DE: "\x01\x0d"-
#52525  REDUCE cov: 7 ft: 35 corp: 29/945b lim: 381 exec/s: 2283 rss: 44Mb L: 18/253 MS: 1 EraseBytes-
#54402  REDUCE cov: 7 ft: 35 corp: 29/944b lim: 397 exec/s: 2365 rss: 44Mb L: 20/253 MS: 2 ShuffleBytes-EraseBytes-
#54593  REDUCE cov: 7 ft: 35 corp: 29/942b lim: 397 exec/s: 2373 rss: 44Mb L: 251/251 MS: 1 EraseBytes-
#55164  REDUCE cov: 7 ft: 35 corp: 29/941b lim: 397 exec/s: 2398 rss: 44Mb L: 51/251 MS: 1 EraseBytes-
#55785  REDUCE cov: 7 ft: 35 corp: 29/940b lim: 397 exec/s: 2324 rss: 44Mb L: 19/251 MS: 1 EraseBytes-
#58971  REDUCE cov: 7 ft: 35 corp: 29/939b lim: 421 exec/s: 2457 rss: 44Mb L: 33/251 MS: 1 EraseBytes-
#59209  REDUCE cov: 7 ft: 35 corp: 29/934b lim: 421 exec/s: 2467 rss: 44Mb L: 246/246 MS: 3 ChangeBinInt-ChangeBit-EraseBytes-
#65536  pulse  cov: 7 ft: 35 corp: 29/934b lim: 477 exec/s: 2520 rss: 44Mb
#69806  REDUCE cov: 7 ft: 35 corp: 29/933b lim: 526 exec/s: 2585 rss: 44Mb L: 17/246 MS: 2 CopyPart-EraseBytes-
#70222  REDUCE cov: 7 ft: 35 corp: 29/924b lim: 526 exec/s: 2600 rss: 44Mb L: 237/237 MS: 1 EraseBytes-
#77271  REDUCE cov: 7 ft: 35 corp: 29/923b lim: 589 exec/s: 2664 rss: 44Mb L: 18/237 MS: 4 ShuffleBytes-ShuffleBytes-ShuffleBytes-EraseBytes-
#77327  REDUCE cov: 7 ft: 35 corp: 29/922b lim: 589 exec/s: 2666 rss: 44Mb L: 50/237 MS: 1 EraseBytes-
#78693  REDUCE cov: 7 ft: 35 corp: 29/916b lim: 598 exec/s: 2713 rss: 44Mb L: 231/231 MS: 1 CrossOver-
#81500  REDUCE cov: 7 ft: 35 corp: 29/909b lim: 625 exec/s: 2716 rss: 44Mb L: 224/224 MS: 2 InsertByte-EraseBytes-
#82012  REDUCE cov: 7 ft: 35 corp: 29/908b lim: 625 exec/s: 2733 rss: 44Mb L: 223/223 MS: 2 PersAutoDict-EraseBytes- DE: "\x01\x0d"-
#92904  REDUCE cov: 7 ft: 35 corp: 29/904b lim: 733 exec/s: 2815 rss: 44Mb L: 219/219 MS: 2 ChangeBit-EraseBytes-
#93906  REDUCE cov: 7 ft: 35 corp: 29/903b lim: 742 exec/s: 2845 rss: 44Mb L: 218/218 MS: 2 CopyPart-EraseBytes-
#100687 REDUCE cov: 7 ft: 35 corp: 29/902b lim: 805 exec/s: 2876 rss: 44Mb L: 8/218 MS: 1 EraseBytes-
#101880 REDUCE cov: 7 ft: 35 corp: 29/901b lim: 814 exec/s: 2910 rss: 44Mb L: 49/218 MS: 3 EraseBytes-EraseBytes-CopyPart-
#102658 REDUCE cov: 7 ft: 35 corp: 29/900b lim: 814 exec/s: 2851 rss: 44Mb L: 48/218 MS: 3 ChangeBit-EraseBytes-CopyPart-
#103319 REDUCE cov: 7 ft: 35 corp: 29/897b lim: 814 exec/s: 2869 rss: 44Mb L: 45/218 MS: 1 EraseBytes-
#104417 REDUCE cov: 7 ft: 35 corp: 29/896b lim: 823 exec/s: 2900 rss: 44Mb L: 44/218 MS: 3 ShuffleBytes-ShuffleBytes-EraseBytes-
#107483 REDUCE cov: 7 ft: 35 corp: 29/894b lim: 850 exec/s: 2904 rss: 44Mb L: 216/216 MS: 1 EraseBytes-
#112952 REDUCE cov: 7 ft: 35 corp: 29/888b lim: 904 exec/s: 2972 rss: 44Mb L: 210/210 MS: 4 ShuffleBytes-InsertByte-EraseBytes-CopyPart-
#120456 REDUCE cov: 7 ft: 35 corp: 29/887b lim: 976 exec/s: 3011 rss: 44Mb L: 43/210 MS: 4 ShuffleBytes-PersAutoDict-ShuffleBytes-EraseBytes- DE: "\x01\x0d"-
#122067 REDUCE cov: 7 ft: 35 corp: 29/886b lim: 985 exec/s: 2977 rss: 44Mb L: 147/210 MS: 1 EraseBytes-
#127516 REDUCE cov: 7 ft: 35 corp: 29/885b lim: 1030 exec/s: 3036 rss: 44Mb L: 16/210 MS: 4 CopyPart-EraseBytes-CrossOver-CopyPart-
#131072 pulse  cov: 7 ft: 35 corp: 29/885b lim: 1060 exec/s: 3048 rss: 44Mb
```

Let's see if that gets us anywhere besides a crash in the same place. Remember I'm looking for a crash just a couple lines down. If this fails, what I'll do is likely this: take a valid structure created by ILCreateFromPath, add it to a bunch of corpus files, and then run `SHGetFolderLocation(0, 5, 0, 0, &pidlAbsolute);`. Remember the main reason we're doing all of this is to hit that function, why??? Because it runs whenever `explorer.exe <folder>` is run. It would be a fun 0-day to have a folder with a name that would own the OS wouldn't it!?!? Yes, yes it would. 

Anyway, while that's running we should do some more hunting right?? Yes, so let's fuzz libexpat on Ubuntu Linux x64 using AFL++. I've done this before and I know that if I let it run for about a week, I get about 5 unique crashes, mostly null derefs. Because I've promised myself to do a 20 days of 0day this should be fairly useful. Let's see how that's done. First, I clone the repo for AFL++, then the equivalent of windows "just click next" by typing `make`. Where I see it build:

```
*] Testing the CC wrapper afl-gcc and its instrumentation output...
afl-cc ++3.00c by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: GCC-DEFAULT
afl-as++3.00c by Michal Zalewski
[+] Instrumented 18 locations (64-bit, non-hardened mode, ratio 100%).
ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
echo 1 | ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr1 ./test-instr

[+] All right, the instrumentation of afl-gcc seems to be working!
[+] Main compiler 'afl-cc' successfully built!
[-] LLVM mode for 'afl-cc'  failed to build, likely you either don't have llvm installed, or you need to set LLVM_CONFIG, to point to e.g. llvm-config-11. See instrumentation/README.llvm.md how to do this. Highly recommended!
[-] LLVM LTO mode for 'afl-cc'  failed to build, this would need LLVM 11+, see instrumentation/README.lto.md how to build it
[-] gcc_plugin for 'afl-cc'  failed to build, unless you really need it that is fine - or read instrumentation/README.gcc_plugin.md how to build it
[+] All done! Be sure to review the README.md - it's pretty short and useful.
```

Aaaand it's done. Let's get this fuzzer going and I'll keep hunting in the Shell32 API. BUT FIRST

## Now for something completely different

Variety is the spice of life and I've been hunting in the shell32 API fruitfully for a while. But I'm starting to get pretty in-depth into it. I've found that both a deep understanding of it as well as fuzzing and RE have been the key. But are there other ways to hunt? Yep, there are! And it never hurts to kick off a simple fuzzer and depend on blind luck as opposed to a deep understanding to find some 0-days. So let's see what that looks like, this time I'm on Ubuntu x64 and I'm going to hunt in libexpat. libexpat is an XML library that's used fucking everywhere (looks it up, it's true, it's even in the BSD kernel). Even a DoS could lead to some interesting weaponizations, so let's see how we can quickly kick off a fuzzer and continue with our shell32 API hunt. 

OK so let's say we're in a time crunch and we don't really want to understand what's going on, but still want to fuzz something. This is my favorite dumbass trick. Clone the libexpat repo: https://github.com/libexpat/libexpat, grab AFL++ https://github.com/AFLplusplus/AFLplusplus and compile it. On Ubuntu all I had to do was install build-essential and clang (the latter is likely unnecessary) as well as autoconf for libexpat. Once all is done, AFL++ will look like this:

```
punk@punkserv ~/T/AFLplusplus (stable)> ls
afl-analyze*  afl-clang-fast@       afl-gcc@            afl-wine-trace*   dictionaries/           instrumentation/     testcases/
afl-as*       afl-clang-fast++@     afl-gotcpu*         Android.bp        Dockerfile              LICENSE              test-instr.c
afl-c++@      afl-cmin*             afl-llvm-rt-64.o@   Android.mk@       docs/                   Makefile             TODO.md
afl-c++.8@    afl-cmin.bash*        afl-plot*           as@               dynamic_list.txt        qemu_mode/           types.h@
afl-cc*       afl-compiler-rt-64.o  afl-showmap*        Changelog.md@     GNUmakefile             QuickStartGuide.md@  unicorn_mode/
afl-cc.8      afl-compiler-rt.o     afl-system-config*  config.h@         GNUmakefile.gcc_plugin  README.md            utils/
afl-clang@    afl-fuzz*             afl-tmin*           CONTRIBUTING.md   GNUmakefile.llvm        src/
afl-clang++@  afl-g++@              afl-whatsup*        custom_mutators/  include/                test/
punk@punkserv ~/T/AFLplusplus (stable)> 
```

Most importantly here, we'll be using afl-clang and afl-clang++. Make note of where they're at. Build libexpat with the AFL versions of shit, clang is best, so something like this:

```
$ CC=/home/punk/Tools/AFLplusplus/afl-clang CXX=/home/punk/Tools/AFLplusplus/afl-clang++ ./buildconf.sh
$ CC=/home/punk/Tools/AFLplusplus/afl-clang CXX=/home/punk/Tools/AFLplusplus/afl-clang++ ./configure
$ CC=/home/punk/Tools/AFLplusplus/afl-clang CXX=/home/punk/Tools/AFLplusplus/afl-clang++ make
```

Then pop yourself on over to the `examples/` dir, and check out elements.c, look at like this:

```
/* This is simple demonstration of how to use expat. This program
   reads an XML document from standard input and writes a line with
   the name of each element to standard output indenting child
   elements by one tab stop more than their parent element.
   It must be used with Expat compiled for UTF-8 output.
                            __  __            _
                         ___\ \/ /_ __   __ _| |_
                        / _ \\  /| '_ \ / _` | __|
                       |  __//  \| |_) | (_| | |_
                        \___/_/\_\ .__/ \__,_|\__|
                                 |_| XML parser

   Copyright (c) 1997-2000 Thai Open Source Software Center Ltd
   Copyright (c) 2000-2017 Expat development team
   Licensed under the MIT license:

   Permission is  hereby granted,  free of charge,  to any  person obtaining
   a  copy  of  this  software   and  associated  documentation  files  (the
   "Software"),  to  deal in  the  Software  without restriction,  including
   without  limitation the  rights  to use,  copy,  modify, merge,  publish,
   distribute, sublicense, and/or sell copies of the Software, and to permit
   persons  to whom  the Software  is  furnished to  do so,  subject to  the
   following conditions:

   The above copyright  notice and this permission notice  shall be included
   in all copies or substantial portions of the Software.

   THE  SOFTWARE  IS  PROVIDED  "AS  IS",  WITHOUT  WARRANTY  OF  ANY  KIND,
   EXPRESS  OR IMPLIED,  INCLUDING  BUT  NOT LIMITED  TO  THE WARRANTIES  OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
   NO EVENT SHALL THE AUTHORS OR  COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
   DAMAGES OR  OTHER LIABILITY, WHETHER  IN AN  ACTION OF CONTRACT,  TORT OR
   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
   USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <expat.h>

#ifdef XML_LARGE_SIZE
#  define XML_FMT_INT_MOD "ll"
#else
#  define XML_FMT_INT_MOD "l"
#endif

#ifdef XML_UNICODE_WCHAR_T
#  include <wchar.h>
#  define XML_FMT_STR "ls"
#else
#  define XML_FMT_STR "s"
#endif

static void XMLCALL
startElement(void *userData, const XML_Char *name, const XML_Char **atts) {
  int i;
  int *depthPtr = (int *)userData;
  (void)atts;

  for (i = 0; i < *depthPtr; i++)
    putchar('\t');
  printf("%" XML_FMT_STR "\n", name);
  *depthPtr += 1;
}

static void XMLCALL
endElement(void *userData, const XML_Char *name) {
  int *depthPtr = (int *)userData;
  (void)name;

  *depthPtr -= 1;
}

int
main(int argc, char *argv[]) {
  char buf[BUFSIZ];
  XML_Parser parser = XML_ParserCreate(NULL);
  int done;
  int depth = 0;
  (void)argc;
  (void)argv;

  XML_SetUserData(parser, &depth);
  XML_SetElementHandler(parser, startElement, endElement);
  do {
    size_t len = fread(buf, 1, sizeof(buf), stdin);
    done = len < sizeof(buf);
    if (XML_Parse(parser, buf, (int)len, done) == XML_STATUS_ERROR) {
      fprintf(stderr, "%" XML_FMT_STR " at line %" XML_FMT_INT_MOD "u\n",
              XML_ErrorString(XML_GetErrorCode(parser)),
              XML_GetCurrentLineNumber(parser));
      XML_ParserFree(parser);
      return 1;
    }
  } while (! done);
  XML_ParserFree(parser);
  return 0;
}
```

ah-ha, we have found an example program that uses some relevant APIs. Wouldn't it be nice to use this as a harness?? Sure, but it's got some problems. First of all see all those mentions to stdin? Well, fuck that, AFL requires you take in a file. So let's hack this apart and make it accept a file at gunpoint:

```
punk@punkserv ~/0/l/e/examples (master)> cat elements.c 
/* This is simple demonstration of how to use expat. This program
   reads an XML document from standard input and writes a line with
   the name of each element to standard output indenting child
   elements by one tab stop more than their parent element.
   It must be used with Expat compiled for UTF-8 output.
                            __  __            _
                         ___\ \/ /_ __   __ _| |_
                        / _ \\  /| '_ \ / _` | __|
                       |  __//  \| |_) | (_| | |_
                        \___/_/\_\ .__/ \__,_|\__|
                                 |_| XML parser

   Copyright (c) 1997-2000 Thai Open Source Software Center Ltd
   Copyright (c) 2000-2017 Expat development team
   Licensed under the MIT license:

   Permission is  hereby granted,  free of charge,  to any  person obtaining
   a  copy  of  this  software   and  associated  documentation  files  (the
   "Software"),  to  deal in  the  Software  without restriction,  including
   without  limitation the  rights  to use,  copy,  modify, merge,  publish,
   distribute, sublicense, and/or sell copies of the Software, and to permit
   persons  to whom  the Software  is  furnished to  do so,  subject to  the
   following conditions:

   The above copyright  notice and this permission notice  shall be included
   in all copies or substantial portions of the Software.

   THE  SOFTWARE  IS  PROVIDED  "AS  IS",  WITHOUT  WARRANTY  OF  ANY  KIND,
   EXPRESS  OR IMPLIED,  INCLUDING  BUT  NOT LIMITED  TO  THE WARRANTIES  OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
   NO EVENT SHALL THE AUTHORS OR  COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
   DAMAGES OR  OTHER LIABILITY, WHETHER  IN AN  ACTION OF CONTRACT,  TORT OR
   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
   USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <expat.h>

#ifdef XML_LARGE_SIZE
#  define XML_FMT_INT_MOD "ll"
#else
#  define XML_FMT_INT_MOD "l"
#endif

#ifdef XML_UNICODE_WCHAR_T
#  include <wchar.h>
#  define XML_FMT_STR "ls"
#else
#  define XML_FMT_STR "s"
#endif

static void XMLCALL
startElement(void *userData, const XML_Char *name, const XML_Char **atts) {
  int i;
  int *depthPtr = (int *)userData;
  (void)atts;

  for (i = 0; i < *depthPtr; i++)
    putchar('\t');
  printf("%" XML_FMT_STR "\n", name);
  *depthPtr += 1;
}

static void XMLCALL
endElement(void *userData, const XML_Char *name) {
  int *depthPtr = (int *)userData;
  (void)name;

  *depthPtr -= 1;
}

int
main(int argc, char *argv[]) {

  FILE *fp;
  size_t sz;
  fp = fopen (argv[1], "r");
  fseek(fp, 0L, SEEK_END);
  sz = ftell(fp);
  rewind(fp);
  char buf[sz];
  XML_Parser parser = XML_ParserCreate(NULL);
  int done;
  int depth = 0;
  //(void)argc;
  //(void)argv;

  XML_SetUserData(parser, &depth);
  XML_SetElementHandler(parser, startElement, endElement);
  do {
    size_t len = fread(buf, 1, sizeof(buf), fp);
    done = len < sizeof(buf);
    if (XML_Parse(parser, buf, (int)len, done) == XML_STATUS_ERROR) {
      fprintf(stderr, "%" XML_FMT_STR " at line %" XML_FMT_INT_MOD "u\n",
              XML_ErrorString(XML_GetErrorCode(parser)),
              XML_GetCurrentLineNumber(parser));
      XML_ParserFree(parser);
      return 1;
    }
  } while (! done);
  XML_ParserFree(parser);
  return 0;
}
```

Boom, that should do it. Only a few lines changed there, specifically we're getting the filesize in bytes and allocating a buffer just big enough to hold it. That should be good. Now pay attention to the following because it's a very common pattern with programs that use `configure` and `make`. The `example/` dir has it's own makefile, nice, we don't have to recompile all of libexpat. So check it:

```
punk@punkserv ~/0/l/e/examples (master)> CC=/home/punk/Tools/AFLplusplus/afl-clang CXX=/home/punk/Tools/AFLplusplus/afl-clang++ make
/home/punk/Tools/AFLplusplus/afl-clang -DHAVE_CONFIG_H -I. -I..  -DHAVE_EXPAT_CONFIG_H -DXML_ENABLE_VISIBILITY=1 -I./../lib  -Wall -Wextra -fexceptions -fno-strict-aliasing -Wmissing-prototypes -Wstrict-prototypes -pedantic -Wnull-dereference -Wdouble-promotion -Wshadow -Wformat=2 -Wmisleading-indentation -fvisibility=hidden -g -O2 -MT elements.o -MD -MP -MF .deps/elements.Tpo -c -o elements.o elements.c
afl-cc ++3.00c by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: GCC-DEFAULT
elements.c:74:10: warning: unused parameter 'argc' [-Wunused-parameter]
main(int argc, char *argv[]) {
         ^
1 warning generated.
afl-as++3.00c by Michal Zalewski
[+] Instrumented 7 locations (64-bit, non-hardened mode, ratio 100%).
mv -f .deps/elements.Tpo .deps/elements.Po
/bin/bash ../libtool  --tag=CC   --mode=link /home/punk/Tools/AFLplusplus/afl-clang -Wall -Wextra -fexceptions -fno-strict-aliasing -Wmissing-prototypes -Wstrict-prototypes -pedantic -Wnull-dereference -Wdouble-promotion -Wshadow -Wformat=2 -Wmisleading-indentation -fvisibility=hidden -g -O2 -fno-strict-aliasing  -o elements elements.o ../lib/libexpat.la 
libtool: link: /home/punk/Tools/AFLplusplus/afl-clang -Wall -Wextra -fexceptions -fno-strict-aliasing -Wmissing-prototypes -Wstrict-prototypes -pedantic -Wnull-dereference -Wdouble-promotion -Wshadow -Wformat=2 -Wmisleading-indentation -fvisibility=hidden -g -O2 -fno-strict-aliasing -o .libs/elements elements.o  ../lib/.libs/libexpat.so
afl-cc ++3.00c by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: GCC-DEFAULT
/home/punk/Tools/AFLplusplus/afl-clang -DHAVE_CONFIG_H -I. -I..  -DHAVE_EXPAT_CONFIG_H -DXML_ENABLE_VISIBILITY=1 -I./../lib  -Wall -Wextra -fexceptions -fno-strict-aliasing -Wmissing-prototypes -Wstrict-prototypes -pedantic -Wnull-dereference -Wdouble-promotion -Wshadow -Wformat=2 -Wmisleading-indentation -fvisibility=hidden -g -O2 -MT outline.o -MD -MP -MF .deps/outline.Tpo -c -o outline.o outline.c
afl-cc ++3.00c by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: GCC-DEFAULT
afl-as++3.00c by Michal Zalewski
[+] Instrumented 11 locations (64-bit, non-hardened mode, ratio 100%).
mv -f .deps/outline.Tpo .deps/outline.Po
/bin/bash ../libtool  --tag=CC   --mode=link /home/punk/Tools/AFLplusplus/afl-clang -Wall -Wextra -fexceptions -fno-strict-aliasing -Wmissing-prototypes -Wstrict-prototypes -pedantic -Wnull-dereference -Wdouble-promotion -Wshadow -Wformat=2 -Wmisleading-indentation -fvisibility=hidden -g -O2 -fno-strict-aliasing  -o outline outline.o ../lib/libexpat.la 
libtool: link: /home/punk/Tools/AFLplusplus/afl-clang -Wall -Wextra -fexceptions -fno-strict-aliasing -Wmissing-prototypes -Wstrict-prototypes -pedantic -Wnull-dereference -Wdouble-promotion -Wshadow -Wformat=2 -Wmisleading-indentation -fvisibility=hidden -g -O2 -fno-strict-aliasing -o .libs/outline outline.o  ../lib/.libs/libexpat.so
afl-cc ++3.00c by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: GCC-DEFAULT
punk@punkserv ~/0/l/e/examples (master)> ls
elements*  elements.c  elements.o  Makefile  Makefile.am  Makefile.in  outline*  outline.c  outline.o  sample.xml
punk@punkserv ~/0/l/e/examples (master)> cd .libs/
punk@punkserv ~/0/l/e/e/.libs (master)> ls
elements*  outline*
punk@punkserv ~/0/l/e/e/.libs (master)> mv ../sample.xml .
punk@punkserv ~/0/l/e/e/.libs (master)> ls
elements*  outline*  sample.xml
punk@punkserv ~/0/l/e/e/.libs (master)> ./elements sample.xml 
letter
	title
	salutation
	text
		emphasis
		component
		component
	title
	text
	greetings
	signature
	address
	address
	weblink
	logo
```

Alright, so we have this working, it's parsing the XML file and returning the relevant info. 

Let's also build a small corpus of XML files. The rule of thumb for AFL++: small, separate files, each with different attributes/things to parse. I'm not being careful here because I just want to get a fuzz running, but that looks something like this:

```
punk@punkserv ~/0/l/e/e/.libs (master)> mv ../elements *.xml CORPUS/
fish: No matches for wildcard “*.xml”. See `help expand`.
mv ../elements *.xml CORPUS/
               ^
punk@punkserv ~/0/l/e/e/.libs (master) [124]> mv ../*.xml CORPUS/
punk@punkserv ~/0/l/e/e/.libs (master)> ls CORPUS/
cd_catalog.xml  plant_catalog.xml  simple2.xml  simple.xml
punk@punkserv ~/0/l/e/e/.libs (master)> ls
CORPUS/  elements*  outline*
punk@punkserv ~/0/l/e/e/.libs (master)> ls CORPUS/
cd_catalog.xml  plant_catalog.xml  simple2.xml  simple.xml
punk@punkserv ~/0/l/e/e/.libs (master)> ls
CORPUS/  elements*  outline*
punk@punkserv ~/0/l/e/e/.libs (master)> ./elements CORPUS/cd_catalog.xml 
punk@punkserv ~/0/l/e/e/.libs (master)>  
```

Now notice the following lines and I'll describe wtf is going on:

```
punk@punkserv ~/0/l/e/e/.libs (master)> pwd
/home/punk/0daze/libexpat/expat/examples/.libs
punk@punkserv ~/0/l/e/e/.libs (master)> ls ../
elements*  elements.c  elements.o  Makefile  Makefile.am  Makefile.in  outline*  outline.c  outline.o
```

OK the example programs are located in `/home/punk/0daze/libexpat/expat/examples/.libs`, in other words in a hidden folder in `examples/`. This is a common point of confusion as if you look one folder back, an executable `elements` file also exists. This file is a SHELL SCRIPT, and not the actual compiled C program. If you pass a shell script to AFL it will yell at you and make you feel small. This is a very common pattern so worth noting: with build systems like this, make sure you're always using the compiled file. Anyway, with that in mind you'll also notice that I ran `./elements cd_catalog.xml` and didn't get any funky errors OR output. I've successfully taken out the part where it writes to stdout, saving me precious cycles. Now let's prep to run AFL:

```
root@punkserv:/home/punk/0daze/libexpat/expat/examples/.libs#     echo core >/proc/sys/kernel/core_pattern
```

and check out my dir:

```
punk@punkserv:~/0daze/libexpat/expat/examples/.libs$ ls
CORPUS  elements  OUT  outline
punk@punkserv:~/0daze/libexpat/expat/examples/.libs$ mv /home/punk/Downloads/*.xml CORPUS/
punk@punkserv:~/0daze/libexpat/expat/examples/.libs$ cd CORPUS/
punk@punkserv:~/0daze/libexpat/expat/examples/.libs/CORPUS$ ls
Sample-employee-XML-file.xml  sample.xml  Sample-XML-Files.xml  Sample-XML-With-Multiple-Records.xml  Simple-XML-file-for-student-details.xml
punk@punkserv:~/0daze/libexpat/expat/examples/.libs/CORPUS$ cd ..
punk@punkserv:~/0daze/libexpat/expat/examples/.libs$ ls
CORPUS  elements  OUT  outline
punk@punkserv:~/0daze/libexpat/expat/examples/.libs$ /home/punk/Tools/AFLplusplus/afl-fuzz -i CORPUS/ -o OUT -- ./elements @@
```

Press enter and:

![/assets/img/afl-run.PNG](/assets/img/afl-run.PNG)



I ran this a while back and I know there's some easy 0-days in there. Nothing super interesting, but I had about 5 unique crashes of varying types. I did not keep that data because I'm an idiot, but I hope to get that back. If you don't get crashes immediately, don't get discouraged, remember this is a "dumb" untargeted approach, so give it a week or two to find things. I promise you you'll find some null derefs in major programs at the very least. The next step is take a look at where the libs you fuzz are used:

https://libexpat.github.io/doc/users/

So now this dumb approach that is unlikely to net me anything huge in a hardened library could lead to 0-days in hundreds of other programs. Not bad for a dumb approach huh? Anyway, back to our regularly scheduled smart approach against explorer.exe

##Continuing explorer.exe






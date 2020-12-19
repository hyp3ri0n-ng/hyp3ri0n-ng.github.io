
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

In other words, a bunch of \'s crashes the ILCreateFromPath API call. Neat. Looks like.. a heap null deref? I dunno, gotta do more research. Anyway enjoy the 0-day!

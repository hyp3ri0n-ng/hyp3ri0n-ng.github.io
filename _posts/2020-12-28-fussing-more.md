---
layout: post
title: Fusssing
tags: [hacking]
---

Alright tired today but doing two things. One fuzzing:

```
/*
SHSTDAPI SHParseDisplayName(
  PCWSTR           pszName,
  IBindCtx         *pbc,
  PIDLIST_ABSOLUTE *ppidl,
  SFGAOF           sfgaoIn,
  SFGAOF           *psfgaoOut
);
*/
#include <shlobj_core.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <objbase.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>



int OohBabyIneedSomeFuzz(const uint8_t *Data) {

    ULONG *ulong;
    LPCWSTR str2 = (const wchar_t *) Data;

    PIDLIST_ABSOLUTE *pidlAbsolute;
    SHParseDisplayName(
        str2,
        NULL,
        pidlAbsolute,
        SFGAO_BROWSABLE,
        ulong
    );
    return 0;
}


int main() {

  

  return 0;
}

/*
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  OohBabyIneedSomeFuzz(Data);
  return 0;
}
*/
```

Simple fuzz of `SHParseDisplayName`, this time I'm doing more testing to ensure I get the LPCWSTR type right. That's why I have that empty main. More on that later.

Second, kicked off (or rather started again) a fuzz of libexpat. It's running on a 32 core system and going at ~4k/sec executions. Not bad AFL++. I'll update with results. Because I'm tired I'm going to have problems really doing some hardcore hunting. Not necessarily a bad thing, let's do some easy stuff and go from there.

One thing I need to be careful about that's been brought  to my attention (by me), is that you can't just cast a char type (uint_8 \* == unsigned char \*) to a wchar. That's gonig to cause weird undefined behavior. So I have ot use something like mbstowstr or the like to convert it all to UTF-16, the default in windows and what we saw when we popped all this in debugger. Coming soon to a theater near you.

OK so I've actually spent most of the day playing with C++ types, specifically how to convert a uint8_t (raw word) into a wchar_t (wide word/quad word). It's not altogether THAT simple, but also not that hard, especially after having done it. Here's the right way to do it:

```
#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <iostream>

int fuzz(const char chars[])
{

size_t size = sizeof(chars);
//printf("%zu", size);
size_t sizew_t = size * 2;
//printf("=====%zu=====\n", sizew_t);
wchar_t pwcs[sizew_t + 2];

mbstowcs(pwcs, chars, sizew_t);
//printf("%ls\n", pwcs);

return 0;

}


/*
int main() {

    //const uint8_t chars[] = {0x0a,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0xc8,0x0a};

    const uint8_t chars[] = {0x41,0x41,0x41};

    char *cchars = (char *) chars;
    fuzz(cchars);


}
*/

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
   char *data_chars = (char *) Data;
  fuzz(data_chars);
  return 0;
}
```

Cool so I kicked off that fuzzer, and it looks like I may have gotten lucky. That big long commented out string? That comes from a report Stack Buffer Overflow `in SHParseDisplayName`:

![/assets/img/bof.png](bof.png)

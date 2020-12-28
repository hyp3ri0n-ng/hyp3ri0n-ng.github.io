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



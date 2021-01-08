## Driver Tut

Well, it's back to my roots boys. No I'm not watching the show roots with Levar Burton playing his iconic role as Kunta Kintay, though I do recommend that, I'm going to talk to you about DRIVERS. WDM Drivers to be exact. In my last post I found a hacky way to brute force some devices, well guess what? It didn't work. Why? I could blame NCC Group's DIBF. Actually let's. I SPECIFICALLY told it to only enumerate IOCTLs, but inevitably I found it fuzzing ioctls after the brute force. This I did not want. So I figure, let's talk about what a driver looks like, how it interacts with the kernel, how to build one, how to query information from one/get it to do stuff, and finally some weak points all culminating in a simple driver enumerator and fuzzer. OK let's go. I'm starting off here:

```
#include <ntddk.h>


void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("YO THIS DRIVER BE UNLOADED"));
}


extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("YO YO YO THIS IS A NEW DRIVER!"));


	return STATUS_SUCCESS;
}
```

Notice the DriverEntry which is a driver's main() equivalent (or winmain() for you windows weirdos). Note i also have an unload routine that does absolutely nothing. Now when doing kernel programming we don't STRICTLY have all C++ functionality, we have most of it, but not all of it. new, delete, exception handling, all of these are things that won't compile in a driver. Already a first glimpse of why there are so many vulnerable drivers. They seem to vaguely follow the rules in a weird strict sense, but for example prefer undefined behavior over throwing an exception (because exceptions don't exist). What's worse, if there is an exception we don't just crash the driver, we BSOD the box. That's pretty lame but OK. Is what it is. Some things are still normal like NTSTATUS is used and a 0 code means all is well, while negative means something failed horribly. 

Instead of exceptions the way we work with drivers are if/then statements. IF our ntstatus != 0 then do something about it, unload the driver, whatever, just handle it.  We get our errors usually through the kernel, the error propagates through the kernel and we end up shoving the information to a pointer in memory that points to some kernel error. Kernel erros are very distinct from user-mode errors, keep that in mind, for example a common user-mode error is 128, I froget what it is, I just remember seeing it a lot, and I just said kernel driver errors were negative. So that's all fucked up. This is quickly becoming a post on why drivers are all fucked up, I like it.

Even strings are fucked up. You know how C has the pretty basic char array with null terminator at the end? NNOOOPPEEE, fuck you, the windows kernel uses UTF-16 (wtf?) and the strings are \_UNICODE\_STRUCTUREs. Therse are structures that give the length of the string, the MAXIMUM length of the string (wut?), and a buffer. This buffer can be used to go fuck yourself or to allocated pooled memory to (discussed later, the pool thing, not fucking yuourself, presumably you know how to do that).

But not all is lost - the kernel has implementred the Rtl* class of functions along with the typical C-string functions modified to work on these weirdo structures. So it's workable when you're programming, if you're reverse enginering you'll wonder why strcpy doesn't stop at a \x00 but instead has a bunch of \x00s intermittently throughout a readable string (an A for example would be \x41\x00 due to little endianness). There's no heap in kernel-land either, the equivalent are Paged and Non-paged pools. A paged pool is a memory pool that is not yet but can be backed up with physical memory and a Non-paged pool is a guaranteed physically-backed structure. Soem structures require non-paged pools be used, but in all other cases windows recommends that you use paged-pools as they'll always be available and won't cause a page fault. The functions to allocated pools are the ExAllocatedPool(WithTag)[WithQquotaTag]. They're not all that different from each other. Note these as attack surface area similar to heap overflow territory.

Here's the most confusing fucking way (and right way) to deal with strings in the kernel, example is from Pavel Yosifovich kernel-master-sensei-dragon-eagle:

```
UNICODE_STRING g_registryPath;

#include <ntddk.h>


void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("YO THIS DRIVER BE UNLOADED"));
}


extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {

  g_registryPath.Buffer = (WCHAR *)ExAllocatePoolWithTag(PagedPool, RegistryPath->Length, DRIVER_TAG);
  
   /*
   PVOID ExAllocatePoolWithTag(
      __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
      SIZE_T                                         NumberOfBytes,
      ULONG                                          Tag
    );
   */
  
  if (registryPath.Buffer == nullptr) {
    KdPrint(("Failed to Allocate Resources));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  g_registryPath.MaximumLength = RegistryPath->Length;
  RtlCopyUnicodeString(&g_registryPath, (PUNICODE_STRING)RegistryPath);
  
  KdPrint(("Copied Registry Path: %^wZ\n", &g_RegistryPath));
  
  ExFreePool(g_registryPath.Buffer);

	return STATUS_SUCCESS;
}
```

And that's how you work with strings! How many rules of programming did I just break there? OK, let's start with the global definition of `g_registryPath` nto strictly necessary in my example, but in Pavel's it was because he frees the pool on DriverUnload routine. I'm doing one of the worst things a developer can do and COUNTING THINGS. We can't be trusted with that, that's how overflows happen and I shouldn't be dealing with lengths here. Anyway, all of that code is pretty confusing to me just to copy the registry path to be used in two functions and printed out. Even KdPrint takes TWO parentheses instead of one. Wtf? Why would you even do that?!

Whatever. Anyway, let's talk about lists. In particular the circular doubly linked lists of the EPROCESS structure. These are worth noting because when we get to exploitation, it almost always involves fucking with the EPROCESS structure as it contains security attributes, tokens, that kind of thing. If you're familiar with doubly linked lists they look like this:

typedef struct \_LIST\_ENTRY {
    struct \_LIST\_ENTRY\* Flink;
    struct \_LIST\_ENTRY\* Blink;
} LIST_ENTRY, \*PLIST_ENTRY

meaning that for example an EPROCESS structure will point to the next one (and the one before it). The kernel is a weird soup of linkage in that LISTs have properties that are in themselves LISTS that are also doubly linked. Too deal with that, this is again an example from Pavel "12 inch kernel penis" Yosifovich which points out that the macro CONTAINING_RECORD comes in very useful in the kernel. For example, the EPROCESS structure has an ActiveProcessLinks of type LIST\_ENTRY. The head of the structure (it's doubly linked not circular) is pointed to by the PsActiveProcessHead.

The CONTAINING_RECORD macro returns the base address of an instance of a structure given the type of the structure and the address of a field within the containing structure. That sounds confusing so maybe an example is in order.


```
typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;

}LIST_ENTRY,*PLIST_ENTRY;
```

The above is a standard LIST_ENTRY. You have a user-defined struct like:

```
typedef struct newstruct
{
    int num1;
    int num2;
    char alpha;
    LIST_ENTRY list_entry;
    float exp;

}MYSTRUCT,*PMYSTRUCT;
```
Note the LIST_ENTRY field there, now a member of ANOTHER STRUCTURE. The CONTAINING_RECORD macro:

```
//
// CONTAINING_RECORD macro
//Gets the value of structure member (field),given the type(MYSTRUCT, in this code) and the List_Entry head(temp, in this code)
//
#define CONTAINING_RECORD(address, type, field) (\
    (type *)((char*)(address) -(unsigned long)(&((type *)0)->field)))
```

Where each argument is: 

address: This is nothing but a pointer to a field (here, list_entry) in an instance of a structure of type Type (here, MYSTRUCT).
    type: The name of the type of the structure (in the source code, it is MYSTRUCT whose base address is to be returned, from which direct access to structure members can be made.
    field: The name of the field (in this source code, it is list_entry) pointed to by address (first argument of the macro) and which is contained in a structure of type Type (MYSTRUCT) 

(all ganked from https://www.codeproject.com/Articles/800404/Understanding-LIST-ENTRY-Lists-and-Its-Importance).

So really it's all about what the name says. It's going to give you back the base address of MYSTRUCT so that you can access other members of this list. I know it's confusing, we'll get back to it when it's more important. The main thing to know is there are various structures that are all linked together and very clever tricks to be able to easily access those structures. I'm getting tired. itchy. tasty.















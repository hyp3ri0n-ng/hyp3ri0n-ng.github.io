## Kernel Stuff

So hunting in explorere.exe is all well and good, and I've been enjoying it. However, I need to get ready for a course I'm giving on the 31st of January! If you're not familiar with our HTP green belt course (https://www.hyperiongray.com/htp) we focus heavily on Windows 10 kernel exploitation. We do a bunch of userland stuff as well, but I find that attacking the kernel allows you to analyze small well-structured (and well documented) files. There's been a lot of work in it, and well, there's a reason why last time I approached Zerodium about kernel-based LPEs they weren't buying any more. It's a great place to start hunting. It requies some lead time in learning wtf is going on, if you're used to reversing in userland a driver looks pretty damn weird (WHERE'S MY MAIN() FUNCTION!!!?!?!?!).

Anyway as i'm doing a bit of review I figured - may as wwell write it up eh? OK, so the book I'm using for review is the. The first part of the book is blah blah virtual addressing etc. which seems to come up in every windows internals book. it makes sense, it's important. But anyway I'm not gonna get into that here, I'll more be talking about drivers and how they work.

Ok so threads are the things that run things. What do i mean? Processes are just MANAGERs for threads, the thread is what actually owns a stack, makes syscalls, etc. It's an interesting way of thinking about a system where you could say that a thread can't really do jack shit - it can only ask the kernel to do stuff. Of course there's tons of layers of abstraction, so it's not the usual way of thinking of an OS, but it's useful nonetheless.

The Guard Page is an interesting concept, it's part of what allows processes to think they have their very own full address space. How so? Well, a page is `committed` to a process whenever memory is needed. As the stack grows, it's possible that it outgrows the limits of that page. If it does, it "overflows" into a guard paage and causes an exception. The guard page is then marked as executable and the instruction set can run into this page. I assume that after the new page is committed there is now another guard page that does the same thing.

Devices each have a "Handle" associated with them, e.g. `\\Devices\\vmhgfs`. Most functions trying to "attach" to one return NULL on failure, note this is the opposite of most userspace stuff where a return 0 is usually good. But that's windows. 

Alright so let's jump to doing a little bit of driver analysis and RE work. This is how I got my start doing 0-day hunting so it's nice to be back on familiar ground :-), greetz to ch3f. You're an asshole but you taught me a lot <3.

Anyway I've noticed that there really isn't much to rival IDA in terms of kernel driver (lkm in Linux) analysis. I've tried with Binary Ninja - goddman I've tried, but there is very very little to no autoanalysis, nor are there any good plugins that aren't date. Ghidra is *pretty good*, but requires a bit of tomfuckery. I'd like to skip that tomfuckery which requires importing symbols from the WDK in a weird proprietary format when honestly, if I have the WDK installed the RE program should just use them. They're in my path and e'erything. Anyway, I pop open `C:\Windows\system32\drivers\vmhgfs.sys` and start looking at it. I have the win_driver_plugin installed from here https://github.com/uf0o/win_driver_plugin. Note I have my own for IDA 7.4 amd python 2 here https://gitlab.com/acaceres/win-driver-plugin-7.4. I also ported it to python 3 for IDA 7.5 but to be honest, just use the other dude's. I didn't make sure all of the functionality was working correctly and he seems to have done a great job. So install that thing by dropping the .py file and the library into the IDA plugins/ folder!

![/assets/img/ida_de.PNG](/assets/img/ida_de.PNG)

And that's why I love IDA, it recognized DriverEntry for me, sweet. Now having done a lot of driver RE, DriverEntry is always a little stub of a function, and I know that a "Real Driver Entry" is usually called in there. I quickly identified this and called it "NextDriverEntry" because RealDriverEntry seemed derogative to the poor lil DriverEntry function. Lil fella gets no respect.

![/assets/img/ida_nde.PNG](/assets/img/ida_nde.PNG)

OK so now this function is a little bit meatier. Within this function I see the telltale following:

```
INIT:00000001400275DA                 or      cs:dword_14001E300, 4
INIT:00000001400275E1                 lea     rcx, SymbolicLinkName ; SymbolicLinkName
INIT:00000001400275E8                 call    cs:IoDeleteSymbolicLink
INIT:00000001400275EE                 mov     rdx, rsi        ; DeviceName
INIT:00000001400275F1                 lea     rcx, SymbolicLinkName ; SymbolicLinkName
INIT:00000001400275F8                 call    cs:IoCreateSymbolicLink
...
INIT:000000014002764F
INIT:000000014002764F loc_14002764F:                          ; CODE XREF: NextDriverEntry+18C↑j
INIT:000000014002764F                 xor     r8d, r8d        ; Context
INIT:0000000140027652                 lea     rdx, DriverReinitializationRoutine ; DriverReinitializationRoutine
INIT:0000000140027659                 mov     rcx, rdi        ; DriverObject
INIT:000000014002765C                 call    cs:IoRegisterDriverReinitialization
INIT:0000000140027662                 lea     rdx, a110420    ; "11.0.42.0"
INIT:0000000140027669                 lea     rcx, aVmhgfs_0  ; "vmhgfs"
INIT:0000000140027670                 call    j_DriverVersion

```

meaning it's still initializing drivery stuff. It's not an unimportant function, but it's still at the less interesting part of itself. We see some driver strings and stuff being passed about, yes yes whatever. And then we see some real shit. The generic move here is to start looking for subroutines that are being called in this driver entry. One of them is going to define your DRIVER_OBJECT's MajorFunction. Check it from MSDN:

```
typedef struct _DRIVER_OBJECT {
  CSHORT             Type;
  CSHORT             Size;
  PDEVICE_OBJECT     DeviceObject;
  ULONG              Flags;
  PVOID              DriverStart;
  ULONG              DriverSize;
  PVOID              DriverSection;
  PDRIVER_EXTENSION  DriverExtension;
  UNICODE_STRING     DriverName;
  PUNICODE_STRING    HardwareDatabase;
  PFAST_IO_DISPATCH  FastIoDispatch;
  PDRIVER_INITIALIZE DriverInit;
  PDRIVER_STARTIO    DriverStartIo;
  PDRIVER_UNLOAD     DriverUnload;
  PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;
```
Or perhaps even more telling if you see what WinDBG has to say about this thing:

```
lkd> dt _DRIVER_OBJECT
nt!_DRIVER_OBJECT
   +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x008 DeviceObject     : Ptr64 _DEVICE_OBJECT
   +0x010 Flags            : Uint4B
   +0x018 DriverStart      : Ptr64 Void
   +0x020 DriverSize       : Uint4B
   +0x028 DriverSection    : Ptr64 Void
   +0x030 DriverExtension  : Ptr64 _DRIVER_EXTENSION
   +0x038 DriverName       : _UNICODE_STRING
   +0x048 HardwareDatabase : Ptr64 _UNICODE_STRING
   +0x050 FastIoDispatch   : Ptr64 _FAST_IO_DISPATCH
   +0x058 DriverInit       : Ptr64     long 
   +0x060 DriverStartIo    : Ptr64     void 
   +0x068 DriverUnload     : Ptr64     void 
   +0x070 MajorFunction    : [28] Ptr64     long 
   ```
   
Cool cool cool cool. Cool. Wait wut? Oh right, so that +0x070 is really telling right there. If you look back at our IDA function under the NextDriverEntry function, there's one i've labeled as RefPdriverEntry. Which I think meant to stand for Reference to a pointer to the DRIVER_OBJECT or something like that, whatever, call it what you want. Anyway this function looks like this:

```
INIT:0000000140027280
INIT:0000000140027280 RefPdriverEntry proc near               ; CODE XREF: NextDriverEntry+24↓p
INIT:0000000140027280                                         ; DATA XREF: .pdata:0000000140020890↑o
INIT:0000000140027280
INIT:0000000140027280 arg_0           = qword ptr  8
INIT:0000000140027280
INIT:0000000140027280                 mov     [rsp+arg_0], rbx
INIT:0000000140027285                 push    rdi
INIT:0000000140027286                 sub     rsp, 20h
INIT:000000014002728A                 mov     rbx, rcx
INIT:000000014002728D                 mov     cs:qword_14001E0D0, rcx
INIT:0000000140027294                 mov     cs:dword_14001E0C8, 1
INIT:000000014002729E                 call    cs:IoGetCurrentProcess
INIT:00000001400272A4                 mov     cs:qword_14001E0C0, rax
INIT:00000001400272AB                 call    sub_140008420
INIT:00000001400272B0                 test    eax, eax
INIT:00000001400272B2                 js      loc_1400273FF
INIT:00000001400272B8                 or      cs:dword_14001E0C8, 20h
INIT:00000001400272BF                 call    cs:MmQuerySystemSize
INIT:00000001400272C5                 xor     ecx, ecx
INIT:00000001400272C7                 mov     edi, eax
INIT:00000001400272C9                 call    sub_140008754
INIT:00000001400272CE                 mov     cs:dword_14001E680, eax
INIT:00000001400272D4                 mov     rcx, rbx
INIT:00000001400272D7                 lea     rax, sub_140001BB0
INIT:00000001400272DE                 mov     [rbx+70h], rax
INIT:00000001400272E2                 lea     rax, sub_140001FE0
INIT:00000001400272E9                 mov     [rbx+88h], rax
INIT:00000001400272F0                 lea     rax, sub_140002500
INIT:00000001400272F7                 mov     [rbx+90h], rax
INIT:00000001400272FE                 lea     rax, sub_140002600
INIT:0000000140027305                 mov     [rbx+98h], rax
INIT:000000014002730C                 lea     rax, sub_140002700
INIT:0000000140027313                 mov     [rbx+0A0h], rax
INIT:000000014002731A                 lea     rax, sub_140022B90
INIT:0000000140027321                 mov     [rbx+0D0h], rax
INIT:0000000140027328                 lea     rax, sub_140002ED0
INIT:000000014002732F                 mov     [rbx+80h], rax
INIT:0000000140027336                 lea     rax, sub_140002FF0
INIT:000000014002733D                 mov     [rbx+100h], rax
INIT:0000000140027344                 lea     rax, sub_1400028B0
INIT:000000014002734B                 mov     [rbx+0E0h], rax
INIT:0000000140027352                 lea     rax, sub_140023E10
INIT:0000000140027359                 mov     [rbx+0C0h], rax
INIT:0000000140027360                 lea     rax, sub_1400240B0
INIT:0000000140027367                 mov     [rbx+0C8h], rax
INIT:000000014002736E                 lea     rax, sub_140023BD0
INIT:0000000140027375                 mov     [rbx+0D8h], rax
INIT:000000014002737C                 lea     rax, sub_140006AC0
INIT:0000000140027383                 mov     [rbx+0F0h], rax
INIT:000000014002738A                 lea     rax, sub_1400068E0
INIT:0000000140027391                 mov     [rbx+0B8h], rax
INIT:0000000140027398                 lea     rax, sub_140006510
INIT:000000014002739F                 mov     [rbx+0F8h], rax
INIT:00000001400273A6                 call    Allocator
INIT:00000001400273AB                 test    eax, eax
INIT:00000001400273AD                 jnz     short loc_140027401
INIT:00000001400273AF                 or      cs:dword_14001E0C8, 2
INIT:00000001400273B6                 mov     ecx, edi
INIT:00000001400273B8                 call    sub_140027000
INIT:00000001400273BD                 test    eax, eax
INIT:00000001400273BF                 jnz     short loc_140027401
INIT:00000001400273C1                 or      cs:dword_14001E0C8, 10h
INIT:00000001400273C8                 mov     ecx, edi
INIT:00000001400273CA                 call    sub_140007BA8
INIT:00000001400273CF                 test    eax, eax
INIT:00000001400273D1                 jnz     short loc_140027401
INIT:00000001400273D3                 or      cs:dword_14001E0C8, 8
INIT:00000001400273DA                 mov     ecx, edi
INIT:00000001400273DC                 call    sub_140003EB0
INIT:00000001400273E1                 test    eax, eax
INIT:00000001400273E3                 jnz     short loc_140027401
INIT:00000001400273E5                 or      cs:dword_14001E0C8, 40h
INIT:00000001400273EC                 call    sub_140006104
INIT:00000001400273F1                 test    eax, eax
INIT:00000001400273F3                 jnz     short loc_140027401
INIT:00000001400273F5                 bts     cs:dword_14001E0C8, 1Fh
INIT:00000001400273FD                 test    eax, eax
INIT:00000001400273FF
INIT:00000001400273FF loc_1400273FF:                          ; CODE XREF: RefPdriverEntry+32↑j
INIT:00000001400273FF                 jz      short loc_140027415
INIT:0000000140027401
INIT:0000000140027401 loc_140027401:                          ; CODE XREF: RefPdriverEntry+12D↑j
INIT:0000000140027401                                         ; RefPdriverEntry+13F↑j ...
INIT:0000000140027401                 lea     rdx, dword_14001E0C8
INIT:0000000140027408                 mov     rcx, rbx
INIT:000000014002740B                 call    sub_140005DEC
INIT:0000000140027410                 mov     eax, 0C0000001h
INIT:0000000140027415
INIT:0000000140027415 loc_140027415:                          ; CODE XREF: RefPdriverEntry:loc_1400273FF↑j
INIT:0000000140027415                 mov     rbx, [rsp+28h+arg_0]
INIT:000000014002741A                 add     rsp, 20h
INIT:000000014002741E                 pop     rdi
INIT:000000014002741F                 retn
INIT:000000014002741F RefPdriverEntry endp
INIT:000000014002741F
```   
   
What immediately catches your eye? Nothing? Yeah I started the same way so don't worry, but here's what's interestnig. First of all, remember we're in Windows 10 x64 land here.

```
INIT:00000001400272D7                 lea     rax, sub_140001BB0
INIT:00000001400272DE                 mov     [rbx+70h], rax
INIT:00000001400272E2                 lea     rax, sub_140001FE0
INIT:00000001400272E9                 mov     [rbx+88h], rax
INIT:00000001400272F0                 lea     rax, sub_140002500
INIT:00000001400272F7                 mov     [rbx+90h], rax
INIT:00000001400272FE                 lea     rax, sub_140002600
INIT:0000000140027305                 mov     [rbx+98h], rax
INIT:000000014002730C                 lea     rax, sub_140002700
INIT:0000000140027313                 mov     [rbx+0A0h], rax
INIT:000000014002731A                 lea     rax, sub_140022B90
INIT:0000000140027321                 mov     [rbx+0D0h], rax
INIT:0000000140027328                 lea     rax, sub_140002ED0
INIT:000000014002732F                 mov     [rbx+80h], rax
INIT:0000000140027336                 lea     rax, sub_140002FF0
INIT:000000014002733D                 mov     [rbx+100h], rax
INIT:0000000140027344                 lea     rax, sub_1400028B0
INIT:000000014002734B                 mov     [rbx+0E0h], rax
INIT:0000000140027352                 lea     rax, sub_140023E10
INIT:0000000140027359                 mov     [rbx+0C0h], rax
INIT:0000000140027360                 lea     rax, sub_1400240B0
INIT:0000000140027367                 mov     [rbx+0C8h], rax
INIT:000000014002736E                 lea     rax, sub_140023BD0
INIT:0000000140027375                 mov     [rbx+0D8h], rax
INIT:000000014002737C                 lea     rax, sub_140006AC0
INIT:0000000140027383                 mov     [rbx+0F0h], rax
INIT:000000014002738A                 lea     rax, sub_1400068E0
INIT:0000000140027391                 mov     [rbx+0B8h], rax
INIT:0000000140027398                 lea     rax, sub_140006510
```

What's going on there? Assembly-ing a little bit, we realize that these are functions being put into offsets of rbx. Who gives a shit right? Well **I** do ok?? Why? Well those offsets are awfully suspicious to me. Remember the MSDN list of arguments for the DRIVER_OBJECT struct? In particular this one:

```
MajorFunction

A dispatch table consisting of an array of entry points for the driver's DispatchXxx routines. The array's index values are the IRP_MJ_XXX values representing each IRP major function code. Each driver must set entry points in this array for the IRP_MJ_XXX requests that the driver handles. For more information, see Writing Dispatch Routines.
```

oh and that WinDBG output that said:

```
   +0x070 MajorFunction    : [28] Ptr64     long 
```

Hm OK, so we see a bunch of 64-bit qwords being shoved into addresses, and the first one is at offset 0x70 from the base pointer.... Well I'll be goddamned if that's not the PDRIVER_DISPATCH array being built (it is, I may be damned, but not for this reason). Alright let's learn a little bit of WinDBG scripting shall we? No. Let's not. It fucking sucks. So I'll just show you one useful command. `da` is for dump ascii:

```
lkd> da @@(((char **)@@(nt!IrpMajorNames))[0])
fffff806`449b8960  "IRP_MJ_CREATE"
lkd> da nt!IrpMajorNames
fffff806`449b8600  "`..D.......D....8..D.......D...."
fffff806`449b8620  "...D....p..D.......D...."
lkd> da @@(((char **)@@(nt!IrpMajorNames))[1])
fffff806`449b8918  "IRP_MJ_CREATE_NAMED_PIPE"
lkd> da @@(((char **)@@(nt!IrpMajorNames))[2])
fffff806`449b8938  "IRP_MJ_CLOSE"
lkd> da @@(((char **)@@(nt!IrpMajorNames))[0])
fffff806`449b8960  "IRP_MJ_CREATE"
lkd> (0x88-0x70)
     ^ Syntax error in '(0x88-0x70)'
lkd> ? (0x88-0x70)/8
Evaluate expression: 3 = 00000000`00000003
lkd> da @@(((char **)@@(nt!IrpMajorNames))[3])
fffff806`449b89a8  "IRP_MJ_READ"
lkd> ? (0x90-0x70)/8
Evaluate expression: 4 = 00000000`00000004
lkd> da @@(((char **)@@(nt!IrpMajorNames))[4])
fffff806`449b89b8  "IRP_MJ_WRITE"
lkd> ? (0x98-0x70)/8
Evaluate expression: 5 = 00000000`00000005
lkd> da @@(((char **)@@(nt!IrpMajorNames))[5])
fffff806`449b8970  "IRP_MJ_QUERY_INFORMATION"
lkd> da @@(((char **)@@(nt!IrpMajorNames))[6])
fffff806`449b8990  "IRP_MJ_SET_INFORMATION"
lkd> da @@(((char **)@@(nt!IrpMajorNames))[67)
Unexpected token ')'
lkd> da @@(((char **)@@(nt!IrpMajorNames))[7])
fffff806`449b8a00  "IRP_MJ_QUERY_EA"
lkd> ? (0xD8-0x70)/8
Evaluate expression: 13 = 00000000`0000000d
lkd> da @@(((char **)@@(nt!IrpMajorNames))[13])
fffff806`449b8a20  "IRP_MJ_FILE_SYSTEM_CONTROL"
```

**sigh** ok what am I doing? I'm dumping the ascii of IrpMajorNames at specific offsets. I'm calculating those offsets by taking what rbp is being incremented by in IDA (say 0x88 and 0x70, calculating the difference, and dividing by the value in bytes of a pointer (8 bytes). Well isn't that annoying as fuck? Yes, yes it is, you're better off just hitting the bookmark thingy and saving this information so you can copy and paste it later. BUT WAIT, THERE'S MORE. What if this could be automated? Oh fuck, right, we have that win_driver_plugin, eh?

Oh wait, fuck, it's broken as shit. It looks like my suggestion of just use this other dude's isn't that great. I'll have to spend some time with it and give it some tlc to massage it back to life. Until then let's keep doing this the manual way - using dynamic analysis. So here's what we're gonna analyze:

```
INIT:00000001400272DE                 mov     [rbx+70h], rax
INIT:00000001400272E2                 lea     rax, sub_140001FE0
INIT:00000001400272E9                 mov     [rbx+88h], rax
INIT:00000001400272F0                 lea     rax, sub_140002500
INIT:00000001400272F7                 mov     [rbx+90h], rax
INIT:00000001400272FE                 lea     rax, sub_140002600
INIT:0000000140027305                 mov     [rbx+98h], rax
INIT:000000014002730C                 lea     rax, sub_140002700
INIT:0000000140027313                 mov     [rbx+0A0h], rax
INIT:000000014002731A                 lea     rax, sub_140022B90
INIT:0000000140027321                 mov     [rbx+0D0h], rax
INIT:0000000140027328                 lea     rax, sub_140002ED0
INIT:000000014002732F                 mov     [rbx+80h], rax
INIT:0000000140027336                 lea     rax, sub_140002FF0
INIT:000000014002733D                 mov     [rbx+100h], rax
INIT:0000000140027344                 lea     rax, sub_1400028B0
INIT:000000014002734B                 mov     [rbx+0E0h], rax
INIT:0000000140027352                 lea     rax, sub_140023E10
INIT:0000000140027359                 mov     [rbx+0C0h], rax
INIT:0000000140027360                 lea     rax, sub_1400240B0
INIT:0000000140027367                 mov     [rbx+0C8h], rax
INIT:000000014002736E                 lea     rax, sub_140023BD0
INIT:0000000140027375                 mov     [rbx+0D8h], rax
INIT:000000014002737C                 lea     rax, sub_140006AC0
INIT:0000000140027383                 mov     [rbx+0F0h], rax
INIT:000000014002738A                 lea     rax, sub_1400068E0
INIT:0000000140027391                 mov     [rbx+0B8h], rax
INIT:0000000140027398                 lea     rax, sub_140006510
INIT:000000014002739F                 mov     [rbx+0F8h], rax
```

Knowing that our base is at 70 and knowing this will have some ascii value let's get cracking:

```
0x88 - "IRP_MJ_READ"
0x90 - "IRP_MJ_WRITE"
0x98 - "IRP_MJ_QUERY_INFORMATION"
0xA0 - "IRP_MJ_SET_INFORMATION"
0xD0 - "IRP_MJ_DIRECTORY_CONTROL"
0x80 - "IRP_MJ_CLOSE"
0x100 - "IRP_MJ_CLEANUP"
0xE0 - "IRP_MJ_DEVICE_CONTROL"
0xC0 - "IRP_MJ_QUERY_VOLUME_INFORMATION"
0xC8 - "IRP_MJ_SET_VOLUME_INFORMATION"
0xD8 - "IRP_MJ_FILE_SYSTEM_CONTROL"
0xf0 - "IRP_MJ_SHUTDOWN"
0xB8 - "IRP_MJ_FLUSH_BUFFERS"
0xF8 - "IRP_MJ_LOCK_CONTROL"
```

OK FINE we didn't actually have to do that, I just wanted to show how super cool I was doing hexy math and shit. We could have just found the device in DeviceTree (a sysinternals tool) and gotten that exact same list:

![/assets/img/devtree.PNG](/assets/img/devtree.PNG)

We're almost ready to start reversing out IOCTL codes. But first I should mention that I also did a "find name" using win_driver_plugin, which works and gives back:

```
	\DosDevices\VMCIDev
	\DosDevices\vmhgfs
	\Device\hgfsInternal
```

Cool so we know the handles that are possible for this driver. A handle is needed for when we send our IOCTL (it's part of DeviceIoControl which actually queries the driver), so that's cool. Oh and we can also query this bitch for this information:

```
lkd> !drvobj vmhgfs 2
Driver object (ffffc100bedbae50) is for:
 \FileSystem\vmhgfs

DriverEntry:   fffff8064a387420	vmhgfs
DriverStartIo: 00000000	
DriverUnload:  00000000	
AddDevice:     00000000	

Dispatch routines:
[00] IRP_MJ_CREATE                      fffff8064a361bb0	vmhgfs+0x1bb0
[01] IRP_MJ_CREATE_NAMED_PIPE           fffff80644291390	nt!IopInvalidDeviceRequest
[02] IRP_MJ_CLOSE                       fffff8064a362ed0	vmhgfs+0x2ed0
[03] IRP_MJ_READ                        fffff8064a361fe0	vmhgfs+0x1fe0
[04] IRP_MJ_WRITE                       fffff8064a362500	vmhgfs+0x2500
[05] IRP_MJ_QUERY_INFORMATION           fffff8064a362600	vmhgfs+0x2600
[06] IRP_MJ_SET_INFORMATION             fffff8064a362700	vmhgfs+0x2700
[07] IRP_MJ_QUERY_EA                    fffff80644291390	nt!IopInvalidDeviceRequest
[08] IRP_MJ_SET_EA                      fffff80644291390	nt!IopInvalidDeviceRequest
[09] IRP_MJ_FLUSH_BUFFERS               fffff8064a3668e0	vmhgfs+0x68e0
[0a] IRP_MJ_QUERY_VOLUME_INFORMATION    fffff8064a383e10	vmhgfs+0x23e10
[0b] IRP_MJ_SET_VOLUME_INFORMATION      fffff8064a3840b0	vmhgfs+0x240b0
[0c] IRP_MJ_DIRECTORY_CONTROL           fffff8064a382b90	vmhgfs+0x22b90
[0d] IRP_MJ_FILE_SYSTEM_CONTROL         fffff8064a383bd0	vmhgfs+0x23bd0
[0e] IRP_MJ_DEVICE_CONTROL              fffff8064a3628b0	vmhgfs+0x28b0
[0f] IRP_MJ_INTERNAL_DEVICE_CONTROL     fffff80644291390	nt!IopInvalidDeviceRequest
[10] IRP_MJ_SHUTDOWN                    fffff8064a366ac0	vmhgfs+0x6ac0
[11] IRP_MJ_LOCK_CONTROL                fffff8064a366510	vmhgfs+0x6510
[12] IRP_MJ_CLEANUP                     fffff8064a362ff0	vmhgfs+0x2ff0
[13] IRP_MJ_CREATE_MAILSLOT             fffff80644291390	nt!IopInvalidDeviceRequest
[14] IRP_MJ_QUERY_SECURITY              fffff80644291390	nt!IopInvalidDeviceRequest
[15] IRP_MJ_SET_SECURITY                fffff80644291390	nt!IopInvalidDeviceRequest
[16] IRP_MJ_POWER                       fffff80644291390	nt!IopInvalidDeviceRequest
[17] IRP_MJ_SYSTEM_CONTROL              fffff80644291390	nt!IopInvalidDeviceRequest
[18] IRP_MJ_DEVICE_CHANGE               fffff80644291390	nt!IopInvalidDeviceRequest
[19] IRP_MJ_QUERY_QUOTA                 fffff80644291390	nt!IopInvalidDeviceRequest
[1a] IRP_MJ_SET_QUOTA                   fffff80644291390	nt!IopInvalidDeviceRequest
[1b] IRP_MJ_PNP                         fffff80644291390	nt!IopInvalidDeviceRequest

Fast I/O routines:
FastIoCheckIfPossible                   fffff8064a366c80	vmhgfs+0x6c80
FastIoRead                              fffff8064a366e60	vmhgfs+0x6e60
FastIoWrite                             fffff8064a366e60	vmhgfs+0x6e60
FastIoLock                              fffff8064a366d50	vmhgfs+0x6d50
FastIoUnlockSingle                      fffff8064a367020	vmhgfs+0x7020
FastIoUnlockAll                         fffff8064a366e70	vmhgfs+0x6e70
FastIoUnlockAllByKey                    fffff8064a366f40	vmhgfs+0x6f40
```

Soooo many options! But now you know how to do it manually right? And that's....good?? Anyway let's take it away from hereooo and look at some of these IRPs. We should look into each one individually, and we will, but first let's continue on our RE journey. The IRP IRP_MJ_DEVICE_CONTROL thing is called the Major Function Handler. It is essentially what receives IOCTLs and determines wtf to do with them. So let's take a look at that. Filtering IDA for 28B0 gives me a single function, which I rename to MajorFunctionHandler for clarity:

![/assets/img/mfh.PNG](/assets/img/mfh.PNG)

aaaaand I'm fucking tired so I'm going to bed. Picking this up in the AM.

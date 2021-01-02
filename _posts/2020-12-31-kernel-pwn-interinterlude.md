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

aaaaand I'm fucking tired so I'm going to bed. Picking this up in the AM. OK time to harvest some IRPS! Now that we know that the Dispatch Handler (MajorFunctionHandler) is at vmhgs+29b0 we can start to look in IDA for more places to harvest IOCTLs. I'm using a bit of a different technique than I've seen elsewhere because it just makes more sense to me than what I am seeing out there. Let's look at the disassembly:

```
.text:00000001400028B0 ; =============== S U B R O U T I N E =======================================
.text:00000001400028B0
.text:00000001400028B0
.text:00000001400028B0 ; __int64 __fastcall MajorFunctionHandler(__int64 a1, IRP *irp)
.text:00000001400028B0 MajorFunctionHandler proc near          ; DATA XREF: .rdata:000000014001A494↓o
.text:00000001400028B0                                         ; .pdata:000000014001F120↓o ...
.text:00000001400028B0
.text:00000001400028B0 var_38          = byte ptr -38h
.text:00000001400028B0 var_30          = qword ptr -30h
.text:00000001400028B0 ListEntry       = qword ptr -28h
.text:00000001400028B0 var_20          = dword ptr -20h
.text:00000001400028B0 var_18          = qword ptr -18h
.text:00000001400028B0 arg_10          = qword ptr  18h
.text:00000001400028B0 arg_18          = qword ptr  20h
.text:00000001400028B0
.text:00000001400028B0 ; FUNCTION CHUNK AT .text:0000000140019DD0 SIZE 0000001B BYTES
.text:00000001400028B0
.text:00000001400028B0 ; __unwind { // __GSHandlerCheck_SEH
.text:00000001400028B0                 mov     [rsp+arg_10], rbx
.text:00000001400028B5                 mov     [rsp+arg_18], rsi
.text:00000001400028BA                 push    rdi
.text:00000001400028BB                 sub     rsp, 50h
.text:00000001400028BF                 mov     rax, cs:__security_cookie
.text:00000001400028C6                 xor     rax, rsp
.text:00000001400028C9                 mov     [rsp+58h+var_18], rax
.text:00000001400028CE                 mov     rbx, rdx
.text:00000001400028D1                 mov     rsi, rcx
.text:00000001400028D4                 mov     [rsp+58h+var_30], rdx
.text:00000001400028D9                 and     [rsp+58h+var_20], 0
.text:00000001400028DE                 and     [rsp+58h+ListEntry], 0
.text:00000001400028E4                 call    cs:KeEnterCriticalRegion
.text:00000001400028EA                 mov     rcx, rbx        ; Irp
.text:00000001400028ED                 call    someIrpProcess
.text:00000001400028F2                 mov     dil, al
.text:00000001400028F5                 mov     [rsp+58h+var_38], al
.text:00000001400028F9                 mov     rcx, [rbx+0B8h]
.text:0000000140002900                 cmp     qword ptr [rcx+30h], 0
.text:0000000140002905                 jnz     short loc_140002920
.text:0000000140002907                 mov     eax, 0C0000010h
.text:000000014000290C                 mov     [rsp+58h+var_20], eax
.text:0000000140002910                 mov     [rbx+30h], eax
.text:0000000140002913                 xor     edx, edx        ; PriorityBoost
.text:0000000140002915                 mov     rcx, rbx        ; Irp
.text:0000000140002918                 call    cs:IofCompleteRequest
.text:000000014000291E                 jmp     short loc_14000299A
.text:0000000140002920 ; ---------------------------------------------------------------------------
.text:0000000140002920
.text:0000000140002920 loc_140002920:                          ; CODE XREF: MajorFunctionHandler+55↑j
.text:0000000140002920                                         ; DATA XREF: .rdata:000000014001B250↓o
.text:0000000140002920                 and     qword ptr [rbx+38h], 0
.text:0000000140002925                 mov     rcx, rbx        ; Irp
.text:0000000140002928                 call    cs:IoIsOperationSynchronous
.text:000000014000292E                 lea     r9, [rsp+58h+ListEntry]
.text:0000000140002933                 mov     r8b, al
.text:0000000140002936                 mov     rdx, rsi
.text:0000000140002939                 mov     rcx, rbx
.text:000000014000293C                 call    sub_140007808
.text:0000000140002941                 mov     [rsp+58h+var_20], eax
.text:0000000140002945                 test    eax, eax
.text:0000000140002947                 jns     short loc_140002959
.text:0000000140002949                 mov     [rbx+30h], eax
.text:000000014000294C                 xor     edx, edx        ; PriorityBoost
.text:000000014000294E                 mov     rcx, rbx        ; Irp
.text:0000000140002951                 call    cs:IofCompleteRequest
.text:0000000140002957                 jmp     short loc_14000299A
.text:0000000140002959 ; ---------------------------------------------------------------------------
.text:0000000140002959
.text:0000000140002959 loc_140002959:                          ; CODE XREF: MajorFunctionHandler+97↑j
.text:0000000140002959                 lea     r9, [rsp+58h+var_20]
.text:000000014000295E                 mov     r8, rbx
.text:0000000140002961                 mov     rdx, [rsp+58h+ListEntry]
.text:0000000140002966                 mov     rcx, rsi
.text:0000000140002969                 call    sub_1400014B0
.text:000000014000296E                 test    al, al
.text:0000000140002970                 jnz     short loc_14000299A
.text:0000000140002972                 mov     rdx, rbx
.text:0000000140002975                 mov     rcx, [rsp+58h+ListEntry] ; ListEntry
.text:000000014000297A                 call    sub_140022500
```

Cool, so we're starting at MajorFunctionHandler, and now see where IDA has automagically labeled those structures ;irp with a comment by them. Well, in each one it's popping the IRP structure into RCX and then executing the function. Makes sense right? x64 first argument always goes into RCX. Using that I've built the following list of places where breakpoints are needed:

```
0x28ED
0x2918
0x2928
0x2951
0x29A1
0x2969
```

Neat. So we have that. Another way to confirm this is to go ahead and pop the address of the MajorFunctionHandler into WinDBG:

`[0e] IRP_MJ_DEVICE_CONTROL              fffff8064a3628b0	vmhgfs+0x28b0`

and disassemble from there. We have no symbols so the best we can do is disassembly, which should look similar to what we have in IDA:

```
ffff806`4a3628b0 48895c2418     mov     qword ptr [rsp+18h], rbx
fffff806`4a3628b5 4889742420     mov     qword ptr [rsp+20h], rsi
fffff806`4a3628ba 57             push    rdi
fffff806`4a3628bb 4883ec50       sub     rsp, 50h
fffff806`4a3628bf 488b05d2a70100 mov     rax, qword ptr [vmhgfs+0x1d098 (fffff806`4a37d098)]
fffff806`4a3628c6 4833c4         xor     rax, rsp
fffff806`4a3628c9 4889442440     mov     qword ptr [rsp+40h], rax
fffff806`4a3628ce 488bda         mov     rbx, rdx
fffff806`4a3628d1 488bf1         mov     rsi, rcx
fffff806`4a3628d4 4889542428     mov     qword ptr [rsp+28h], rdx
fffff806`4a3628d9 8364243800     and     dword ptr [rsp+38h], 0
fffff806`4a3628de 488364243000   and     qword ptr [rsp+30h], 0
fffff806`4a3628e4 ff1546770100   call    qword ptr [vmhgfs+0x1a030 (fffff806`4a37a030)]
fffff806`4a3628ea 488bcb         mov     rcx, rbx
fffff806`4a3628ed e8d6330000     call    vmhgfs+0x5cc8 (fffff806`4a365cc8)
fffff806`4a3628f2 408af8         mov     dil, al
fffff806`4a3628f5 88442420       mov     byte ptr [rsp+20h], al
fffff806`4a3628f9 488b8bb8000000 mov     rcx, qword ptr [rbx+0B8h]
fffff806`4a362900 4883793000     cmp     qword ptr [rcx+30h], 0
fffff806`4a362905 7519           jne     vmhgfs+0x2920 (fffff806`4a362920)
fffff806`4a362907 b8100000c0     mov     eax, 0C0000010h
fffff806`4a36290c 89442438       mov     dword ptr [rsp+38h], eax
fffff806`4a362910 894330         mov     dword ptr [rbx+30h], eax
fffff806`4a362913 33d2           xor     edx, edx
fffff806`4a362915 488bcb         mov     rcx, rbx
fffff806`4a362918 ff153a770100   call    qword ptr [vmhgfs+0x1a058 (fffff806`4a37a058)]
fffff806`4a36291e eb7a           jmp     vmhgfs+0x299a (fffff806`4a36299a)
fffff806`4a362920 4883633800     and     qword ptr [rbx+38h], 0
fffff806`4a362925 488bcb         mov     rcx, rbx
fffff806`4a362928 ff1542770100   call    qword ptr [vmhgfs+0x1a070 (fffff806`4a37a070)]
fffff806`4a36292e 4c8d4c2430     lea     r9, [rsp+30h]
fffff806`4a362933 448ac0         mov     r8b, al
fffff806`4a362936 488bd6         mov     rdx, rsi
fffff806`4a362939 488bcb         mov     rcx, rbx
fffff806`4a36293c e8c74e0000     call    vmhgfs+0x7808 (fffff806`4a367808)
fffff806`4a362941 89442438       mov     dword ptr [rsp+38h], eax
fffff806`4a362945 85c0           test    eax, eax
fffff806`4a362947 7910           jns     vmhgfs+0x2959 (fffff806`4a362959)
fffff806`4a362949 894330         mov     dword ptr [rbx+30h], eax
fffff806`4a36294c 33d2           xor     edx, edx
fffff806`4a36294e 488bcb         mov     rcx, rbx
fffff806`4a362951 ff1501770100   call    qword ptr [vmhgfs+0x1a058 (fffff806`4a37a058)]
fffff806`4a362957 eb41           jmp     vmhgfs+0x299a (fffff806`4a36299a)
fffff806`4a362959 4c8d4c2438     lea     r9, [rsp+38h]
fffff806`4a36295e 4c8bc3         mov     r8, rbx
fffff806`4a362961 488b542430     mov     rdx, qword ptr [rsp+30h]
fffff806`4a362966 488bce         mov     rcx, rsi
fffff806`4a362969 e842ebffff     call    vmhgfs+0x14b0 (fffff806`4a3614b0)
fffff806`4a36296e 84c0           test    al, al
fffff806`4a362970 7528           jne     vmhgfs+0x299a (fffff806`4a36299a)
fffff806`4a362972 488bd3         mov     rdx, rbx
fffff806`4a362975 488b4c2430     mov     rcx, qword ptr [rsp+30h]
fffff806`4a36297a e881fb0100     call    vmhgfs+0x22500 (fffff806`4a382500)
fffff806`4a36297f 89442438       mov     dword ptr [rsp+38h], eax
fffff806`4a362983 eb15           jmp     vmhgfs+0x299a (fffff806`4a36299a)
fffff806`4a362985 488b542428     mov     rdx, qword ptr [rsp+28h]
fffff806`4a36298a 33c9           xor     ecx, ecx
fffff806`4a36298c e8cf590000     call    vmhgfs+0x8360 (fffff806`4a368360)
fffff806`4a362991 89442438       mov     dword ptr [rsp+38h], eax
fffff806`4a362995 408a7c2420     mov     dil, byte ptr [rsp+20h]
fffff806`4a36299a 4084ff         test    dil, dil
fffff806`4a36299d 7408           je      vmhgfs+0x29a7 (fffff806`4a3629a7)
fffff806`4a36299f 33c9           xor     ecx, ecx
fffff806`4a3629a1 ff1599760100   call    qword ptr [vmhgfs+0x1a040 (fffff806`4a37a040)]
fffff806`4a3629a7 ff158b760100   call    qword ptr [vmhgfs+0x1a038 (fffff806`4a37a038)]
fffff806`4a3629ad 8b442438       mov     eax, dword ptr [rsp+38h]
fffff806`4a3629b1 488b4c2440     mov     rcx, qword ptr [rsp+40h]
fffff806`4a3629b6 4833cc         xor     rcx, rsp
fffff806`4a3629b9 e8525e0000     call    vmhgfs+0x8810 (fffff806`4a368810)
fffff806`4a3629be 488b5c2470     mov     rbx, qword ptr [rsp+70h]
fffff806`4a3629c3 488b742478     mov     rsi, qword ptr [rsp+78h]
fffff806`4a3629c8 4883c450       add     rsp, 50h
fffff806`4a3629cc 5f             pop     rdi
fffff806`4a3629cd c3             ret     
fffff806`4a3629ce cc             int     3
fffff806`4a3629cf cc             int     3
fffff806`4a3629d0 48895c2410     mov     qword ptr [rsp+10h], rbx
fffff806`4a3629d5 4889742418     mov     qword ptr [rsp+18h], rsi
fffff806`4a3629da 57             push    rdi
fffff806`4a3629db 4883ec70       sub     rsp, 70h
fffff806`4a3629df 488b05b2a60100 mov     rax, qword ptr [vmhgfs+0x1d098 (fffff806`4a37d098)]
fffff806`4a3629e6 4833c4         xor     rax, rsp
fffff806`4a3629e9 4889442460     mov     qword ptr [rsp+60h], rax
fffff806`4a3629ee 488b4148       mov     rax, qword ptr [rcx+48h]
fffff806`4a3629f2 488bf9         mov     rdi, rcx
fffff806`4a3629f5 8bb168010000   mov     esi, dword ptr [rcx+168h]
fffff806`4a3629fb 4885c0         test    rax, rax
fffff806`4a3629fe 740c           je      vmhgfs+0x2a0c (fffff806`4a362a0c)
fffff806`4a362a00 0f108168010000 movups  xmm0, xmmword ptr [rcx+168h]
fffff806`4a362a07 f30f7f4030     movdqu  xmmword ptr [rax+30h], xmm0
fffff806`4a362a0c 85f6           test    esi, esi
fffff806`4a362a0e 7579           jne     vmhgfs+0x2a89 (fffff806`4a362a89)
fffff806`4a362a10 e887560000     call    vmhgfs+0x809c (fffff806`4a36809c)
fffff806`4a362a15 488b4f68       mov     rcx, qword ptr [rdi+68h]
fffff806`4a362a19 4c8d4c2450     lea     r9, [rsp+50h]
fffff806`4a362a1e 4533c0         xor     r8d, r8d
fffff806`4a362a21 488d542458     lea     rdx, [rsp+58h]
fffff806`4a362a26 488bd8         mov     rbx, rax
fffff806`4a362a29 e866370000     call    vmhgfs+0x6194 (fffff806`4a366194)
fffff806`4a362a2e 488364244800   and     qword ptr [rsp+48h], 0
fffff806`4a362a34 488364244000   and     qword ptr [rsp+40h], 0
fffff806`4a362a3a 488b4c2458     mov     rcx, qword ptr [rsp+58h]
fffff806`4a362a3f 448b973c010000 mov     r10d, dword ptr [rdi+13Ch]
fffff806`4a362a46 4c8b442450     mov     r8, qword ptr [rsp+50h]
fffff806`4a362a4b 48895c2438     mov     qword ptr [rsp+38h], rbx
fffff806`4a362a50 4489542430     mov     dword ptr [rsp+30h], r10d
fffff806`4a362a55 488d9100010000 lea     rdx, [rcx+100h]
fffff806`4a362a5c 448a9738010000 mov     r10b, byte ptr [rdi+138h]
fffff806`4a362a63 488b8910010000 mov     rcx, qword ptr [rcx+110h]
fffff806`4a362a6a 4d8d4858       lea     r9, [r8+58h]
fffff806`4a362a6e 4088742428     mov     byte ptr [rsp+28h], sil
fffff806`4a362a73 4488542420     mov     byte ptr [rsp+20h], r10b
fffff806`4a362a78 ff1552760100   call    qword ptr [vmhgfs+0x1a0d0 (fffff806`4a37a0d0)]
fffff806`4a362a7e 4885db         test    rbx, rbx
fffff806`4a362a81 b803010000     mov     eax, 103h
fffff806`4a362a86 0f45f0         cmovne  esi, eax
fffff806`4a362a89 8bc6           mov     eax, esi
fffff806`4a362a8b 488b4c2460     mov     rcx, qword ptr [rsp+60h]
fffff806`4a362a90 4833cc         xor     rcx, rsp
fffff806`4a362a93 e8785d0000     call    vmhgfs+0x8810 (fffff806`4a368810)
fffff806`4a362a98 4c8d5c2470     lea     r11, [rsp+70h]
fffff806`4a362a9d 498b5b18       mov     rbx, qword ptr [r11+18h]
fffff806`4a362aa1 498b7320       mov     rsi, qword ptr [r11+20h]
fffff806`4a362aa5 498be3         mov     rsp, r11
fffff806`4a362aa8 5f             pop     rdi
fffff806`4a362aa9 c3             ret     
fffff806`4a362aaa cc             int     3
fffff806`4a362aab cc             int     3
fffff806`4a362aac 48895c2408     mov     qword ptr [rsp+8], rbx
fffff806`4a362ab1 48896c2410     mov     qword ptr [rsp+10h], rbp
fffff806`4a362ab6 4889742418     mov     qword ptr [rsp+18h], rsi
fffff806`4a362abb 57             push    rdi
fffff806`4a362abc 4156           push    r14
fffff806`4a362abe 4157           push    r15
fffff806`4a362ac0 4883ec20       sub     rsp, 20h
fffff806`4a362ac4 488d9918010000 lea     rbx, [rcx+118h]
fffff806`4a362acb 408afa         mov     dil, dl
fffff806`4a362ace 4c8bf9         mov     r15, rcx
fffff806`4a362ad1 4533f6         xor     r14d, r14d
fffff806`4a362ad4 488bcb         mov     rcx, rbx
fffff806`4a362ad7 418ae9         mov     bpl, r9b
fffff806`4a362ada 418bf0         mov     esi, r8d
fffff806`4a362add 418d5608       lea     edx, [r14+8]
fffff806`4a362ae1 e81a5f0000     call    vmhgfs+0x8a00 (fffff806`4a368a00)
fffff806`4a362ae6 8a442460       mov     al, byte ptr [rsp+60h]
fffff806`4a362aea 488d0ddffeffff lea     rcx, [vmhgfs+0x29d0 (fffff806`4a3629d0)]
fffff806`4a362af1 f6d8           neg     al
fffff806`4a362af3 40887b20       mov     byte ptr [rbx+20h], dil
fffff806`4a362af7 897324         mov     dword ptr [rbx+24h], esi
fffff806`4a362afa 481bc0         sbb     rax, rax
fffff806`4a362afd 4823c1         and     rax, rcx
fffff806`4a362b00 4084ed         test    bpl, bpl
fffff806`4a362b03 740d           je      vmhgfs+0x2b12 (fffff806`4a362b12)
fffff806`4a362b05 488bd0         mov     rdx, rax
fffff806`4a362b08 498bcf         mov     rcx, r15
fffff806`4a362b0b e804600000     call    vmhgfs+0x8b14 (fffff806`4a368b14)
fffff806`4a362b10 eb17           jmp     vmhgfs+0x2b29 (fffff806`4a362b29)
fffff806`4a362b12 4438742460     cmp     byte ptr [rsp+60h], r14b
fffff806`4a362b17 7413           je      vmhgfs+0x2b2c (fffff806`4a362b2c)
fffff806`4a362b19 498bcf         mov     rcx, r15
fffff806`4a362b1c 4589b768010000 mov     dword ptr [r15+168h], r14d
fffff806`4a362b23 ff1537790100   call    qword ptr [vmhgfs+0x1a460 (fffff806`4a37a460)]
fffff806`4a362b29 448bf0         mov     r14d, eax
fffff806`4a362b2c 488b5c2440     mov     rbx, qword ptr [rsp+40h]
fffff806`4a362b31 418bc6         mov     eax, r14d
fffff806`4a362b34 488b6c2448     mov     rbp, qword ptr [rsp+48h]
fffff806`4a362b39 488b742450     mov     rsi, qword ptr [rsp+50h]
fffff806`4a362b3e 4883c420       add     rsp, 20h
fffff806`4a362b42 415f           pop     r15
fffff806`4a362b44 415e           pop     r14
fffff806`4a362b46 5f             pop     rdi
fffff806`4a362b47 c3             ret     
fffff806`4a362b48 4053           push    rbx
fffff806`4a362b4a 56             push    rsi
fffff806`4a362b4b 57             push    rdi
fffff806`4a362b4c 4883ec60       sub     rsp, 60h
fffff806`4a362b50 488b0541a50100 mov     rax, qword ptr [vmhgfs+0x1d098 (fffff806`4a37d098)]
fffff806`4a362b57 4833c4         xor     rax, rsp
fffff806`4a362b5a 4889442458     mov     qword ptr [rsp+58h], rax
fffff806`4a362b5f 418bf1         mov     esi, r9d
fffff806`4a362b62 488d442450     lea     rax, [rsp+50h]
fffff806`4a362b67 33ff           xor     edi, edi
fffff806`4a362b69 4889442420     mov     qword ptr [rsp+20h], rax
fffff806`4a362b6e 48217c2450     and     qword ptr [rsp+50h], rdi
fffff806`4a362b73 4533c9         xor     r9d, r9d
fffff806`4a362b76 498bd8         mov     rbx, r8
fffff806`4a362b79 e84a210000     call    vmhgfs+0x4cc8 (fffff806`4a364cc8)
fffff806`4a362b7e 85c0           test    eax, eax
fffff806`4a362b80 786f           js      vmhgfs+0x2bf1 (fffff806`4a362bf1)
fffff806`4a362b82 4c8b542450     mov     r10, qword ptr [rsp+50h]
fffff806`4a362b87 4d85d2         test    r10, r10
fffff806`4a362b8a 7465           je      vmhgfs+0x2bf1 (fffff806`4a362bf1)
fffff806`4a362b8c 0fb70b         movzx   ecx, word ptr [rbx]
fffff806`4a362b8f d1e9           shr     ecx, 1
fffff806`4a362b91 83e901         sub     ecx, 1
fffff806`4a362b94 741f           je      vmhgfs+0x2bb5 (fffff806`4a362bb5)
fffff806`4a362b96 488b5308       mov     rdx, qword ptr [rbx+8]
fffff806`4a362b9a 41b85c000000   mov     r8d, 5Ch
fffff806`4a362ba0 66443b044a     cmp     r8w, word ptr [rdx+rcx*2]
fffff806`4a362ba5 7407           je      vmhgfs+0x2bae (fffff806`4a362bae)
fffff806`4a362ba7 83c1ff         add     ecx, 0FFFFFFFFh
fffff806`4a362baa 75ee           jne     vmhgfs+0x2b9a (fffff806`4a362b9a)
fffff806`4a362bac eb07           jmp     vmhgfs+0x2bb5 (fffff806`4a362bb5)
fffff806`4a362bae 8d3c4d02000000 lea     edi, [rcx*2+2]
fffff806`4a362bb5 488364244000   and     qword ptr [rsp+40h], 0
fffff806`4a362bbb 498d9200010000 lea     rdx, [r10+100h]
fffff806`4a362bc2 8b8424a0000000 mov     eax, dword ptr [rsp+0A0h]
fffff806`4a362bc9 440fb7cf       movzx   r9d, di
fffff806`4a362bcd 498b8a10010000 mov     rcx, qword ptr [r10+110h]
fffff806`4a362bd4 4c8bc3         mov     r8, rbx
fffff806`4a362bd7 89742438       mov     dword ptr [rsp+38h], esi
fffff806`4a362bdb 89442430       mov     dword ptr [rsp+30h], eax
fffff806`4a362bdf 488364242800   and     qword ptr [rsp+28h], 0
fffff806`4a362be5 488364242000   and     qword ptr [rsp+20h], 0
fffff806`4a362beb ff15e7740100   call    qword ptr [vmhgfs+0x1a0d8 (fffff806`4a37a0d8)]
fffff806`4a362bf1 488b4c2458     mov     rcx, qword ptr [rsp+58h]
fffff806`4a362bf6 4833cc         xor     rcx, rsp
fffff806`4a362bf9 e8125c0000     call    vmhgfs+0x8810 (fffff806`4a368810)
fffff806`4a362bfe 4883c460       add     rsp, 60h
fffff806`4a362c02 5f             pop     rdi
fffff806`4a362c03 5e             pop     rsi
fffff806`4a362c04 5b             pop     rbx
fffff806`4a362c05 c3             ret     
fffff806`4a362c06 cc             int     3
```

So you can math a little bit with the addresses (+28b0 since that's where MajorFunctionHandler is) to make sure our offsets are in the right place.

```
0: kd> ? (fffff806`4a362915 - fffff806`4a3628b0 + 28b0)
Evaluate expression: 10517 = 00000000`00002915
```

0x2915, fucking close enough to 0x2918 so we're going to call this CONFIRMED. As an aside I've always found it useful to confirm things using both static and dynamic analysis, allowing the two to go hand in hand and check each other. Both have their strengths and weaknesses and it's easy to screw something up or make an erroneous decision. So IMO it's prudent to check out at least one of my breakpoints before I set it. Once I set a bp all I need to do is tell WinDBG to run and wait for that breakpoint to be hit. Once it is my sweet sweet Dispatch Code will be right there for me to pull out of the IRP structure (which we know will be in RCX because it's being passed as the first arg in all of these functions). So let's get cracking eh? Great, I've entered the breakpoints, and speaking of confirmation, they were set right at `call`s meaning that RCX should point to the 1st argument aka the IRP structure. So now all we need to do is let the breakpoint be hit, dump the IRP struct, and harvest IOCTLS and information about that IRP (like buffer sizes and such). Once we have those in hand we in bidness baby and we can go ahead and kick off a fuzzer (haven't decided which yet) against them. 

![/assets/img/windbg_bps.PNG](/assets/img/windbg_bps.PNG)


Oh also may as well use ioctlpus to confirm that indeed they are valid IOCTL codes as well. By the way the aforementioned process is typically automated in some way, in fact the win_driver_plugin I pointed you to is supposed to be able to harves IOCTL codes automatically, but everytime I try  it either fails out with a python exception, or gives me back some data that doesn't really make sense (it gives me only 2 IOCTL codes repeated 4 times or so each). So whatever, the manual way is smarter anyway. I guess. I'm trying to look at the positive, but fuck, it sucks. OK moving on. We set our BPs and then we set off to do stuff that uses the driver we're targeting. In this case our driver is in charge of creating shared folders between guest and host and shit. so to trigger these breakpoints i'm just going to be setting up a shared folder. If you've never done this, then people like me is probably the reason, it can weaken your guest -> host security boundary. OK let's go.

Well looks like just sitting there was enough to trigger one bp, here's the process made a little more concrete for you:

```
: kd> bp vmhgfs+0x28ED
0: kd> bp vmhgfs+0x2918
breakpoint 2 redefined
0: kd> bp vmhgfs+0x2928
0: kd> bp vmhgfs+0x2951
0: kd> bp vmhgfs+0x29A1
0: kd> bp vmhgfs+0x2969
0: kd> g
Breakpoint 4 hit
vmhgfs+0x28ed:
fffff806`4a3628ed e8d6330000      call    vmhgfs+0x5cc8 (fffff806`4a365cc8)
13: kd> dt nt!_IRP @rcx Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.
   +0x078 Tail                                                           : 
      +0x000 Overlay                                                        : 
         +0x040 CurrentStackLocation                                           : 
            +0x008 Parameters                                                     : 
               +0x000 DeviceIoControl                                                : 
                  +0x000 OutputBufferLength                                             : 0x424
                  +0x008 InputBufferLength                                              : 0
                  +0x010 IoControlCode                                                  : 0x8600204c
                  +0x018 Type3InputBuffer                                               : (null) 
```

And I'm using this as kind of a notebook, so i'll document everything here. Breakpoint 4 was hit so I disable it:

```
13: kd> bl
     0 d Enable Clear  fffff806`442c2fc0     0001 (0001) nt!IofCompleteRequest
     1 d Enable Clear  fffff806`4a3628b0     0001 (0001) vmhgfs+0x28b0
     2 e Disable Clear  fffff806`4a362918     0001 (0001) vmhgfs+0x2918
     3 e Disable Clear  00000000`000028ed     0001 (0001) 
     4 e Disable Clear  fffff806`4a3628ed     0001 (0001) vmhgfs+0x28ed
     5 e Disable Clear  fffff806`4a362928     0001 (0001) vmhgfs+0x2928
     6 e Disable Clear  fffff806`4a362951     0001 (0001) vmhgfs+0x2951
     7 e Disable Clear  fffff806`4a3629a1     0001 (0001) vmhgfs+0x29a1
     8 e Disable Clear  fffff806`4a362969     0001 (0001) vmhgfs+0x2969

13: kd> bd 4
```

BP 5 this time....

```
13: kd> g
Breakpoint 5 hit
13: kd> dt nt!_IRP @rcx Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.
   +0x078 Tail                                                           : 
      +0x000 Overlay                                                        : 
         +0x040 CurrentStackLocation                                           : 
            +0x008 Parameters                                                     : 
               +0x000 DeviceIoControl                                                : 
                  +0x000 OutputBufferLength                                             : 0x424
                  +0x008 InputBufferLength                                              : 0
                  +0x010 IoControlCode                                                  : 0x8600204c
                  +0x018 Type3InputBuffer                                               : (null) 
```

Breakpoint 8 was hit, but there didn't appear to be an IRP structure in RCX. And for the life of me I can't get the other ones to trigger. Time to read up a bit more on the driver and see wtf else it does. Hmph, so a couple won't trigger no matter what a I do. What a twat. Let's see if there's some other way I can pull out IOCTL codes with WinDBG. Well first let's try this: what do we say to the god of windows?? Reboot today boy, reboot today. Let's reboot and see if it hits a bp. I also see some stuff about setting ACLs poking around IDA so that'll be our next thing if a reboot doesn't do it.
                                





---
layout: post
title: Hacky Scripting Fun
tags: [hacking]
---

Fuuucking hell. OK so I lost this post earlier and have been working on some dumb shit. Here's my goal: use some hacky ass python script along with DIBF for IOCTL discovery  against every  open handle in the OS. How do you get every open handle in the OS? I DON'T FUCKING KNOW. So I set off to find every stupid ass generic tool out there on the internet that doesn't know how to properly refer to shit on the operating system. I was looking for KERNEL DEVICE HANDLES PEOPLE. Apparently no one can fucking do that except for WinObj. The problem: I can't export shit from WinObj, so I'm fucked trying to reproduce its functionality. There were a couple of undocu functions it uses to do its magic and I did not want to deal with reversing some shit that should be fucking easy. So I turned to other tools. FINALLY, FINALLLLYYY I got to ntobjx.exe which is essentially winobj with a save button. I saved it, wrote some hacky-ass python string manipulations and grabbed my list of drivers:

```
\Device\Harddisk0\Partition0
\Device\Harddisk0\Partition1
\Device\Harddisk0\Partition2
\Device\Harddisk0\Partition3
\Device\Harddisk0\Partition4
\Device\HarddiskVolume3
\Device\HarddiskVolume3
\Device\Mup\;Csc
\Device\Harddisk0\DR0
\Device\HarddiskVolume1
\Device\HarddiskVolume2
\Device\HarddiskVolume3
\Device\HarddiskVolume4
\Device\HarddiskVolumeShadowCopy1
\Device\HarddiskVolumeShadowCopy3
\Device\HarddiskVolumeShadowCopy2
\Device\Mup\;hgfs
\Device\Tdx
\Device\Tdx
\Device\Mup\;LanmanRedirector
\Device\Mup\;MailslotRedirector
\Device\Mup\;RdpDr
\Device\Ide\IdePort0
\Device\Ide\IdePort1
\Device\RaidPort0
\Device\RaidPort1
\Device\HarddiskVolume1
\Device\NDMP1
\Device\DfsClient
\Device\00000013
\Device\00000013
\Device\0000001c
\Device\0000001c
\Device\0000001d
\Device\0000001d
\Device\0000001e
\Device\0000001e
\Device\0000001f
\Device\0000001f
\Device\00000020
\Device\00000020
\Device\00000021
\Device\00000021
\Device\00000022
\Device\00000022
\Device\00000023
\Device\00000023
\Device\00000024
\Device\00000024
\Device\00000025
\Device\00000025
\Device\00000026
\Device\00000026
\Device\00000027
\Device\00000027
\Device\00000028
\Device\00000028
\Device\00000029
\Device\00000029
\Device\0000002a
\Device\0000002a
\Device\0000002b
\Device\0000006f
\Device\00000073
\Device\00000073
\Device\00000068
\Device\00000070
\Device\00000010
\Device\ahcache
\DosDevices\COM1
\Device\BitLocker
\Device\HarddiskVolume3
\Device\HarddiskVolume3
\Device\CdRom0
\Device\cimfs\control
\Device\Serial0
\Device\ConDrv\Console
\Device\ConDrv\CurrentIn
\Device\ConDrv\CurrentOut
\Device\CdRom0
\Device\Harddisk0\DR0
\Device\00000081
\Device\00000081
\Device\00000081
\Device\Video0
\Device\Video1
\Device\Video2
\Device\Video3
\Device\Video4
\Device\Video5
\Device\Video6
\Device\Video7
\Device\Video8
\Device\EneTechIo
\Device\FsWrap
\Device\gpuenergydrv
\Device\HarddiskVolume1
\Device\HarddiskVolume2
\Device\HarddiskVolume3
\Device\HarddiskVolume4
\Device\HarddiskVolume1
\Device\HarddiskVolume2
\Device\HarddiskVolume3
\Device\HarddiskVolume4
\Device\HarddiskVolumeShadowCopy1
\Device\HarddiskVolumeShadowCopy2
\Device\HarddiskVolumeShadowCopy3
\Device\USBFDO-0
\Device\USBFDO-1
\Device\USBFDO-2
\Device\00000079
\Device\00000079
\Device\00000079
\Device\00000079
\Device\00000079
\Device\00000079
\Device\00000079
\Device\0000007f
\Device\0000007f
\Device\00000080
\Device\00000080
\Device\IPSECDOSP
\Device\IRPMnDrv
\Device\LLDPCTRL
\Device\MailSlot
\Device\MountPointManager
\Device\MPS
\Device\MSSECFLTSYS
\Device\MSSGRMAGENTSYS
\Device\Ndis
\Device\NduIoDevice
\Device\Nsi
\Device\Null
\Device\NXTIPSEC
\Device\PartmgrControl
\Device\NTPNP_PCI0006
\Device\NTPNP_PCI0006
\Device\NTPNP_PCI0043
\Device\NTPNP_PCI0041
\Device\NTPNP_PCI0045
\Device\NTPNP_PCI0044
\Device\NTPNP_PCI0046
\Device\NTPNP_PCI0046
\Device\PciControl
\Device\Ide\PciIde0Channel0
\Device\Ide\PciIde0Channel1
\Device\PEAuth
\Device\Harddisk0\DR0
\Device\NamedPipe
\DosDevices\LPT1
\Device\Psched
\Device\RdpDrDvMgr
\Device\RESOURCE_HUB
\Device\00000002
\Device\0000000a
\Device\00000007
\Device\00000007
\Device\00000006
\Device\00000006
\Device\0000000e
\Device\0000000e
\Device\0000000e
\Device\0000000e
\Device\0000000e
\Device\0000000e
\Device\0000000e
\Device\00000008
\Device\00000005
\Device\00000001
\Device\00000074
\Device\00000074
\Device\00000076
\Device\Ide\IdePort0
\Device\Ide\IdePort1
\Device\RaidPort0
\Device\RaidPort1
\Device\Spaceport
\Device\HarddiskVolume1
\Device\HarddiskVolume2
\Device\HarddiskVolume3
\Device\HarddiskVolume4
\Device\000000ae
\Device\000000ab
\Device\000000ac
\Device\000000aa
\Device\00000089
\Device\00000088
\Device\0000008a
\Device\000000a0
\Device\000000a2
\Device\000000a1
\Device\0000009f
\Device\HarddiskVolume1
\Device\Tcp
\Device\00000086
\Device\00000085
\Device\00000082
\Device\00000084
\Device\00000083
\Device\Mup
\Device\USBPDO-1
\Device\USBPDO-2
\Device\USBPDO-0
\Device\USBPDO-3
\Device\00000005
\Device\vmci
\Device\VMCIHostDev
\Device\VmGenerationCounter
\Device\hgfsInternal
\Device\vmmemctl
\Device\VolMgrControl
\Device\HarddiskVolume4
\Device\HarddiskVolume1
\Device\CdRom0
\Device\HarddiskVolume3
\Device\vwififlt
\Device\wdnisdrv
\Device\WfpAle
\Device\WFP
\Device\WindowsTrustedRT
\Device\WMIDataDevice
\Device\NDMP1
\Device\OSDataDevice
\Device\BootDevice\Windows
```

There's not even that fucking many of them and I know for a fact some are missing there. Whatever, fuck it, good enough. Anyway, now my goal is to just brute force the fuck out of ioctls here. DIBF will do just fine along with a quick couple of lines of python:


```
from concurrent.futures import ThreadPoolExecutor # pip install futures
from subprocess import STDOUT, call
import re
import subprocess



handles = open("handles.txt")
handles_list = []

for line in handles:
    _line = line.strip().split()
    if _line != []:
        handles_list.append(_line[-1])


handles_new = (list(set(handles_list)))

for line in handles_new:

    limit=10
    line = line.strip()
    _filename = line.strip().replace("\\", "_")
    devname = line.strip().replace("\\Device", "\\\\?")
    print(devname)
    cmd = ".\dibf.exe -f 0 -s 0x0 -e 0xffffffff -l " + _filename + " " + devname
    print(cmd)
    x = subprocess.run(cmd, shell=True, capture_output = True)
    print(x)
```
of course this wouldn't be hacking without a hacky as shit python script. Instead of dealing with multithreading, I just kick this off 3 times, once with a file of handles, once wwith the same file backwards, and again with the same file starting somewhere in the middle. Fuck threading, fuck all of that. This should get me some results quick if I leave it on overnight and all day! Time to get me some IOCTL codes. Then i can even use that same logfile to feed into DIBF and use its fuzzer, which I haven't been impressed with, but hey, throw it at a bunch of targets and something will probably crash.

As you can see I have a very very clever title for this, like with everything else. It's called You Can't HANDLE the Truth:

```
λ ls
_Device_WindowsTrustedRT  DIBF/  dibf.exe*  handles.txt  handles2.txt  handles3.txt  youcanthandlethetruth.py  youcanthandlethetruth.py~

C:\Users\0day\Desktop\dynamic-analysis-tools\custom\youcanthandle
λ python youcanthandlethetruth.py
```

Perhaps tomorrow i'll iteratively improve this, or perhaps not. On deck are: recreating an IRP-mon like functionality with a mutational fuzzer, doing more RE work on vmhgfs, doing more fuzz work on vmhgfs, and continuing my analysis of explorer.exe, which i was just getting my teeth into! So much stuff to do so little time....

I even have my first IOCTLs already!

```
C:\Users\0day\Desktop\dynamic-analysis-tools\custom\youcanthandle
λ cat _Device_WindowsTrustedRT
\\?\WindowsTrustedRT
94264 0 2000
98268 0 2000
560008 0 2000
```










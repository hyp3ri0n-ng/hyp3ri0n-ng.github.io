---
layout: post
title: Picking Up the Pieces
tags: [hacking]
---

OK maybe that's a dramatic title. Anyway, I was on day 4 or 5 or whatever of my 20 days of 0-day, a stupid little challenge I made for myself. Then I had an idea: I've always hated WinDBG, the syntax is fucked, writing scripts sucks, and overall I hate it. I've always dreamed of creating my own debugger based on it. Why based on it? Well, because it's the only debugger that supports kernel debugging. I dubbed this project LokiKD. I started writing it, I'll be committing my code soon, but to be honest, I realized exactly _how much random shit windbg supports_ and it made me lose my faith in the project. I was wondering why no one had done it and now it makes total sense - WinDBG is just good enough that people won't be writing their own debugger, and the people that are writing WinDBG have the wonderful ability to see the source of the stuff they're debugging. So WinDBG it is. Loki is dead, long live WinDBG.

So let's get back to our fuzzing, here's about where we were:

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
    pidlAbsolute->mkid.abID;
    pidlAbsolute->mkid.cb;
    SHGetFolderLocation(0, 5, 0, 0, &pidlAbsolute);
    ILFree(pidlAbsolute);

    //printf("RETURNING");
    return 0;
};

/*

int main() {
    //const uint8_t *Data = (const uint8_t *) "C:\\AAA" "\x0a" "\x0d" "AA\\BBBBB\\\x0a";
    //const uint8_t *Data = (const uint8_t *) "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\..";
    const uint8_t Data[] = {0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x41};
    std::cout << sizeof(Data) << "\n\n\n";
    size_t size = sizeof(Data);
    fuzzMeDrZaus(Data, size);
    return 0;
};
*/


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  fuzzMeDrZaus(Data, Size);
  return 0;
}
```

alright, supatight. We're targeting that last function to see if we can get some sort of corruption. The sidetracking i've had over the last two days was because I started using WinDBG to try to further understand the structure of pidlAbsolute. It's actually somewhat interesting, so let's go over a little bit about how I did that. OK, so remember in Binary Ninja, we saw a call to this function exactly as we wrote it in our own source. However, I want to make sure that when we fuzz we're creating reasonable stuff and not shoving in data that we could not reasonably get to as a normal user. That means we actually have to understand the function and arguments pretty well. What I found was interesting-ish. Let's take a look. Since we've really been taking a look at the shell32 SH prefixed functions and SHGetFolderLocation() is included in that, why don't we put some breakpoints to interesting functions. Here's what I do:

```
0:000> bm shell32!SH*
  1: 00007ff8`141dfe24 @!"SHELL32!SHGetLogonID"
  2: 00007ff8`1421eb80 @!"SHELL32!SHGetSetSettings"
  3: 00007ff8`142913b0 @!"SHELL32!SHGetStockIconInfo"
  4: 00007ff8`1425857c @!"SHELL32!SHRegSetDWORD"
  5: 00007ff8`141e7838 @!"SHELL32!ShellExecuteProvider::ShellExecuteExW::StartActivity"
  6: 00007ff8`141fd790 @!"SHELL32!SHChangeNotifyRegister"
  7: 00007ff8`141fd09c @!"SHELL32!SHGetAttributesWithBindCtx"
  8: 00007ff8`1424df00 @!"SHELL32!ShellExecuteProvider::`scalar deleting destructor'"
  9: 00007ff8`1425ce80 @!"SHELL32!SHTestTokenMembership"
 10: 00007ff8`141bdc40 @!"SHELL32!SHRegGetGUID"
 11: 00007ff8`142acdc0 @!"SHELL32!SHCreatePropSheetExtArrayEx"
 12: 00007ff8`141e76c8 @!"SHELL32!ShellExecuteProvider::ShellExecuteNormal::StartActivityWithCorrelationVector"
 13: 00007ff8`141e7290 @!"SHELL32!ShellExecuteExW"
 14: 00007ff8`141dbf40 @!"SHELL32!SHGetFolderTypeFromCanonicalName"
 15: 00007ff8`14245920 @!"SHELL32!SHIsSameObject"
 16: 00007ff8`1422d400 @!"SHELL32!SHGetImageList"
 17: 00007ff8`141c3980 @!"SHELL32!SHGetThreadUndoManager"
 18: 00007ff8`1420db30 @!"SHELL32!Shell_GetStockImageIndex"
 19: 00007ff8`142482c0 @!"SHELL32!SHCreateLocalServer"
 20: 00007ff8`141edc84 @!"SHELL32!SHCleanupSeparators"
 21: 00007ff8`14240b34 @!"SHELL32!SHWaitOp_Create"
 22: 00007ff8`1420b100 @!"SHELL32!SHDefExtractIconW"
 23: 00007ff8`1422aa38 @!"SHELL32!SHGetFilterFromIDList"
 24: 00007ff8`141fe1c0 @!"SHELL32!SHGetNameAndFlagsW"
 25: 00007ff8`142a2670 @!"SHELL32!SHCreateShellItem"
 26: 00007ff8`1423e6cc @!"SHELL32!SHILClone"
 27: 00007ff8`14254480 @!"SHELL32!SHELL32_VerifySaferTrust"
 28: 00007ff8`14283e38 @!"SHELL32!ShStrW::SetStr"
 29: 00007ff8`1426970c @!"SHELL32!SHQueryToken<_TOKEN_USER>"
 30: 00007ff8`1421fee0 @!"SHELL32!SHMapIDListToSystemImageListIndexAsync2"
 31: 00007ff8`141d74e0 @!"SHELL32!SHGetAttributesFromDataObject"
 32: 00007ff8`141f07fc @!"SHELL32!SHGetFileInfoW"
 33: 00007ff8`141d0280 @!"SHELL32!SHCreateCAssocHandler"
 34: 00007ff8`141df730 @!"SHELL32!SHProcessMessagesUntilEventsEx"
 35: 00007ff8`141ff550 @!"SHELL32!SHCompareIDsFull"
 36: 00007ff8`14263aa0 @!"SHELL32!SHCreateDesktop"
 37: 00007ff8`1422b9e8 @!"SHELL32!Shell_SysColorChange"
 38: 00007ff8`142ae470 @!"SHELL32!Shell_NotifyIconGetRect"
 39: 00007ff8`1420332c @!"SHELL32!SHCompareIDs"
 40: 00007ff8`141c3a30 @!"SHELL32!SHCreateThreadUndoManager"
 41: 00007ff8`141e4aa0 @!"SHELL32!SHIsCurrentAppElevated"
 42: 00007ff8`1422e4e8 @!"SHELL32!SHFusionInitializeFromModuleID"
breakpoint 8 redefined
  8: 00007ff8`1424df00 @!"SHELL32!Shell32Logging::`scalar deleting destructor'"
 43: 00007ff8`142aac9c @!"SHELL32!SHGetDetailsOfInfo"
 44: 00007ff8`1424df40 @!"SHELL32!Shell32LoggingTelemetry::`scalar deleting destructor'"
 45: 00007ff8`141bba6c @!"SHELL32!SHKeepDUIInitializedForThread"
 46: 00007ff8`142a99e0 @!"SHELL32!SHFusionDialogBoxParam"
 47: 00007ff8`1428fb90 @!"SHELL32!SHGetUserDisplayName"
 48: 00007ff8`141ce130 @!"SHELL32!SHGetFileInfoA"
 49: 00007ff8`141c42b0 @!"SHELL32!SHGetCorrectOwnerSid"
 50: 00007ff8`14204990 @!"SHELL32!SHLogILFromFSIL"
 51: 00007ff8`141ff228 @!"SHELL32!SHChangeNotification_Create"
 52: 00007ff8`14283f08 @!"SHELL32!ShStrW::Reset"
 53: 00007ff8`141d853c @!"SHELL32!SHGetItemArrayFromDataObjEx"
 54: 00007ff8`141d430c @!"SHELL32!ShouldAllowLibraryEditing"
 55: 00007ff8`1423e350 @!"SHELL32!SHELL32_GetPlaceholderStatesFromFileAttributesAndReparsePointTag"
 56: 00007ff8`1420a6b0 @!"SHELL32!SHBindToParent"
 57: 00007ff8`141c937c @!"SHELL32!SHMapCmdIDToVerb"
 58: 00007ff8`141ee1e0 @!"SHELL32!SHPrepareMenuForDefcm"
 59: 00007ff8`141dfebc @!"SHELL32!SHQueryToken<_TOKEN_GROUPS>"
 60: 00007ff8`141d719c @!"SHELL32!SHGetAttributesRequiringElevationFromDataObject"
 61: 00007ff8`1423f074 @!"SHELL32!SHEvaluateSystemCommandTemplateWithOptions"
 62: 00007ff8`141f2594 @!"SHELL32!SHGetUIObjectOfItem"
 63: 00007ff8`142735f4 @!"SHELL32!SHLogicalToPhysicalDPI"
 64: 00007ff8`1422ab4c @!"SHELL32!SHGetFiltersFromIDList"
 65: 00007ff8`141db5c8 @!"SHELL32!SHBindWithFolder2Shim"
 66: 00007ff8`141e1950 @!"SHELL32!SHRegGetFILETIME"
 67: 00007ff8`142058d0 @!"SHELL32!SHCreateItemInKnownFolder"
 68: 00007ff8`14260860 @!"SHELL32!ShouldNavPaneShowLibraries"
 69: 00007ff8`141cb428 @!"SHELL32!SHGetTargetFolderIDList"
 70: 00007ff8`141c4f30 @!"SHELL32!SHAssocEnumHandlers"
 71: 00007ff8`14252d00 @!"SHELL32!SHGetDataFromIDListW"
 72: 00007ff8`141e6f54 @!"SHELL32!ShellExecuteProvider::ShellExecuteNormal::~ShellExecuteNormal"
 73: 00007ff8`141deb74 @!"SHELL32!ShouldUseFriendlyDates"
 74: 00007ff8`142aa62c @!"SHELL32!SHAddIconsToCache"
 75: 00007ff8`141e73ec @!"SHELL32!ShellExecuteProvider::ShellExecuteExW::Stop"
 76: 00007ff8`14261ee8 @!"SHELL32!SHRegGetBOOLWithREGSAM"
 77: 00007ff8`141fede0 @!"SHELL32!SHChangeNotify"
 78: 00007ff8`1422b570 @!"SHELL32!Shell_GetImageLists"
 79: 00007ff8`14283ec0 @!"SHELL32!ShStrW::SetSize"
 80: 00007ff8`141f42f4 @!"SHELL32!SHOpenEffectiveToken"
 81: 00007ff8`1420a2d0 @!"SHELL32!SHGetIDListFromObject"
 82: 00007ff8`142200e0 @!"SHELL32!SHGetIconIndexFromPIDL"
 83: 00007ff8`14283130 @!"SHELL32!SHCleanupUrlForDisplay"
 84: 00007ff8`1423f9f8 @!"SHELL32!SHRegAllocData"
 85: 00007ff8`141b374c @!"SHELL32!SHGetTargetItem"
 86: 00007ff8`1422f60c @!"SHELL32!SHLogicalToPhysicalDPIMetric"
 87: 00007ff8`141ff43c @!"SHELL32!SHCoInitialize"
 88: 00007ff8`14248434 @!"SHELL32!SHQueryToken<_TOKEN_MANDATORY_LABEL>"
 89: 00007ff8`142071c0 @!"SHELL32!SHILAliasTranslate"
 90: 00007ff8`141e7150 @!"SHELL32!ShellExecuteProvider::ShellExecuteNormal::StopActivity"
 91: 00007ff8`1420adb0 @!"SHELL32!SHBindToFolderIDListParentEx"
 92: 00007ff8`141f4b00 @!"SHELL32!Shell_NotifyIconW"
 93: 00007ff8`141e7538 @!"SHELL32!ShellExecuteNormal"
 94: 00007ff8`141e7378 @!"SHELL32!ShellExecuteProvider::ShellExecuteExW::~ShellExecuteExW"
 95: 00007ff8`14206ca0 @!"SHELL32!SHGetPathFromIDListAlloc"
 96: 00007ff8`14263fa0 @!"SHELL32!SHChangeNotifyDeregister"
 97: 00007ff8`1423a7d0 @!"SHELL32!SHPrivateExtractIcons"
 98: 00007ff8`141ed820 @!"SHELL32!Shell_MergeMenus"
 99: 00007ff8`142ace90 @!"SHELL32!SHDestroyPropSheetExtArray"
100: 00007ff8`1420e6b0 @!"SHELL32!Shell_GetCachedImageIndexW"
101: 00007ff8`141f8604 @!"SHELL32!SHExePathFromPid"
102: 00007ff8`1425d69c @!"SHELL32!SHWaitOp_OperateInternal"
103: 00007ff8`14255320 @!"SHELL32!SHCreateSessionKey"
104: 00007ff8`143e0b3c @!"SHELL32!SHBoolSystemParametersInfoEx"
105: 00007ff8`1469db2c @!"SHELL32!ShellItemArraySupportsSyncOrShare"
106: 00007ff8`143c13d0 @!"SHELL32!Shell32LoggingTelemetry::WinOldLowStorageCleanup::StopActivity"
107: 00007ff8`14430820 @!"SHELL32!SHGetUserPicturePathEx"
108: 00007ff8`14439ed0 @!"SHELL32!SHQueryRecycleBinW"
109: 00007ff8`143e0d1c @!"SHELL32!Shell32RegTypeLib"
110: 00007ff8`1442aef0 @!"SHELL32!SHELL32_CDrivesContextMenu_Create"
111: 00007ff8`1442ad10 @!"SHELL32!SHELL32_CDBurn_IsBlankDisc"
112: 00007ff8`1442af10 @!"SHELL32!SHELL32_CDrives_CreateSFVCB"
113: 00007ff8`1427f060 @!"SHELL32!ShellItemLinkFitter::GetClassInfoW"
114: 00007ff8`146e0874 @!"SHELL32!SHFusionTaskDialogIndirect"
115: 00007ff8`1442b050 @!"SHELL32!SHELL32_CRecentDocsContextMenu_CreateInstance"
116: 00007ff8`1442ad20 @!"SHELL32!SHELL32_CDBurn_IsBlankDisc2"
117: 00007ff8`1444dea0 @!"SHELL32!SHTraceSQMSetValue"
118: 00007ff8`14693b10 @!"SHELL32!SHUserSetPasswordHint"
119: 00007ff8`145d1c80 @!"SHELL32!ShouldProceedWithOperation"
120: 00007ff8`1435d300 @!"SHELL32!Shell32LoggingTelemetry::BurnDisc::StartActivity"
121: 00007ff8`142b1570 @!"SHELL32!SHELL32_PifMgr_GetProperties"
122: 00007ff8`143bae2c @!"SHELL32!Shell32LoggingTelemetry::GetClipboard_"
123: 00007ff8`1424a740 @!"SHELL32!SHUpdateRecycleBinIcon"
124: 00007ff8`1436c230 @!"SHELL32!SHInvokePrinterCommandW"
125: 00007ff8`1442b430 @!"SHELL32!SHELL32_SHCreateLocalServer"
126: 00007ff8`141cfe70 @!"SHELL32!SHELL32_CSyncRootManager_CreateInstance"
127: 00007ff8`1422ad00 @!"SHELL32!SHSettingsChanged"
128: 00007ff8`1442b0c0 @!"SHELL32!SHELL32_CanDisplayWin8CopyDialog"
129: 00007ff8`1436c150 @!"SHELL32!SHInvokePrinterCommandA"
130: 00007ff8`1469f324 @!"SHELL32!SHDoFilesExistForVirtualizedFolder"
131: 00007ff8`143a86c0 @!"SHELL32!SHGetUnreadMailCountW"
132: 00007ff8`14435c80 @!"SHELL32!SHGetIconOverlayIndexA"
133: 00007ff8`1437d118 @!"SHELL32!SHGetMachineGUID"
134: 00007ff8`141d2be0 @!"SHELL32!SHCreateLocalServerRunDll"
135: 00007ff8`1422e338 @!"SHELL32!SHFusionCreateWindowEx"
136: 00007ff8`14650468 @!"SHELL32!ShellMRTHelper::MRTHelperBase::ResolvePath"
137: 00007ff8`143ad730 @!"SHELL32!ShowFormatInitErrorDialog"
138: 00007ff8`146a50b8 @!"SHELL32!SHAnimateWindowSize"
139: 00007ff8`141e8000 @!"SHELL32!SHELL32_AreAllItemsAvailable"
breakpoint 121 redefined
121: 00007ff8`142b1570 @!"SHELL32!SHWaitForFileToOpen"
140: 00007ff8`14503da4 @!"SHELL32!SHEncryptFile"
141: 00007ff8`14570040 @!"SHELL32!ShellPlaceholderLinkVerb::Execute"
142: 00007ff8`146dd618 @!"SHELL32!SHQualifyUsernameAsLocal"
143: 00007ff8`14696ec0 @!"SHELL32!SHGetTargetFolderItem"
144: 00007ff8`143e3a10 @!"SHELL32!SHQueryUserNotificationState"
145: 00007ff8`142aad34 @!"SHELL32!SHResToStrRet"
146: 00007ff8`1435cc6c @!"SHELL32!SHCreateOriginalItemBindCtx"
147: 00007ff8`143e3990 @!"SHELL32!SHKnownFolderFromCSIDLStub"
148: 00007ff8`1444e8ec @!"SHELL32!SHGetComparisonInfoEx"
149: 00007ff8`141d7d28 @!"SHELL32!SHRegCloseKeys"
150: 00007ff8`143b00bc @!"SHELL32!SHChkDskDriveEx"
151: 00007ff8`1436ffe0 @!"SHELL32!ShellExecuteExA"
152: 00007ff8`1469f0ac @!"SHELL32!SHGetRunLevelFromActCtx"
153: 00007ff8`146dd3f4 @!"SHELL32!SHGetRIDFromSID"
154: 00007ff8`146635cc @!"SHELL32!ShowHideIconOnlyOnDesktop"
155: 00007ff8`1456a064 @!"SHELL32!SHCreateByValueOperationInterrupt"
156: 00007ff8`14641c20 @!"SHELL32!SHELL32_SendToMenu_InvokeTargetedCommand"
157: 00007ff8`1427d500 @!"SHELL32!SHLoadInProc"
158: 00007ff8`146932b4 @!"SHELL32!SHDeleteDataFileForUser"
159: 00007ff8`1442b340 @!"SHELL32!SHELL32_GetSqmableFileName"
160: 00007ff8`1425af00 @!"SHELL32!SHGetFolderTypeDescription"
161: 00007ff8`14346444 @!"SHELL32!SheGetDirW"
162: 00007ff8`1442ac80 @!"SHELL32!SHELL32_CDBurn_Erase"
163: 00007ff8`14342e28 @!"SHELL32!SHGetSetCLSID"
164: 00007ff8`1442ceb0 @!"SHELL32!SHLoadLegacyRegUIStringW"
165: 00007ff8`146a347c @!"SHELL32!SHGetTopBrowserWindow"
166: 00007ff8`14351240 @!"SHELL32!SHAddToRecentDocsEx"
167: 00007ff8`1442b540 @!"SHELL32!SHELL32_StampIconForFile"
168: 00007ff8`1449d320 @!"SHELL32!Shell32LoggingTelemetry::EmptyRecycleBin<long & __ptr64>"
169: 00007ff8`145efea0 @!"SHELL32!ShellItemLinkFitter::GetAdjacent"
170: 00007ff8`144375b0 @!"SHELL32!SHLimitInputEdit"
171: 00007ff8`144140d0 @!"SHELL32!SHCoCreateInstanceWorker"
172: 00007ff8`143bf510 @!"SHELL32!Shell32LoggingTelemetry::WinOldLowStorageNotify<unsigned long & __ptr64,enum LOWDISK_STATE & __ptr64,long & __ptr64>"
173: 00007ff8`142b52a0 @!"SHELL32!Shell32LoggingTelemetry::LowDisk::WasAlreadyReportedToTelemetry"
174: 00007ff8`143e9818 @!"SHELL32!SHInvokeCommandOnContextMenu2"
175: 00007ff8`1436e4c8 @!"SHELL32!SHGetAttributes"
176: 00007ff8`143b9c20 @!"SHELL32!SHGetLocalizedName"
177: 00007ff8`143ad848 @!"SHELL32!Shell32LoggingTelemetry::FormatDialog::StartActivity"
178: 00007ff8`144885e0 @!"SHELL32!ShellItemLinkFitter::Register"
179: 00007ff8`141d84fc @!"SHELL32!SHGetItemArrayFromDataObj"
breakpoint 173 redefined
173: 00007ff8`142b52a0 @!"SHELL32!ShellExecuteProvider::ShellExecuteNormal::WasAlreadyReportedToTelemetry"
180: 00007ff8`146dd758 @!"SHELL32!SHTranslateNameToSID"
181: 00007ff8`1442b4c0 @!"SHELL32!SHELL32_SHOpenWithDialog"
182: 00007ff8`1442f970 @!"SHELL32!SHResolveUserNames"
183: 00007ff8`146a33b0 @!"SHELL32!SHGetNavigateTarget"
184: 00007ff8`141c4db8 @!"SHELL32!SHComputeSystemToMonitorDPIRatio"
185: 00007ff8`1442ad00 @!"SHELL32!SHELL32_CDBurn_GetTaskInfo"
186: 00007ff8`14268884 @!"SHELL32!SHGetCachedPrivateProfile"
187: 00007ff8`143b9f20 @!"SHELL32!SHGetPropertyStoreFromIDList"
188: 00007ff8`1442b3a0 @!"SHELL32!SHELL32_NormalizeRating"
189: 00007ff8`146a8154 @!"SHELL32!SHAcctGetProgramDataDirectory"
190: 00007ff8`1425cb50 @!"SHELL32!SHELL32_GetDPIAdjustedLogicalSize"
191: 00007ff8`14414288 @!"SHELL32!SHExtCoCreateInstanceString"
192: 00007ff8`146ddf08 @!"SHELL32!SHRegSetExpandStringW"
193: 00007ff8`141ea8c0 @!"SHELL32!SHCreateItemFromParsingName"
194: 00007ff8`1426d730 @!"SHELL32!SHELL32_AddToBackIconTable"
195: 00007ff8`143b9dd0 @!"SHELL32!SHGetNewLinkInfoA"
196: 00007ff8`146a3274 @!"SHELL32!SHGetUserPictureFromTileData"
197: 00007ff8`1469c978 @!"SHELL32!SHBeginLabelEdit"
198: 00007ff8`146996a4 @!"SHELL32!SHCreateFilteredIDList"
199: 00007ff8`14677830 @!"SHELL32!SHShowManageLibraryUI"
200: 00007ff8`141ffd78 @!"SHELL32!SHILCombine"
201: 00007ff8`145b7148 @!"SHELL32!SHResolveFilterConditionEx"
202: 00007ff8`14503fb4 @!"SHELL32!SHIsSystemFileEncryptable"
203: 00007ff8`1425b100 @!"SHELL32!ShellDDEInit"
204: 00007ff8`143b9ef0 @!"SHELL32!SHGetNewLinkInfoW"
205: 00007ff8`143fe5b0 @!"SHELL32!SHGetComputerDisplayName"
206: 00007ff8`143a8f50 @!"SHELL32!SHSetUnreadMailCountW"
207: 00007ff8`1436fe00 @!"SHELL32!ShellExec_RunDLLW"
208: 00007ff8`1442b0f0 @!"SHELL32!SHELL32_CloseAutoplayPrompt"
209: 00007ff8`1442b330 @!"SHELL32!SHELL32_GetSkyDriveNetworkStates"
210: 00007ff8`143f1434 @!"SHELL32!ShowAdminInfoTaskDialog"
211: 00007ff8`1428f390 @!"SHELL32!SHAddDefaultPropertiesByExt"
212: 00007ff8`1436fd50 @!"SHELL32!ShellExec_RunDLLA"
213: 00007ff8`1442b5a0 @!"SHELL32!SHELL32_TryVirtualDiscImageDriveEject"
214: 00007ff8`142c4a90 @!"SHELL32!ShouldSkipHandler"
215: 00007ff8`143a06b4 @!"SHELL32!SHCreateFileOperation"
216: 00007ff8`143a83e0 @!"SHELL32!SHFindComputer"
217: 00007ff8`143bf430 @!"SHELL32!Shell32LoggingTelemetry::StorageToastCloudConsentNotify<unsigned long & __ptr64,enum LOWDISK_STATE & __ptr64,long & __ptr64>"
218: 00007ff8`1442b460 @!"SHELL32!SHELL32_SHEncryptFile"
219: 00007ff8`14240cb0 @!"SHELL32!SHGetItemFromDataObject"
220: 00007ff8`143f0c50 @!"SHELL32!SHDefExtractIconA"
221: 00007ff8`145042fc @!"SHELL32!ShowMountedVolumeProperties"
222: 00007ff8`143ba040 @!"SHELL32!SHMapIDListToSystemImageListIndex"
223: 00007ff8`143cbd98 @!"SHELL32!SHResolveFilterCondition"
224: 00007ff8`143a0790 @!"SHELL32!SHCreateInfotipControl"
225: 00007ff8`14426c80 @!"SHELL32!SHCreateRelatedItemFromIDList"
226: 00007ff8`1439b584 @!"SHELL32!ShouldUseStorageProviderViews"
227: 00007ff8`146c877c @!"SHELL32!SHIsExplorerIniChange"
228: 00007ff8`1464d634 @!"SHELL32!ShellMRTHelper::Common::ConvertMsAppXUriToMsResourceUri"
229: 00007ff8`14650634 @!"SHELL32!SHCheckPathPermissions"
230: 00007ff8`1424dc10 @!"SHELL32!Shell32LoggingTelemetry::ShellExtensionList<unsigned short const * __ptr64 & __ptr64,unsigned short const * __ptr64 & __ptr64,unsigned long & __ptr64,unsigned short const * __ptr64 & __ptr64,bool>"
231: 00007ff8`14692d9c @!"SHELL32!SHCreateDataFileForUser"
232: 00007ff8`1442b260 @!"SHELL32!SHELL32_FreeEncryptedFileKeyInfo"
233: 00007ff8`14414160 @!"SHELL32!SHExtCoCreateInstanceCheckCategory"
234: 00007ff8`1442b1f0 @!"SHELL32!SHELL32_CreateSharePointView"
235: 00007ff8`1442b280 @!"SHELL32!SHELL32_GenerateAppID"
236: 00007ff8`1434318c @!"SHELL32!SHGetSetFolderSetting"
237: 00007ff8`146937f4 @!"SHELL32!SHSetPictureIntoDataFileForUser"
238: 00007ff8`1442b380 @!"SHELL32!SHELL32_LegacyEnumSpecialTasksByType"
239: 00007ff8`143512e0 @!"SHELL32!SHFreeNameMappings"
240: 00007ff8`1469d80c @!"SHELL32!SHGetAccelerator"
241: 00007ff8`14351280 @!"SHELL32!SHCreateShellItemArray"
242: 00007ff8`144cfa5c @!"SHELL32!SHIsVirtualDevice"
243: 00007ff8`14696bac @!"SHELL32!ShouldTranslateForNavigation"
244: 00007ff8`143c087c @!"SHELL32!Shell32LoggingTelemetry::LowDisk::StartActivity"
245: 00007ff8`1442b3f0 @!"SHELL32!SHELL32_ResolveLinkInfoW"
246: 00007ff8`146df358 @!"SHELL32!ShouldShowHomegroupUsersForStatus"
247: 00007ff8`14693a70 @!"SHELL32!SHUserGetPasswordHint"
248: 00007ff8`1442c8ec @!"SHELL32!SHDoesComCatCacheExist"
249: 00007ff8`143a7f00 @!"SHELL32!SHCreateDirectoryExAStub"
250: 00007ff8`1421fde0 @!"SHELL32!SHMapIDListToSystemImageListIndexAsync"
251: 00007ff8`143fdae0 @!"SHELL32!SHILCreateFromPath"
252: 00007ff8`14344b28 @!"SHELL32!SHDeleteFilePidl"
253: 00007ff8`143adab0 @!"SHELL32!Shell32LoggingTelemetry::FormatDialog::StopActivity"
254: 00007ff8`1464d748 @!"SHELL32!ShellMRTHelper::Common::ConvertMsAppXUriToMsResourceUri"
255: 00007ff8`1466ff54 @!"SHELL32!ShowShellInfraCriticalFailureDialogAndWait"
256: 00007ff8`144b8f30 @!"SHELL32!SHGetParsingNameFromPropertyStore"
257: 00007ff8`1442b490 @!"SHELL32!SHELL32_SHIsVirtualDevice"
258: 00007ff8`1442af80 @!"SHELL32!SHELL32_CLocationFolderUI_CreateInstance"
259: 00007ff8`14409a60 @!"SHELL32!SHHandleUpdateImage"
260: 00007ff8`14341af0 @!"SHELL32!SHCreateStdEnumFmtEtc"
261: 00007ff8`14570c28 @!"SHELL32!SHInvokeCommandOnItem"
262: 00007ff8`143ba100 @!"SHELL32!SHSetLocalizedName"
263: 00007ff8`1428d62c @!"SHELL32!SHILCombineParentAndFirst"
264: 00007ff8`1442b480 @!"SHELL32!SHELL32_SHGetThreadUndoManager"
breakpoint 121 redefined
121: 00007ff8`142b1570 @!"SHELL32!ShellHookProc"
265: 00007ff8`143be37c @!"SHELL32!Shell32LoggingTelemetry::TryFileDataObject<long & __ptr64>"
266: 00007ff8`14344c0c @!"SHELL32!SHFastDeleteFile"
267: 00007ff8`144db1e0 @!"SHELL32!ShowHelp"
268: 00007ff8`143a9258 @!"SHELL32!SHSysErrorMessageBox"
269: 00007ff8`14243e70 @!"SHELL32!SHCreateAssociationRegistration"
270: 00007ff8`14358c80 @!"SHELL32!SHOpenWithDialog"
271: 00007ff8`143b97d0 @!"SHELL32!SHCreateLinks"
272: 00007ff8`143f7664 @!"SHELL32!SHStampIcon"
273: 00007ff8`1422e478 @!"SHELL32!SHActivateContext"
274: 00007ff8`145424b4 @!"SHELL32!ShouldDisableAppHostedViewSubCommand"
275: 00007ff8`14615044 @!"SHELL32!ShouldAddLinkPage"
276: 00007ff8`14614f58 @!"SHELL32!SHFindLinkTarget"
277: 00007ff8`141c7794 @!"SHELL32!SHFormatResMessageArgAllocVA"
278: 00007ff8`145b4b0c @!"SHELL32!Shell32LoggingTelemetry::FormatDiscUdf::StartActivity"
279: 00007ff8`14415f40 @!"SHELL32!SHCreateCategoryEnum"
280: 00007ff8`143e39f0 @!"SHELL32!SHPropStgWriteMultipleStub"
281: 00007ff8`1420d9a0 @!"SHELL32!SHFree"
282: 00007ff8`14426d20 @!"SHELL32!SHCreateRelatedItemWithParent"
283: 00007ff8`143cbb6c @!"SHELL32!SHGetCategorizer"
284: 00007ff8`143a7f20 @!"SHELL32!SHCreateFilterFromFullText"
285: 00007ff8`14280010 @!"SHELL32!ShellPlaceholderLinkVerb::v_EnableCommand"
286: 00007ff8`143f0024 @!"SHELL32!SHLoadLibraryFromItem"
287: 00007ff8`14263ec0 @!"SHELL32!SHDesktopMessageLoop"
288: 00007ff8`14438e70 @!"SHELL32!SHOpenOrGetWebBrowserApp"
289: 00007ff8`14503c2c @!"SHELL32!SHCompressFile"
290: 00007ff8`142ad130 @!"SHELL32!SHDuplicateHandle"
291: 00007ff8`1443767c @!"SHELL32!SHLimitInputEditChars"
292: 00007ff8`1442b520 @!"SHELL32!SHELL32_ShowHideIconOnlyOnDesktop"
293: 00007ff8`1442b420 @!"SHELL32!SHELL32_SHCreateByValueOperationInterrupt"
294: 00007ff8`1469309c @!"SHELL32!SHCreateUserPictureFromPictureBytes"
295: 00007ff8`146ddf60 @!"SHELL32!SHRegSubKeyExistsW"
296: 00007ff8`146a6a34 @!"SHELL32!SHPropertyBag_ReadStreamScreenResForDpi"
297: 00007ff8`146a85c4 @!"SHELL32!SHFormatMessageArgAlloc"
298: 00007ff8`146aa564 @!"SHELL32!ShStrA::SetSize"
299: 00007ff8`1442b2c0 @!"SHELL32!SHELL32_GetDiskCleanupPath"
300: 00007ff8`1442b2d0 @!"SHELL32!SHELL32_GetFileNameFromBrowse"
301: 00007ff8`1425f950 @!"SHELL32!SHExtCoCreateInstance"
302: 00007ff8`146702e4 @!"SHELL32!ShowShellInfrastuctureCriticalFailureDialogWorker"
303: 00007ff8`14280b90 @!"SHELL32!ShellItemLink::GetClassInfoW"
304: 00007ff8`14427410 @!"SHELL32!SHCreateShellFolderViewEx"
305: 00007ff8`143e967c @!"SHELL32!SHGetItemArrayOfSelection"
306: 00007ff8`1442b3d0 @!"SHELL32!SHELL32_Printjob_GetPidl"
307: 00007ff8`14341f60 @!"SHELL32!SHCreateDefClassObject"
308: 00007ff8`1426dab0 @!"SHELL32!SHELL32_IconCache_DoneExtractingIcons"
309: 00007ff8`1442b4d0 @!"SHELL32!SHELL32_SHStartNetConnectionDialogW"
310: 00007ff8`1429d6d0 @!"SHELL32!SHCreateSetStgEnum"
311: 00007ff8`1442b470 @!"SHELL32!SHELL32_SHFormatDriveAsync"
312: 00007ff8`141fd4ac @!"SHELL32!SHSimpleIDListFromFindDataAndFlags"
313: 00007ff8`1425dc40 @!"SHELL32!SHGetKnownFolderPathStub"
314: 00007ff8`1434e4a8 @!"SHELL32!SHGetComparisonInfo"
315: 00007ff8`143da638 @!"SHELL32!SHLogicalToPhysicalDPI"
316: 00007ff8`141b6150 @!"SHELL32!SHSimpleItemFromAttributes"
breakpoint 121 redefined
121: 00007ff8`142b1570 @!"SHELL32!SHELL32_PifMgr_SetProperties"
317: 00007ff8`142301a0 @!"SHELL32!SHGetPropertyStoreForWindow"
breakpoint 121 redefined
121: 00007ff8`142b1570 @!"SHELL32!SHELL32_CopySecondaryTiles"
318: 00007ff8`1428fce0 @!"SHELL32!SHELL32_IsSystemUpgradeInProgress"
319: 00007ff8`14478e28 @!"SHELL32!SHGetPropertyStoreFromPropertyParsingName"
320: 00007ff8`1442b130 @!"SHELL32!SHELL32_CreateConfirmationInterrupt"
321: 00007ff8`1434654c @!"SHELL32!SheGetPathOffsetW"
322: 00007ff8`1442b3c0 @!"SHELL32!SHELL32_Printers_CreateBindInfo"
323: 00007ff8`1434ad84 @!"SHELL32!SHRegDuplicateKey"
324: 00007ff8`1442b2e0 @!"SHELL32!SHELL32_GetLinkInfoData"
325: 00007ff8`143bf360 @!"SHELL32!Shell32LoggingTelemetry::StorageToastClicks<unsigned long,long,unsigned long & __ptr64>"
326: 00007ff8`1434e260 @!"SHELL32!SHCombineMultipleConditionsEx"
327: 00007ff8`14650760 @!"SHELL32!ShellMRTHelper::Common::ScaleFactorToResourceScale"
328: 00007ff8`142b13e0 @!"SHELL32!SHAddToRecentDocs"
329: 00007ff8`146dddec @!"SHELL32!SHEnumStringValueW"
330: 00007ff8`1423f050 @!"SHELL32!SHEvaluateSystemCommandTemplate"
331: 00007ff8`144381c4 @!"SHELL32!SHLaunchPropSheet"
332: 00007ff8`146e9504 @!"SHELL32!SHFindConnectedUserBySid"
333: 00007ff8`14426c30 @!"SHELL32!SHCreateRelatedItem"
334: 00007ff8`1425fa40 @!"SHELL32!SHCreateDirectoryExWStub"
335: 00007ff8`143deee0 @!"SHELL32!ShutdownThreadProc"
336: 00007ff8`143ff558 @!"SHELL32!SHHasTimeoutElapsed"
337: 00007ff8`14396b70 @!"SHELL32!SHHelpShortcuts_RunDLL"
338: 00007ff8`1442ac40 @!"SHELL32!SHELL32_BindToFilePlaceholderHandler"
339: 00007ff8`1422f420 @!"SHELL32!SHSetTemporaryPropertyForItem"
340: 00007ff8`1464eea4 @!"SHELL32!ShellMRTHelper::MRTHelperBase::InitializeMRTObjects"
341: 00007ff8`14396c20 @!"SHELL32!SHHelpShortcuts_RunDLLW"
342: 00007ff8`1464edb4 @!"SHELL32!ShellMRTHelper::Common::HasMsAppDataUriScheme"
343: 00007ff8`14260c20 @!"SHELL32!ShouldNavPaneExpandToCurrentFolder"
344: 00007ff8`1434e6c4 @!"SHELL32!SHResolveConditionEx"
345: 00007ff8`1442ca84 @!"SHELL32!SHReadImplementingClassesOfCategory"
346: 00007ff8`146969e4 @!"SHELL32!ShStrW::Trim"
347: 00007ff8`14418350 @!"SHELL32!SHCreateDrvExtIcon"
348: 00007ff8`1464ee2c @!"SHELL32!ShellMRTHelper::Common::HasMsAppXUriScheme"
349: 00007ff8`142b12d0 @!"SHELL32!SHELL32_SHGetUserNameW"
350: 00007ff8`1442b010 @!"SHELL32!SHELL32_CNetFolderUI_CreateInstance"
351: 00007ff8`14371350 @!"SHELL32!ShellInfraCriticalFailureProvider::`scalar deleting destructor'"
352: 00007ff8`1436fd20 @!"SHELL32!SHCreateProcessAsUserW"
353: 00007ff8`144c0b08 @!"SHELL32!ShouldShowItemBasedOnCapabilities"
354: 00007ff8`143a0860 @!"SHELL32!SHSimulateDropWithSite"
355: 00007ff8`14438d40 @!"SHELL32!SHOpenFolderAndSelectItems"
356: 00007ff8`1442cac8 @!"SHELL32!SHReadRequiringClassesOfCategory"
357: 00007ff8`14409db0 @!"SHELL32!SHCreateDefaultPropertiesOp"
358: 00007ff8`143f75c0 @!"SHELL32!SHAddSparseIcon"
359: 00007ff8`146e7d90 @!"SHELL32!ShellExecuteRegApp"
360: 00007ff8`14358110 @!"SHELL32!SHExtCoCreateLocalServerFromRegKey"
361: 00007ff8`143a91c0 @!"SHELL32!SHSimulateDropOnClsid"
362: 00007ff8`141d7df0 @!"SHELL32!SHGetAssocKeys"
363: 00007ff8`1426969c @!"SHELL32!SHGetUserSid"
364: 00007ff8`142acdb0 @!"SHELL32!SHCreatePropSheetExtArray"
365: 00007ff8`1421fe40 @!"SHELL32!SHIconIndexFromPIDL"
366: 00007ff8`1469d7d0 @!"SHELL32!SHChangeMenuWasSentByMe"
367: 00007ff8`14351300 @!"SHELL32!SHGetPathFromMsUri"
368: 00007ff8`143f2e0c @!"SHELL32!ShellExecCmdLineWithSite"
369: 00007ff8`143a96fc @!"SHELL32!ShowElevationPromptSuppressedError"
370: 00007ff8`1442b2a0 @!"SHELL32!SHELL32_GetCommandProviderForFolderType"
371: 00007ff8`143a7e0c @!"SHELL32!SHCreateDataObjectFromShellItemsOrFolder"
372: 00007ff8`143a8b10 @!"SHELL32!SHIsFileAvailableOffline"
373: 00007ff8`145f1590 @!"SHELL32!ShellItemLink::SetTarget"
374: 00007ff8`1442aee0 @!"SHELL32!SHELL32_CDefFolderMenu_MergeMenu"
375: 00007ff8`146dd514 @!"SHELL32!SHParseUserName"
376: 00007ff8`1440eba4 @!"SHELL32!SHAssocEnumHandlersForProtocolByApplicationInternal"
377: 00007ff8`1442b070 @!"SHELL32!SHELL32_CallFileCopyHooks"
378: 00007ff8`14435830 @!"SHELL32!SHGetDriveMedia"
379: 00007ff8`143bc080 @!"SHELL32!SHPropertiesForUnk"
380: 00007ff8`1440ed00 @!"SHELL32!SHCreateAssocHandler"
381: 00007ff8`1437d4e8 @!"SHELL32!SHRegSetBOOL"
382: 00007ff8`143b9800 @!"SHELL32!SHCreateLinksEx"
383: 00007ff8`14439e40 @!"SHELL32!SHQueryRecycleBinA"
384: 00007ff8`1442ad80 @!"SHELL32!SHELL32_CDBurn_IsLiveFS"
385: 00007ff8`1442ae10 @!"SHELL32!SHELL32_CDBurn_OnMediaChange"
386: 00007ff8`1469fa38 @!"SHELL32!SHIsTimewarpEnabledForPath"
387: 00007ff8`143b998c @!"SHELL32!SHGetCompressedFileSizeW"
388: 00007ff8`143d9960 @!"SHELL32!SHELL32_Create_IEnumUICommand"
389: 00007ff8`14342d88 @!"SHELL32!SHGetPrivateProfileStringEx"
390: 00007ff8`1442b020 @!"SHELL32!SHELL32_CPL_IsLegacyCanonicalNameListedUnderKey"
391: 00007ff8`1442ae80 @!"SHELL32!SHELL32_CDefFolderMenu_Create2Ex"
392: 00007ff8`14687784 @!"SHELL32!ShowUnindexableLocationDialog"
393: 00007ff8`1442b4a0 @!"SHELL32!SHELL32_SHLaunchPropSheet"
394: 00007ff8`1425db00 @!"SHELL32!SHGetKnownFolderItemStub"
395: 00007ff8`1425d8a0 @!"SHELL32!SHGetSpecialFolderLocationStub"
396: 00007ff8`142724b4 @!"SHELL32!SHLogicalToPhysicalDPIForImages"
397: 00007ff8`14341bac @!"SHELL32!SHCreateStdEnumFmtEtcEx"
398: 00007ff8`1442b360 @!"SHELL32!SHELL32_HandleUnrecognizedFileSystem"
399: 00007ff8`1442abb0 @!"SHELL32!SHCreateTransferFallback"
400: 00007ff8`141df90c @!"SHELL32!SHProcessMessagesUpdateTimeout"
401: 00007ff8`1434e400 @!"SHELL32!SHCreateLeafConditionEx"
402: 00007ff8`1442ae20 @!"SHELL32!SHELL32_CDefFolderMenu_Create2"
403: 00007ff8`1442ac50 @!"SHELL32!SHELL32_CCommonPlacesFolder_CreateInstance"
404: 00007ff8`143f2c40 @!"SHELL32!SHValidateUNC"
405: 00007ff8`1454e9a8 @!"SHELL32!ShouldUpdateEstimates"
406: 00007ff8`14435d00 @!"SHELL32!SHGetIconOverlayIndexW"
407: 00007ff8`143bf1a8 @!"SHELL32!Shell32LoggingTelemetry::StorageToastClicks<unsigned long,int,unsigned long & __ptr64>"
408: 00007ff8`1442b300 @!"SHELL32!SHELL32_GetRatingBucket"
409: 00007ff8`1437cbc0 @!"SHELL32!SHCreateIDListWithFilters"
410: 00007ff8`1420a1c0 @!"SHELL32!SHBindToObject"
411: 00007ff8`1469f13c @!"SHELL32!SHInitLUAVirtualizationFromActCtx"
412: 00007ff8`143a8150 @!"SHELL32!SHEnumerateUnreadMailAccountsW"
413: 00007ff8`143e3b20 @!"SHELL32!SHSetKnownFolderPathStub"
414: 00007ff8`143c0a9c @!"SHELL32!Shell32LoggingTelemetry::LowDisk::Stop"
415: 00007ff8`1443aab0 @!"SHELL32!SHStartNetConnectionDialogA"
416: 00007ff8`143581f8 @!"SHELL32!ShowSetDefaultMessage"
417: 00007ff8`1424be40 @!"SHELL32!SHELL32_CDBurn_GetStagingPathOrNormalPath"
418: 00007ff8`14399f4c @!"SHELL32!ShouldSuppressGrouping"
419: 00007ff8`1442b1d0 @!"SHELL32!SHELL32_CreateFileFolderContextMenu"
420: 00007ff8`1451f4d8 @!"SHELL32!SHCreateItemStore"
breakpoint 309 redefined
309: 00007ff8`1442b4d0 @!"SHELL32!SHStartNetConnectionDialogW"
421: 00007ff8`143a892c @!"SHELL32!SHIsCurrentThreadOnUserDesktop"
422: 00007ff8`14438124 @!"SHELL32!SHFormatDriveAsync"
423: 00007ff8`146a34ec @!"SHELL32!SHNavigateToFavorite"
424: 00007ff8`14346124 @!"SHELL32!SheChangeDirW"
425: 00007ff8`141e8770 @!"SHELL32!SHGetNameFromIDList"
426: 00007ff8`1434e380 @!"SHELL32!SHCreateAndOrConditionEx"
427: 00007ff8`1442b4b0 @!"SHELL32!SHELL32_SHLogILFromFSIL"
428: 00007ff8`14345d10 @!"SHELL32!SheChangeDirA"
429: 00007ff8`145f1220 @!"SHELL32!ShellItemLink::Register"
430: 00007ff8`1429d4d8 @!"SHELL32!SHCreateEnumPropStg"
431: 00007ff8`14259f00 @!"SHELL32!SHAlloc"
432: 00007ff8`1442b410 @!"SHELL32!SHELL32_SHAddSparseIcon"
433: 00007ff8`1442b4f0 @!"SHELL32!SHELL32_SetPlaceholderReparsePointAttribute"
434: 00007ff8`1442b150 @!"SHELL32!SHELL32_CreateDefaultOperationDataProvider"
435: 00007ff8`1438ec80 @!"SHELL32!SHCreateNotConditionEx"
436: 00007ff8`1442b250 @!"SHELL32!SHELL32_FilePlaceholder_CreateInstance"
437: 00007ff8`145f017c @!"SHELL32!ShellItemLink::GetShellExec"
438: 00007ff8`145f1e90 @!"SHELL32!ShellItemLinkFitter::_SelfLayoutDoLayout"
breakpoint 351 redefined
351: 00007ff8`14371350 @!"SHELL32!ShellInfraCriticalFailureProvider::`vector deleting destructor'"
439: 00007ff8`1442b5e0 @!"SHELL32!SHELL32_UpdateFilePlaceholderStates"
440: 00007ff8`1425ea30 @!"SHELL32!SHShouldShowWizards"
441: 00007ff8`14438230 @!"SHELL32!SHMultiFileProperties"
442: 00007ff8`1442b060 @!"SHELL32!SHELL32_CTransferConfirmation_CreateInstance"
443: 00007ff8`146701dc @!"SHELL32!ShowShellInfrastuctureCriticalFailureDialog"
444: 00007ff8`145422d0 @!"SHELL32!SHTrackContextMenu"
445: 00007ff8`14346390 @!"SHELL32!SheGetDirA"
446: 00007ff8`1426d850 @!"SHELL32!SHELL32_LookupFrontIconIndex"
447: 00007ff8`143e3680 @!"SHELL32!SHAppBarMessage"
448: 00007ff8`143befa4 @!"SHELL32!Shell32LoggingTelemetry::SetStoragePolicy<unsigned long & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64,unsigned long & __ptr64,long & __ptr64,unsigned char,unsigned char,unsigned char & __ptr64>"
449: 00007ff8`144099a0 @!"SHELL32!SHChangeNotifySuspendResume"
450: 00007ff8`141dfaf8 @!"SHELL32!SHCreateSharedMutex"
451: 00007ff8`143a4428 @!"SHELL32!Shell32Instance::get"
452: 00007ff8`143b0380 @!"SHELL32!SHFormatDrive"
453: 00007ff8`1442b140 @!"SHELL32!SHELL32_CreateConflictInterrupt"
454: 00007ff8`14641c70 @!"SHELL32!SHELL32_SendToMenu_VerifyTargetedCommand"
455: 00007ff8`1469d9d0 @!"SHELL32!SHStrDupAsCP"
456: 00007ff8`1469d8a4 @!"SHELL32!SHIsButtonObscured"
457: 00007ff8`1438fa30 @!"SHELL32!SHExtCoCreateFromRegKey"
458: 00007ff8`14259e00 @!"SHELL32!SHELL32_GetIconOverlayManager"
459: 00007ff8`1442b100 @!"SHELL32!SHELL32_CommandLineFromMsiDescriptor"
460: 00007ff8`14396dd0 @!"SHELL32!SHObjectProperties"
461: 00007ff8`1422f4e0 @!"SHELL32!SHGetTemporaryPropertyForItem"
462: 00007ff8`1443a890 @!"SHELL32!SHQueryShellFolderValue"
463: 00007ff8`14546660 @!"SHELL32!SHRemoveSkipBindCtx"
464: 00007ff8`142aa6f0 @!"SHELL32!SHGetMalloc"
465: 00007ff8`1442b240 @!"SHELL32!SHELL32_FilePlaceholder_BindToPrimaryStream"
466: 00007ff8`143a86a0 @!"SHELL32!SHGetRealIDL"
467: 00007ff8`143c1110 @!"SHELL32!Shell32LoggingTelemetry::LowDisk::StopActivity"
468: 00007ff8`142b84f3 @!"SHELL32!SHExpandEnvironmentStringsW"
469: 00007ff8`146a81a8 @!"SHELL32!SHAcctGetUserPicturePath"
470: 00007ff8`146a303c @!"SHELL32!SHGetDIBFromPictureData"
471: 00007ff8`1425e7e0 @!"SHELL32!SHGetKnownFolderIDListStub"
472: 00007ff8`1451bd40 @!"SHELL32!ShowMountErrorDialog"
473: 00007ff8`143a9180 @!"SHELL32!SHSimpleIDListFromPath"
474: 00007ff8`1442b290 @!"SHELL32!SHELL32_GetAppIDRoot"
475: 00007ff8`1442ada0 @!"SHELL32!SHELL32_CDBurn_OnEject"
476: 00007ff8`1442aff0 @!"SHELL32!SHELL32_CMountPoint_WantAutorunUI"
477: 00007ff8`141c7770 @!"SHELL32!SHFormatResMessageArgAlloc"
478: 00007ff8`143a96e0 @!"SHELL32!ShortSizeFormatExportW"
479: 00007ff8`1469c84c @!"SHELL32!SHProcessMessagesUntilTimeout"
480: 00007ff8`143c0df8 @!"SHELL32!Shell32LoggingTelemetry::WinOldLowStorageCleanup::Stop"
481: 00007ff8`1427a3d0 @!"SHELL32!SHEnableServiceObject"
482: 00007ff8`146a36f4 @!"SHELL32!SHGetPrivateProfileInt"
483: 00007ff8`1442afe0 @!"SHELL32!SHELL32_CMountPoint_ProcessAutoRunFile"
484: 00007ff8`143bf0d0 @!"SHELL32!Shell32LoggingTelemetry::StorageToastClicks<unsigned long,long & __ptr64,int>"
breakpoint 121 redefined
121: 00007ff8`142b1570 @!"SHELL32!SHELL32_PifMgr_OpenProperties"
485: 00007ff8`14692030 @!"SHELL32!SHIsAccountGuest"
486: 00007ff8`146a6850 @!"SHELL32!SHGetPerScreenResNameForDpi"
487: 00007ff8`143fe990 @!"SHELL32!SHNetConnectionDialog"
488: 00007ff8`1427eb80 @!"SHELL32!SHStgOpenStorageW"
489: 00007ff8`14437890 @!"SHELL32!SHLimitInputEndSubclass"
490: 00007ff8`142552f0 @!"SHELL32!SHCreateIconImageList"
breakpoint 488 redefined
488: 00007ff8`1427eb80 @!"SHELL32!SHStgOpenStorageA"
491: 00007ff8`144a75f0 @!"SHELL32!SHTraceSQMStreamFour"
492: 00007ff8`141edc1c @!"SHELL32!SHPrettyMenuForDefcm"
493: 00007ff8`1469c4f8 @!"SHELL32!SHInvokeCommandOnBackgroundThread"
494: 00007ff8`1442b390 @!"SHELL32!SHELL32_LegacyEnumTasks"
495: 00007ff8`144307f0 @!"SHELL32!SHGetUserPicturePath"
496: 00007ff8`146a28cc @!"SHELL32!SHPlaySound"
497: 00007ff8`142478f4 @!"SHELL32!SHRegGetStringEx"
498: 00007ff8`1456ef58 @!"SHELL32!ShellPlaceholderLinkVerb::`scalar deleting destructor'"
499: 00007ff8`14662994 @!"SHELL32!SHPropertyBag_ReadIcon"
500: 00007ff8`1450a0e8 @!"SHELL32!SHGetFilterNameForIDList"
501: 00007ff8`141c1ef0 @!"SHELL32!SHCreateDataObject"
502: 00007ff8`14409ef0 @!"SHELL32!SHSetDefaultProperties"
503: 00007ff8`1428c540 @!"SHELL32!SHCreateDefaultExtractIcon"
504: 00007ff8`1442ad90 @!"SHELL32!SHELL32_CDBurn_OnDeviceChange"
505: 00007ff8`141c9ec8 @!"SHELL32!SHFusionCreateWindow"
506: 00007ff8`1469f414 @!"SHELL32!SHGetVirtualizedFolderPath"
507: 00007ff8`14397c38 @!"SHELL32!SHCoDupArray<_tagpropertykey>"
508: 00007ff8`14351340 @!"SHELL32!SHPathPrepareForWriteW"
509: 00007ff8`1427ca50 @!"SHELL32!SHELL32_CFSFolderCallback_Create"
510: 00007ff8`143a97d0 @!"SHELL32!ShowSuperHidden"
511: 00007ff8`1420a8b0 @!"SHELL32!SHCreateItemWithParent"
512: 00007ff8`1424ea50 @!"SHELL32!SHELL32_CFSDropTarget_CreateInstance"
513: 00007ff8`143f2de0 @!"SHELL32!ShellExecCmdLine"
514: 00007ff8`143f0d00 @!"SHELL32!Shell_GetCachedImageIndexA"
515: 00007ff8`145f20e0 @!"SHELL32!ShellItemLinkFitter::_SelfLayoutUpdateDesiredSize"
516: 00007ff8`143512a0 @!"SHELL32!SHFileOperationA"
517: 00007ff8`14342c70 @!"SHELL32!SHExtractIconsW"
518: 00007ff8`14342cbc @!"SHELL32!SHGetCachedPrivateProfile"
519: 00007ff8`143a8dd0 @!"SHELL32!SHLoadNonloadedIconOverlayIdentifiers"
520: 00007ff8`143fdfb0 @!"SHELL32!SHQueryToken<_TOKEN_PRIVILEGES>"
521: 00007ff8`1464fd74 @!"SHELL32!ShellMRTHelper::MRTHelperBase::Resolve"
522: 00007ff8`143bf280 @!"SHELL32!Shell32LoggingTelemetry::StorageToastClicks<unsigned long,int,int>"
523: 00007ff8`1469d954 @!"SHELL32!SHSendChangeMenuNotify"
524: 00007ff8`146dfd2c @!"SHELL32!SHFusionCreateDialogParam"
525: 00007ff8`14438250 @!"SHELL32!SHOpenPropSheetW"
526: 00007ff8`1442e814 @!"SHELL32!SHIsCurrentAccountDomainUser"
527: 00007ff8`143a8df4 @!"SHELL32!SHRunDLLProcess"
528: 00007ff8`1420b7b0 @!"SHELL32!SHParseDisplayName"
529: 00007ff8`1436e780 @!"SHELL32!ShellExecuteProvider::ShellExecuteExW::StopActivity"
530: 00007ff8`14263c90 @!"SHELL32!SHCloseDesktopHandle"
531: 00007ff8`143e9560 @!"SHELL32!SHGetContextMenuOfSelection"
532: 00007ff8`144d9ee4 @!"SHELL32!SHGetPrivateProfileStringEx"
533: 00007ff8`145f26b8 @!"SHELL32!ShellItemLinkFitter::_UpdateShellLinksDesiredSize"
534: 00007ff8`141dad60 @!"SHELL32!SHELL32_SHCreateShellFolderView"
535: 00007ff8`142d1a80 @!"SHELL32!ShellPlaceholderLinkVerb::`vector deleting destructor'"
536: 00007ff8`143b96a0 @!"SHELL32!SHCreateItemFromRelativeName"
537: 00007ff8`142ad1b0 @!"SHELL32!ShellExecuteW"
538: 00007ff8`143e3b00 @!"SHELL32!SHSetFolderPathWStub"
539: 00007ff8`14437810 @!"SHELL32!SHLimitInputEditWithFlags"
540: 00007ff8`143f13b0 @!"SHELL32!SHWNetGetConnection"
541: 00007ff8`1436ff50 @!"SHELL32!ShellExecuteA"
542: 00007ff8`14346658 @!"SHELL32!SheSetEnvVarW"
543: 00007ff8`146a7ffc @!"SHELL32!SHAcctAccountName2DataFileName"
544: 00007ff8`1422b650 @!"SHELL32!SHELL32_IconOverlayManagerInit"
545: 00007ff8`144274b0 @!"SHELL32!SHShellFolderView_Message"
546: 00007ff8`141ce2c0 @!"SHELL32!SHGetFolderPathExStub"
547: 00007ff8`1442b200 @!"SHELL32!SHELL32_EncryptDirectory"
548: 00007ff8`143e39d0 @!"SHELL32!SHPropStgReadMultipleStub"
549: 00007ff8`1440ed50 @!"SHELL32!SHGetNoAssocIconIndex"
550: 00007ff8`143ba060 @!"SHELL32!SHRemoveLocalizedName"
551: 00007ff8`143e3930 @!"SHELL32!SHGetFolderPathAndSubDirWStub"
552: 00007ff8`14344210 @!"SHELL32!SHDuplicateHandle"
553: 00007ff8`14436520 @!"SHELL32!SHGetSettings"
554: 00007ff8`141edb5c @!"SHELL32!SHLoadPopupMenu"
555: 00007ff8`1440a190 @!"SHELL32!SHReplaceFromPropSheetExtArray"
556: 00007ff8`143e3910 @!"SHELL32!SHGetFolderPathAndSubDirAStub"
557: 00007ff8`14345d00 @!"SHELL32!SHELL32_PifMgr_CloseProperties"
558: 00007ff8`141df350 @!"SHELL32!SHLocalStrDupW"
559: 00007ff8`143f0cf0 @!"SHELL32!Shell_GetCachedImageIndex"
560: 00007ff8`145ef8f0 @!"SHELL32!ShellItemLink::`vector deleting destructor'"
561: 00007ff8`1437cda8 @!"SHELL32!SHDisplayNameFromScopeAndSubQueries"
562: 00007ff8`1425dce0 @!"SHELL32!SHELL32_IconCache_RememberRecentlyExtractedIconsW"
563: 00007ff8`1443ab50 @!"SHELL32!SHStartNetDisconnectionDialog"
564: 00007ff8`146a665c @!"SHELL32!SHILTranslateGlobalEvent"
565: 00007ff8`1440f55c @!"SHELL32!SHBrowseForFolder2"
566: 00007ff8`142288c0 @!"SHELL32!SHMapWindowRects"
567: 00007ff8`1425d770 @!"SHELL32!SHSetInstanceExplorerStub"
568: 00007ff8`14414304 @!"SHELL32!SHExtCoCreateLocalServerLowIL"
569: 00007ff8`1426d360 @!"SHELL32!SHMapPIDLToSystemImageListIndex"
570: 00007ff8`14285314 @!"SHELL32!SHExtTextOutW"
571: 00007ff8`141ba6f0 @!"SHELL32!ShellConstructMessageStringW"
572: 00007ff8`144c0820 @!"SHELL32!SHGetOriginalItemFromBindCtx"
573: 00007ff8`1424d110 @!"SHELL32!SHCoCreateInstanceStub"
574: 00007ff8`141e3c10 @!"SHELL32!SHRegGetUSDWORDW"
575: 00007ff8`1442af70 @!"SHELL32!SHELL32_CLibraryDropTarget_CreateInstance"
576: 00007ff8`1464c578 @!"SHELL32!ShellMRTHelper::MRTHelperBase::~MRTHelperBase"
577: 00007ff8`1427364c @!"SHELL32!SHComputeDPI"
578: 00007ff8`143e3ac0 @!"SHELL32!SHResolveLibraryStub"
579: 00007ff8`1442ac60 @!"SHELL32!SHELL32_CDBurn_CloseSession"
580: 00007ff8`1437d3dc @!"SHELL32!SHMapCmdIDToHelpText"
581: 00007ff8`1442b230 @!"SHELL32!SHELL32_EnumCommonTasks"
582: 00007ff8`143f176c @!"SHELL32!ShowSecurityZoneDialog"
583: 00007ff8`1466e864 @!"SHELL32!ShellInfraCriticalFailureProvider::CriticalFailure<unsigned int & __ptr64,int>"
584: 00007ff8`143a7c58 @!"SHELL32!SHBindToObjectByName"
breakpoint 498 redefined
498: 00007ff8`1456ef58 @!"SHELL32!ShellPlaceholderLinkVerb::`vector deleting destructor'"
585: 00007ff8`143a7d74 @!"SHELL32!SHCLSIDFromStringEx"
586: 00007ff8`141db420 @!"SHELL32!SHGetItemFromObject"
587: 00007ff8`14351260 @!"SHELL32!SHConfirmOperation"
588: 00007ff8`144df098 @!"SHELL32!SHCreateSkipBindCtx"
589: 00007ff8`1440eb90 @!"SHELL32!SHAssocEnumHandlersForProtocolByApplication"
590: 00007ff8`1434e3f0 @!"SHELL32!SHCreateFilter"
591: 00007ff8`1442b120 @!"SHELL32!SHELL32_CopyFilePlaceholderToNewFile"
592: 00007ff8`1469956c @!"SHELL32!SHCoCreateCreateIDListChildBindCtx"
593: 00007ff8`1442b000 @!"SHELL32!SHELL32_CMountPoint_WantAutorunUIGetReady"
594: 00007ff8`1442b9e0 @!"SHELL32!SHEmptyRecycleBinA"
595: 00007ff8`143b855c @!"SHELL32!SHSetLocalizedNameOnItem"
596: 00007ff8`141cdeb8 @!"SHELL32!SHEnableMenuCheckMarkOrBmp"
597: 00007ff8`1434e3c0 @!"SHELL32!SHCreateConditionFactory"
598: 00007ff8`1435cb40 @!"SHELL32!SHAddSkipBindCtx"
599: 00007ff8`1454253c @!"SHELL32!ShowFolderMenu"
600: 00007ff8`14639770 @!"SHELL32!SHIsTempDisplayMode"
601: 00007ff8`1422c990 @!"SHELL32!SHELL32_IconCacheRestore"
602: 00007ff8`143b9cd0 @!"SHELL32!SHGetLocalizedNameAlloc"
603: 00007ff8`1426d3b0 @!"SHELL32!SHELL32_AddToFrontIconTable"
604: 00007ff8`1440bd00 @!"SHELL32!SHApplyPropertiesToItem"
605: 00007ff8`1464ed3c @!"SHELL32!ShellMRTHelper::Common::HasFileUriScheme"
606: 00007ff8`146a2e70 @!"SHELL32!SHConvertImageToUserTile"
607: 00007ff8`14351360 @!"SHELL32!SHValidateMSUri"
608: 00007ff8`1438f990 @!"SHELL32!SHCreateAndOrCondition"
609: 00007ff8`1442afa0 @!"SHELL32!SHELL32_CMountPoint_DoAutorunPrompt"
610: 00007ff8`1444a0a0 @!"SHELL32!ShellAboutA"
breakpoint 173 redefined
173: 00007ff8`142b52a0 @!"SHELL32!Shell32LoggingTelemetry::FormatDiscUdf::WasAlreadyReportedToTelemetry"
611: 00007ff8`144c0a7c @!"SHELL32!ShouldShowBasedOnCapabilities"
612: 00007ff8`1444a1d0 @!"SHELL32!ShellAboutW"
613: 00007ff8`144390c4 @!"SHELL32!SHOpenOrGetWebBrowserAppForItem"
614: 00007ff8`14430b30 @!"SHELL32!SHSetUserPicturePath"
615: 00007ff8`143f15b8 @!"SHELL32!ShowAdminInfoUrlIfConfigured"
616: 00007ff8`14260bc0 @!"SHELL32!ShouldNavPaneShowAllFolders"
617: 00007ff8`1442e7b8 @!"SHELL32!SHIsAccountDomainUser"
618: 00007ff8`1440d4dc @!"SHELL32!SHDeleteProtectedValue"
619: 00007ff8`1441371c @!"SHELL32!Shell32LoggingTelemetry::ShellExtensionList<unsigned short (& __ptr64)[39],unsigned short (& __ptr64)[39],unsigned long & __ptr64,unsigned short (& __ptr64)[260],bool>"
620: 00007ff8`146aa52c @!"SHELL32!ShStrA::Reset"
621: 00007ff8`142462d0 @!"SHELL32!SHChangeNotification_Lock"
622: 00007ff8`143f1664 @!"SHELL32!ShowDiagnosticsDlgForNetError"
623: 00007ff8`14344db0 @!"SHELL32!SHMoveFile"
624: 00007ff8`145b7024 @!"SHELL32!SHGetIDListChildFromBindCtx"
625: 00007ff8`143fe500 @!"SHELL32!SHCacheComputerDescription"
626: 00007ff8`14409c70 @!"SHELL32!SHAddDefaultProperties"
627: 00007ff8`1468767c @!"SHELL32!ShareUnshareLibraryLocations"
628: 00007ff8`142b1290 @!"SHELL32!SHCreateQueryCancelAutoPlayMoniker"
breakpoint 440 redefined
440: 00007ff8`1425ea30 @!"SHELL32!SHELL32_IsGetKeyboardLayoutPresent"
629: 00007ff8`1427e2b0 @!"SHELL32!SHELL32_CreateQosRecorder"
630: 00007ff8`14409b20 @!"SHELL32!SHUpdateImageA"
631: 00007ff8`1460e7e8 @!"SHELL32!SHGetPrivateProfileStringAlloc"
632: 00007ff8`146997d8 @!"SHELL32!SHSetPropertyFilter"
633: 00007ff8`143b9b80 @!"SHELL32!SHGetDiskFreeSpaceExA"
634: 00007ff8`143e3970 @!"SHELL32!SHIsLegacyAnsiPropertyStub"
635: 00007ff8`143e9b28 @!"SHELL32!SHIsVerbAvailableOnSelection"
636: 00007ff8`1427dcc0 @!"SHELL32!SHELL32_CFillPropertiesTask_CreateInstance"
637: 00007ff8`144d5d94 @!"SHELL32!ShowTempProfileWarningDialogAndWait"
638: 00007ff8`1442b440 @!"SHELL32!SHELL32_SHDuplicateEncryptionInfoFile"
639: 00007ff8`1425f170 @!"SHELL32!SHGetInstanceExplorerStub"
640: 00007ff8`1437ca18 @!"SHELL32!SHAppendFiltersToIDList"
641: 00007ff8`143b9c00 @!"SHELL32!SHGetDiskFreeSpaceExW"
642: 00007ff8`1422c980 @!"SHELL32!SHELL32_IconCacheCreate"
643: 00007ff8`1435cf38 @!"SHELL32!SHMapICIVerbToCmdID"
644: 00007ff8`14263f60 @!"SHELL32!SHChangeNotifyRegisterThread"
645: 00007ff8`143a8580 @!"SHELL32!SHGetPathFromIDListA"
646: 00007ff8`1469c2a0 @!"SHELL32!SHUnprepareMenuForDefcm"
647: 00007ff8`1425ab60 @!"SHELL32!SHELL32_IsValidLinkInfo"
648: 00007ff8`1425d230 @!"SHELL32!SHELL32_CreateLinkInfoW"
649: 00007ff8`14413550 @!"SHELL32!SHBrowseForFolderW"
650: 00007ff8`143a0588 @!"SHELL32!SHBreakText"
651: 00007ff8`144098b8 @!"SHELL32!SHChangeNotifyAutoplayDrive"
652: 00007ff8`1442d720 @!"SHELL32!SHFind_InitMenuPopup"
653: 00007ff8`1437caf0 @!"SHELL32!SHCombineMultipleConditions"
654: 00007ff8`1442b3b0 @!"SHELL32!SHELL32_NotifyLinkTrackingServiceOfMove"
655: 00007ff8`143a0608 @!"SHELL32!SHCoCreateInstanceAndLoadFromFile"
656: 00007ff8`1435ce80 @!"SHELL32!SHInvokeCommandOnPidl"
breakpoint 560 redefined
560: 00007ff8`145ef8f0 @!"SHELL32!ShellItemLink::`scalar deleting destructor'"
657: 00007ff8`1425e70c @!"SHELL32!SHInitializeInfotipControl"
658: 00007ff8`146a31f4 @!"SHELL32!SHGetUserPicture"
659: 00007ff8`141daf10 @!"SHELL32!SHCreateShellFolderView"
660: 00007ff8`142462b0 @!"SHELL32!SHGetFolderPathWStub"
661: 00007ff8`143bf8a0 @!"SHELL32!Shell32LoggingTelemetry::WinOldLowStorageCleanup::~WinOldLowStorageCleanup"
662: 00007ff8`144a20cc @!"SHELL32!SHCreateMemoryStream"
663: 00007ff8`1420be70 @!"SHELL32!SHBindToFolderIDListParent"
664: 00007ff8`1469c714 @!"SHELL32!SHInvokeCommandOnDataObject"
665: 00007ff8`1441440c @!"SHELL32!SHPinDllOfCLSIDStr"
666: 00007ff8`145b4c10 @!"SHELL32!Shell32LoggingTelemetry::FormatDiscUdf::StopActivity"
667: 00007ff8`145f7b24 @!"SHELL32!ShowIndividualConflictsDialog"
668: 00007ff8`142427f8 @!"SHELL32!SHILCloneFirst"
669: 00007ff8`1434e570 @!"SHELL32!SHLoadFilterFromStream"
670: 00007ff8`143fe7f0 @!"SHELL32!SHGetNetResource"
671: 00007ff8`14418050 @!"SHELL32!SHCreateDelegatingTransfer"
672: 00007ff8`14437550 @!"SHELL32!SHLimitInputCombo"
673: 00007ff8`14202cd4 @!"SHELL32!SHRegOpenKeyMergeWow64"
674: 00007ff8`1456f0ac @!"SHELL32!ShellPlaceholderLinkVerb::AttemptExecuteOnItem"
675: 00007ff8`144063ec @!"SHELL32!ShellComponentSetup"
676: 00007ff8`141f24fc @!"SHELL32!SHGetUIObjectOf"
677: 00007ff8`1442ac70 @!"SHELL32!SHELL32_CDBurn_DriveSupportedForDataBurn"
678: 00007ff8`143a8248 @!"SHELL32!SHFileOperationEx"
679: 00007ff8`143e39b0 @!"SHELL32!SHPropStgCreateStub"
680: 00007ff8`1437d548 @!"SHELL32!SHSetFilterToIDList"
681: 00007ff8`14220330 @!"SHELL32!SHFullIDListFromFolderAndRelativeItem"
682: 00007ff8`143b9590 @!"SHELL32!SHCreateFileExtractIconW"
683: 00007ff8`146c87f4 @!"SHELL32!SHOutlineRect"
684: 00007ff8`146e80e0 @!"SHELL32!ShellExecuteRunApp"
685: 00007ff8`1442ace0 @!"SHELL32!SHELL32_CDBurn_GetCDInfo"
686: 00007ff8`1420b9e0 @!"SHELL32!SHRestricted"
687: 00007ff8`1442ba70 @!"SHELL32!SHEmptyRecycleBinW"
688: 00007ff8`1469d058 @!"SHELL32!SHFixAmpersands"
689: 00007ff8`141d7d70 @!"SHELL32!SHGetAssocKeysForIDList"
690: 00007ff8`1442ddb0 @!"SHELL32!SHFlushSFCache"
691: 00007ff8`143fea84 @!"SHELL32!SHWNetGetResourceInformationAlloc"
692: 00007ff8`1428e890 @!"SHELL32!SHILCloneParent"
693: 00007ff8`143cbd08 @!"SHELL32!SHResolveCondition"
694: 00007ff8`143fe150 @!"SHELL32!SHTestTokenPrivilegeW"
695: 00007ff8`143b8528 @!"SHELL32!SHGetCurrentDirectory"
696: 00007ff8`143e9a70 @!"SHELL32!SHInvokeCommandOnSelection"
697: 00007ff8`143465e0 @!"SHELL32!SheSetCurDrive"
698: 00007ff8`14481ba0 @!"SHELL32!ShellItemLinkFitter::`scalar deleting destructor'"
699: 00007ff8`1435d0e4 @!"SHELL32!SHTraceSQMStream"
700: 00007ff8`1442b040 @!"SHELL32!SHELL32_CPL_ModifyWowDisplayName"
701: 00007ff8`143433f8 @!"SHELL32!SHGetSetIconFileIndex"
702: 00007ff8`143e3b60 @!"SHELL32!Shell_NotifyIconA"
703: 00007ff8`144da248 @!"SHELL32!ShellExecCommandFile"
704: 00007ff8`1442b210 @!"SHELL32!SHELL32_EncryptedFileKeyInfo"
705: 00007ff8`143a84b0 @!"SHELL32!SHFindFiles"
breakpoint 157 redefined
157: 00007ff8`1427d500 @!"SHELL32!SHELL32_CLocationContextMenu_Create"
706: 00007ff8`1422d268 @!"SHELL32!SHCreateGangedSysImageList"
707: 00007ff8`14430620 @!"SHELL32!SHGetDefaultUserPicture"
708: 00007ff8`146a8218 @!"SHELL32!SHGetPictureFromDataFileForUser"
709: 00007ff8`1424dc88 @!"SHELL32!Shell32LoggingTelemetry::ShellExtensionList_"
710: 00007ff8`145f0600 @!"SHELL32!ShellItemLink::OnEvent"
711: 00007ff8`143f2ba0 @!"SHELL32!SHExecuteErrorMessageBox"
712: 00007ff8`146934f4 @!"SHELL32!SHGetUserPictureBytes"
713: 00007ff8`14342f30 @!"SHELL32!SHGetSetFlags"
714: 00007ff8`14343020 @!"SHELL32!SHGetSetFolderCustomSettings"
715: 00007ff8`14651698 @!"SHELL32!ShellMRTHelper::Common::TryFallbackToFilePath"
716: 00007ff8`14409b90 @!"SHELL32!SHUpdateImageW"
717: 00007ff8`1422e2d4 @!"SHELL32!SHFusionLoadLibrary"
718: 00007ff8`143de7c0 @!"SHELL32!SHDoDragDrop"
719: 00007ff8`143e3950 @!"SHELL32!SHGetSpecialFolderPathAStub"
720: 00007ff8`14392f08 @!"SHELL32!SHCreateSingleKindList"
721: 00007ff8`1438f800 @!"SHELL32!SHCombineMultipleFilterConditions"
722: 00007ff8`14346514 @!"SHELL32!SheGetEnvVarW"
723: 00007ff8`1449d14c @!"SHELL32!SHGetPostEnumOpFromBindCtx"
724: 00007ff8`1440a110 @!"SHELL32!SHAddFromPropSheetExtArray"
725: 00007ff8`14205240 @!"SHELL32!SHGetPathFromIDListW"
726: 00007ff8`143a8cd0 @!"SHELL32!SHLaunchSearch"
727: 00007ff8`1425d210 @!"SHELL32!SHELL32_DestroyLinkInfo"
728: 00007ff8`142b52f0 @!"SHELL32!SHCreateDirectoryStub"
729: 00007ff8`143a93b4 @!"SHELL32!SHTrackPopupMenu"
730: 00007ff8`1442b510 @!"SHELL32!SHELL32_SetPlaceholderReparsePointAttribute2"
731: 00007ff8`14392e10 @!"SHELL32!SHCreateLeafCondition"
732: 00007ff8`143fd378 @!"SHELL32!SHGetSize"
733: 00007ff8`14413320 @!"SHELL32!SHBrowseForFolderA"
734: 00007ff8`1451134c @!"SHELL32!SHIsThisComputerByNameOnly"
735: 00007ff8`143b6b0c @!"SHELL32!SHRegValueExists"
736: 00007ff8`141ef8b0 @!"SHELL32!SHCreateDefaultContextMenu"
737: 00007ff8`14651a00 @!"SHELL32!ShellMRTHelper::Common::TryGetStagedPackagePathByFullNameAlloc"
738: 00007ff8`1435d094 @!"SHELL32!SHTraceSQMCreateStringStreamEntry"
739: 00007ff8`144c0764 @!"SHELL32!SHCopyPropertyStore"
740: 00007ff8`143e38f0 @!"SHELL32!SHGetFolderPathAStub"
741: 00007ff8`1441a650 @!"SHELL32!SHCreateFileDataObject"
742: 00007ff8`14241a38 @!"SHELL32!SHGetUIObjectFromFullPIDL"
743: 00007ff8`14273584 @!"SHELL32!SHPhysicalToLogicalDPI"
744: 00007ff8`1442b370 @!"SHELL32!SHELL32_IconCacheHandleAssociationChanged"
745: 00007ff8`1435d5d0 @!"SHELL32!Shell32LoggingTelemetry::BurnDisc::StopActivity"
746: 00007ff8`14520a9c @!"SHELL32!SHGetRecycleBinFolderIDList"
747: 00007ff8`141e3c88 @!"SHELL32!SHRegGetDWORD"
748: 00007ff8`14433980 @!"SHELL32!SHOpenControlPanel"
749: 00007ff8`14696980 @!"SHELL32!ShStrW::Printf"
750: 00007ff8`1428d840 @!"SHELL32!SHELL32_CPL_CategoryIdArrayFromVariant"
751: 00007ff8`1449cfe0 @!"SHELL32!SHCreatePostEnumOpBindCtx"
752: 00007ff8`1426dbe0 @!"SHELL32!SHELL32_IconCache_AboutToExtractIcons"
753: 00007ff8`14250ae0 @!"SHELL32!SHELL32_SuspendUndo"
754: 00007ff8`1424bf20 @!"SHELL32!SHChangeNotification_Unlock"
755: 00007ff8`1442cb10 @!"SHELL32!SHWriteClassesOfCategories"
756: 00007ff8`14409960 @!"SHELL32!SHChangeNotifyDeregisterWindow"
breakpoint 173 redefined
173: 00007ff8`142b52a0 @!"SHELL32!Shell32LoggingTelemetry::WinOldLowStorageCleanup::WasAlreadyReportedToTelemetry"
757: 00007ff8`141b3090 @!"SHELL32!SHELL32_GetThumbnailAdornerFromFactory2"
758: 00007ff8`14280bb0 @!"SHELL32!ShellItemLink::ShellExecProp"
759: 00007ff8`145d7b10 @!"SHELL32!SHFlushPrivateProfile"
760: 00007ff8`141df6dc @!"SHELL32!SHProcessMessagesUntilEvent"
761: 00007ff8`1442b350 @!"SHELL32!SHELL32_GetThumbnailAdornerFromFactory"
breakpoint 173 redefined
173: 00007ff8`142b52a0 @!"SHELL32!Shell32LoggingTelemetry::FormatDialog::WasAlreadyReportedToTelemetry"
762: 00007ff8`1423c040 @!"SHELL32!SHELL32_IconCacheDestroy"
763: 00007ff8`14344a44 @!"SHELL32!SHDeleteFile"
764: 00007ff8`14438a84 @!"SHELL32!SHOpenOrGetFolderView"
765: 00007ff8`143eff40 @!"SHELL32!SHELL32_SHUICommandFromGUID"
766: 00007ff8`14252af8 @!"SHELL32!SHSysAllocString"
767: 00007ff8`144d9f84 @!"SHELL32!SHMapUrlToZone"
768: 00007ff8`143a7ce8 @!"SHELL32!SHBindToObjectWithMode"
769: 00007ff8`1437d2a8 @!"SHELL32!SHIsSafeToDrop"
770: 00007ff8`1435cfa8 @!"SHELL32!SHTraceSQMCount"
771: 00007ff8`143e0bf8 @!"SHELL32!SHWritePrivateProfileString"
772: 00007ff8`141d2d10 @!"SHELL32!SHGetFolderLocationStub"
773: 00007ff8`1422b5f0 @!"SHELL32!SHELL32_RefreshOverlayImages"
774: 00007ff8`141d1850 @!"SHELL32!SHCreateShellItemArrayFromShellItem"
775: 00007ff8`1442c9b0 @!"SHELL32!SHEnumClassesOfCategories"
776: 00007ff8`14351320 @!"SHELL32!SHPathPrepareForWriteA"
777: 00007ff8`146dd468 @!"SHELL32!SHGetUserSidStringFallbackForImpersonation"
778: 00007ff8`14604f10 @!"SHELL32!SHCopyStreamWithProgress2"
779: 00007ff8`14696af4 @!"SHELL32!ShStrW::_SetStr"
780: 00007ff8`143f3030 @!"SHELL32!ShellExecPidl"
781: 00007ff8`1439b4e0 @!"SHELL32!SHGetTopViewDescription"
782: 00007ff8`141e7df4 @!"SHELL32!Shell32LoggingTelemetry::IsEnabled"
783: 00007ff8`144b7d74 @!"SHELL32!ShowRemovePropertiesDialogEx"
784: 00007ff8`143512c0 @!"SHELL32!SHFileOperationW"
785: 00007ff8`1442afd0 @!"SHELL32!SHELL32_CMountPoint_IsAutoRunDriveAndEnabledByPolicy"
breakpoint 698 redefined
698: 00007ff8`14481ba0 @!"SHELL32!ShellItemLinkFitter::`vector deleting destructor'"
786: 00007ff8`14354590 @!"SHELL32!SHRegSetString"
787: 00007ff8`143432c4 @!"SHELL32!SHGetSetFolderSettingPath"
788: 00007ff8`1442acf0 @!"SHELL32!SHELL32_CDBurn_GetLiveFSDiscInfo"
789: 00007ff8`143f6440 @!"SHELL32!SHGetFileNameFromBrowse"
790: 00007ff8`14692be0 @!"SHELL32!SHCopyUserTile"
791: 00007ff8`1425fce0 @!"SHELL32!SHGetDesktopFolderStub"
792: 00007ff8`143e26f0 @!"SHELL32!SHCreateNotCondition"
793: 00007ff8`1420e5e0 @!"SHELL32!SHELL32_LookupBackIconIndex"
794: 00007ff8`1425a080 @!"SHELL32!SHELL32_IconCache_ExpandEnvAndSearchPath"
795: 00007ff8`146a6978 @!"SHELL32!SHPropertyBag_ReadStreamScreenResWithVersionForDpi"
796: 00007ff8`146aa608 @!"SHELL32!ShStrA::_SetStr"
797: 00007ff8`146a5d18 @!"SHELL32!SHOLEMerge"
798: 00007ff8`1466fbdc @!"SHELL32!ShellInfraCriticalFailureProvider::OOBECriticalFailure"
799: 00007ff8`1435cde4 @!"SHELL32!SHFireHelpEntryDataPoint"
800: 00007ff8`141f07f0 @!"SHELL32!SHGetFileInfoWStub"
801: 00007ff8`14262f00 @!"SHELL32!SHCLSIDFromString"
802: 00007ff8`146968d8 @!"SHELL32!ShStrW::Append"
803: 00007ff8`143e94ac @!"SHELL32!SHCopyItemArrayConvertLinksToTargets"
804: 00007ff8`1442b530 @!"SHELL32!SHELL32_SimpleRatingToFilterCondition"
805: 00007ff8`14345d90 @!"SHELL32!SheChangeDirExW"
806: 00007ff8`141d1a70 @!"SHELL32!SHCreateShellItemArrayFromDataObject"
807: 00007ff8`1442b1e0 @!"SHELL32!SHELL32_CreatePlaceholderFile"
808: 00007ff8`141e40c8 @!"SHELL32!SHSetProtectedValue"
809: 00007ff8`14396c80 @!"SHELL32!SHHelpShortcuts_RunDLL_Common"
810: 00007ff8`1425f150 @!"SHELL32!SHCreateShellItemArrayFromIDLists"
811: 00007ff8`143e3ae0 @!"SHELL32!SHSetFolderPathAStub"
812: 00007ff8`1442b3e0 @!"SHELL32!SHELL32_PurgeSystemIcon"
813: 00007ff8`14397bcc @!"SHELL32!SHCoDupArray<SORTCOLUMN>"
814: 00007ff8`146a853c @!"SHELL32!SHFormatMessageArg"
815: 00007ff8`14260050 @!"SHELL32!SHELL32_SHCreateDefaultContextMenu"
816: 00007ff8`146dd8e4 @!"SHELL32!SHTranslateSIDToName"
breakpoint 121 redefined
121: 00007ff8`142b1570 @!"SHELL32!SHGetShellFolderViewCB"
817: 00007ff8`1420a110 @!"SHELL32!SHCreateItemFromIDList"
818: 00007ff8`143b9a70 @!"SHELL32!SHGetDataFromIDListA"
819: 00007ff8`14416080 @!"SHELL32!SHReplaceFilterInIDList"
820: 00007ff8`1434e630 @!"SHELL32!SHNextObjectFromEnumUnknown"
821: 00007ff8`1442af00 @!"SHELL32!SHELL32_CDrivesDropTarget_Create"
822: 00007ff8`1425e9a0 @!"SHELL32!SHGetSpecialFolderPathWStub"
823: 00007ff8`143c097c @!"SHELL32!Shell32LoggingTelemetry::WinOldLowStorageCleanup::StartActivity"
breakpoint 173 redefined
173: 00007ff8`142b52a0 @!"SHELL32!Shell32LoggingTelemetry::BurnDisc::WasAlreadyReportedToTelemetry"
824: 00007ff8`14693910 @!"SHELL32!SHSetUserPictureBytes"
825: 00007ff8`141d6d08 @!"SHELL32!SHRegGetStringValueMergeWow64"
826: 00007ff8`1428b750 @!"SHELL32!SHGetPathFromIDListEx"
827: 00007ff8`1470ede0 @!"SHELL32!SHGetInputLanguageTag"
828: 00007ff8`144d9e40 @!"SHELL32!SHGetPrivateProfileString"
breakpoint 173 redefined
173: 00007ff8`142b52a0 @!"SHELL32!ShellExecuteProvider::ShellExecuteExW::WasAlreadyReportedToTelemetry"
829: 00007ff8`1442af90 @!"SHELL32!SHELL32_CMountPoint_DoAutorun"
830: 00007ff8`143de980 @!"SHELL32!SHDoDragDropWithPreferredEffect"
831: 00007ff8`143b9fb0 @!"SHELL32!SHGetPropertyStoreFromParsingName"
832: 00007ff8`1425f620 @!"SHELL32!SHCloneSpecialIDList"
```

At first I thought wow, holy shit thats awesome! SO many functions to attack!! Then I realized it's probably just the fact that the dll is imported along with all of its functions and methods. It does't mean they're all used, but hey wtf, we put breakpoints on all of them anyway. Opening up explorer.exe like so `explorer.exe C:\windows\` opens up a file explorer window to that folder. After setting those breakpoints and making it `g` I get stopped at an interesting function `SHParseDisplayName()`. We came across this in a previous post (https://github.com/hyp3ri0n-ng/hyp3ri0n-ng.github.io/blob/master/_posts/2020-12-16-moarmoarfuzz.md), and I mentinoed I was going to fuzz it. Then it looks like I stopped for some reason and never actually did it. OK, well, let's pick it back up and see what it looks like in dynamic analysis world:

```
0:000> g
ModLoad: 00007ff8`04950000 00007ff8`0499a000   C:\Windows\system32\wbload.dll
ModLoad: 00007fff`f87f0000 00007fff`f8abd000   C:\Program Files (x86)\Stardock\Start10\Start10_64.dll
ModLoad: 00007ff8`148a0000 00007ff8`149f7000   C:\Windows\System32\ole32.dll
Breakpoint 528 hit
Time Travel Position: 324F:DE
SHELL32!SHParseDisplayName:
00007ff8`1420b7b0 4055            push    rbp
0:000> r
rax=0000000000000000 rbx=0000000000000000 rcx=00000000000cf380
rdx=000000001c01ec50 rsi=0000000000000000 rdi=0000000000000000
rip=00007ff81420b7b0 rsp=00000000000cf268 rbp=00000000000cf380
 r8=00000000000cf300  r9=0000000000000000 r10=0000000000000000
r11=00000000000cf260 r12=0000000000000000 r13=0000000000000000
r14=00000000000cf300 r15=000000001c013d70
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
SHELL32!SHParseDisplayName:
00007ff8`1420b7b0 4055            push    rbp
```

Alright, first things first, calling conventions (yaaaayyyy)! We know in x64 world that the calling convention can be remembered as RCX, RDX, R8, R9 and then the stack. This is distinctly different than x86 world where everything is stored on the stack (mostly). Looks like RCX has given us the mem location of 0xcf380, so let's analyze that place in memory:

```
0:000> dq @rcx
00000000`000cf380  0057005c`003a0043 006f0064`006e0069
00000000`000cf390  00000000`00730077 00000000`00000000
00000000`000cf3a0  00000000`00000000 00000000`00000000
00000000`000cf3b0  00000000`00000000 00000000`00000000
00000000`000cf3c0  00000000`00000000 00000000`00000000
00000000`000cf3d0  00000000`00000000 00000000`00000000
00000000`000cf3e0  00000000`00000000 00000000`00000000
00000000`000cf3f0  00000000`00000000 00000000`00000000
```

OK so we should notice a few things here. First of all, remember we're in little-endian world so all our shit is backwards, also remember we're working in quad-words as our memory unit, so shit is backwards for 8 entire bytes (16 nibbles). It's pretty neat when you go into low-level land and start recognizing familiar things, but you can immediately see that my input is being passed to `SHParseDisplayName()` because we can actually see the encoded letters (windows uses UTF-16 so remember, each char is 2 bytes wide or 4 nibbles). Our first letter is 0x0043 ok that's a `C` the second letter is 0x003a `:` our 3rd `\\`. And I'm sure you can guess the rest of it, it's C:\windows! OK so that's pretty neat, I know exactly what my fuzz input should look like. It's at this point that I get ridiculously sidetracked. I've always been curious about a fuzzing technique that is something like "snapshot fuzzing". The basic idea would be that I find a list of the few most interesting instructions I run, in this case something like these instructions:

```
 3
    SHELL32!SHParseDisplayName:
00007ff8`1420b7b0 4055             push    rbp
00007ff8`1420b7b2 53               push    rbx
00007ff8`1420b7b3 56               push    rsi
00007ff8`1420b7b4 57               push    rdi
00007ff8`1420b7b5 4154             push    r12
00007ff8`1420b7b7 4155             push    r13
00007ff8`1420b7b9 4156             push    r14
00007ff8`1420b7bb 4157             push    r15
00007ff8`1420b7bd 488d6c24e9       lea     rbp, [rsp-17h]
00007ff8`1420b7c2 4881ec88000000   sub     rsp, 88h
00007ff8`1420b7c9 488b05d8fc6100   mov     rax, qword ptr [SHELL32!_security_cookie (00007ff8`1482b4a8)]
00007ff8`1420b7d0 4833c4           xor     rax, rsp
00007ff8`1420b7d3 48894507         mov     qword ptr [rbp+7], rax
00007ff8`1420b7d7 4c8b657f         mov     r12, qword ptr [rbp+7Fh]
00007ff8`1420b7db 458be9           mov     r13d, r9d
00007ff8`1420b7de 49832000         and     qword ptr [r8], 0
00007ff8`1420b7e2 4c8bf2           mov     r14, rdx
00007ff8`1420b7e5 4c8945d7         mov     qword ptr [rbp-29h], r8
00007ff8`1420b7e9 4d85e4           test    r12, r12
00007ff8`1420b7ec 0f8599010000     jne     SHELL32!SHParseDisplayName+0x1db (00007ff8`1420b98b)
00007ff8`1420b7f2 488d55f7         lea     rdx, [rbp-9]
00007ff8`1420b7f6 48ff152bd96600   call    qword ptr [SHELL32!_imp_SHStrDupW (00007ff8`14879128)]
00007ff8`1420b7fd 0f1f440000       nop     dword ptr [rax+rax]
00007ff8`1420b802 8bf8             mov     edi, eax
00007ff8`1420b804 85c0             test    eax, eax
00007ff8`1420b806 0f88f1000000     js      SHELL32!SHParseDisplayName+0x14d (00007ff8`1420b8fd)
00007ff8`1420b80c 488365ff00       and     qword ptr [rbp-1], 0
00007ff8`1420b811 488d4dff         lea     rcx, [rbp-1]
00007ff8`1420b815 48ff15bcbd5500   call    qword ptr [SHELL32!_imp_STORAGE_SHGetDesktopFolderWorker (00007ff8`147675d8)]
00007ff8`1420b81c 0f1f440000       nop     dword ptr [rax+rax]
00007ff8`1420b821 8bf8             mov     edi, eax
00007ff8`1420b823 85c0             test    eax, eax
00007ff8`1420b825 0f88ac000000     js      SHELL32!SHParseDisplayName+0x127 (00007ff8`1420b8d7)
00007ff8`1420b82b 33db             xor     ebx, ebx
00007ff8`1420b82d 33f6             xor     esi, esi
00007ff8`1420b82f 4d85f6           test    r14, r14
00007ff8`1420b832 0f84e7000000     je      SHELL32!SHParseDisplayName+0x16f (00007ff8`1420b91f)
00007ff8`1420b838 85ff             test    edi, edi
00007ff8`1420b83a 0f888e000000     js      SHELL32!SHParseDisplayName+0x11e (00007ff8`1420b8ce)
00007ff8`1420b840 488b4dff         mov     rcx, qword ptr [rbp-1]
00007ff8`1420b844 498bc4           mov     rax, r12
00007ff8`1420b847 48f7d8           neg     rax
00007ff8`1420b84a 44896ddf         mov     dword ptr [rbp-21h], r13d
00007ff8`1420b84e 488d45df         lea     rax, [rbp-21h]
00007ff8`1420b852 48894dcf         mov     qword ptr [rbp-31h], rcx
00007ff8`1420b856 481bff           sbb     rdi, rdi
00007ff8`1420b859 4c8bfe           mov     r15, rsi
00007ff8`1420b85c 488365ef00       and     qword ptr [rbp-11h], 0
00007ff8`1420b861 4823f8           and     rdi, rax
00007ff8`1420b864 4d85f6           test    r14, r14
00007ff8`1420b867 7427             je      SHELL32!SHParseDisplayName+0xe0 (00007ff8`1420b890)
00007ff8`1420b869 498b06           mov     rax, qword ptr [r14]
00007ff8`1420b86c 4c8d45e7         lea     r8, [rbp-19h]
00007ff8`1420b870 488d15b9fa5600   lea     rdx, [SHELL32!`string' (00007ff8`1477b330)]
00007ff8`1420b877 498bce           mov     rcx, r14
00007ff8`1420b87a 488b4050         mov     rax, qword ptr [rax+50h]
00007ff8`1420b87e ff15fcc25500     call    qword ptr [SHELL32!_guard_dispatch_icall_fptr (00007ff8`14767b80)]
00007ff8`1420b884 85c0             test    eax, eax
00007ff8`1420b886 0f8916010000     jns     SHELL32!SHParseDisplayName+0x1f2 (00007ff8`1420b9a2)
00007ff8`1420b88c 488b4dcf         mov     rcx, qword ptr [rbp-31h]
00007ff8`1420b890 488b01           mov     rax, qword ptr [rcx]
00007ff8`1420b893 4d8bc6           mov     r8, r14
00007ff8`1420b896 488b55d7         mov     rdx, qword ptr [rbp-29h]
00007ff8`1420b89a 4c8b4df7         mov     r9, qword ptr [rbp-9]
00007ff8`1420b89e 48897c2430       mov     qword ptr [rsp+30h], rdi
00007ff8`1420b8a3 488b4018         mov     rax, qword ptr [rax+18h]
00007ff8`1420b8a7 4889542428       mov     qword ptr [rsp+28h], rdx
00007ff8`1420b8ac 488b55ef         mov     rdx, qword ptr [rbp-11h]
00007ff8`1420b8b0 488364242000     and     qword ptr [rsp+20h], 0
00007ff8`1420b8b6 ff15c4c25500     call    qword ptr [SHELL32!_guard_dispatch_icall_fptr (00007ff8`14767b80)]
00007ff8`1420b8bc 8bf8             mov     edi, eax
00007ff8`1420b8be 498bf7           mov     rsi, r15
00007ff8`1420b8c1 85c0             test    eax, eax
00007ff8`1420b8c3 7809             js      SHELL32!SHParseDisplayName+0x11e (00007ff8`1420b8ce)
00007ff8`1420b8c5 4d85e4           test    r12, r12
00007ff8`1420b8c8 0f85c7000000     jne     SHELL32!SHParseDisplayName+0x1e5 (00007ff8`1420b995)
00007ff8`1420b8ce 4885f6           test    rsi, rsi
00007ff8`1420b8d1 0f859f000000     jne     SHELL32!SHParseDisplayName+0x1c6 (00007ff8`1420b976)
00007ff8`1420b8d7 488b4df7         mov     rcx, qword ptr [rbp-9]
00007ff8`1420b8db 48ff150ed56600   call    qword ptr [SHELL32!_imp_CoTaskMemFree (00007ff8`14878df0)]
00007ff8`1420b8e2 0f1f440000       nop     dword ptr [rax+rax]
00007ff8`1420b8e7 488b4dff         mov     rcx, qword ptr [rbp-1]
00007ff8`1420b8eb 4885c9           test    rcx, rcx
00007ff8`1420b8ee 740d             je      SHELL32!SHParseDisplayName+0x14d (00007ff8`1420b8fd)
00007ff8`1420b8f0 488b01           mov     rax, qword ptr [rcx]
00007ff8`1420b8f3 488b4010         mov     rax, qword ptr [rax+10h]
00007ff8`1420b8f7 ff1583c25500     call    qword ptr [SHELL32!_guard_dispatch_icall_fptr (00007ff8`14767b80)]
00007ff8`1420b8fd 8bc7             mov     eax, edi
00007ff8`1420b8ff 488b4d07         mov     rcx, qword ptr [rbp+7]
00007ff8`1420b903 4833cc           xor     rcx, rsp
00007ff8`1420b906 e805a00a00       call    SHELL32!_security_check_cookie (00007ff8`142b5910)
00007ff8`1420b90b 4881c488000000   add     rsp, 88h
00007ff8`1420b912 415f             pop     r15
00007ff8`1420b914 415e             pop     r14
00007ff8`1420b916 415d             pop     r13
00007ff8`1420b918 415c             pop     r12
00007ff8`1420b91a 5f               pop     rdi
00007ff8`1420b91b 5e               pop     rsi
00007ff8`1420b91c 5b               pop     rbx
00007ff8`1420b91d 5d               pop     rbp
00007ff8`1420b91e c3               ret     
00007ff8`1420b91f 488d55df         lea     rdx, [rbp-21h]
00007ff8`1420b923 33c9             xor     ecx, ecx
00007ff8`1420b925 48ff158cdd6600   call    qword ptr [SHELL32!_imp_CreateBindCtx (00007ff8`148796b8)]
00007ff8`1420b92c 0f1f440000       nop     dword ptr [rax+rax]
00007ff8`1420b931 8bf8             mov     edi, eax
00007ff8`1420b933 85c0             test    eax, eax
00007ff8`1420b935 7834             js      SHELL32!SHParseDisplayName+0x1bb (00007ff8`1420b96b)
00007ff8`1420b937 488b4ddf         mov     rcx, qword ptr [rbp-21h]
00007ff8`1420b93b e8a4710700       call    SHELL32!BindCtx_AddObjectParam (00007ff8`14282ae4)
00007ff8`1420b940 8bf8             mov     edi, eax
00007ff8`1420b942 85c0             test    eax, eax
00007ff8`1420b944 7814             js      SHELL32!SHParseDisplayName+0x1aa (00007ff8`1420b95a)
00007ff8`1420b946 488b5ddf         mov     rbx, qword ptr [rbp-21h]
00007ff8`1420b94a 488bcb           mov     rcx, rbx
00007ff8`1420b94d 488b03           mov     rax, qword ptr [rbx]
00007ff8`1420b950 488b4008         mov     rax, qword ptr [rax+8]
00007ff8`1420b954 ff1526c25500     call    qword ptr [SHELL32!_guard_dispatch_icall_fptr (00007ff8`14767b80)]
00007ff8`1420b95a 488b4ddf         mov     rcx, qword ptr [rbp-21h]
00007ff8`1420b95e 488b01           mov     rax, qword ptr [rcx]
00007ff8`1420b961 488b4010         mov     rax, qword ptr [rax+10h]
00007ff8`1420b965 ff1515c25500     call    qword ptr [SHELL32!_guard_dispatch_icall_fptr (00007ff8`14767b80)]
00007ff8`1420b96b 4c8bf3           mov     r14, rbx
00007ff8`1420b96e 488bf3           mov     rsi, rbx
00007ff8`1420b971 e9c2feffff       jmp     SHELL32!SHParseDisplayName+0x88 (00007ff8`1420b838)
00007ff8`1420b976 488b03           mov     rax, qword ptr [rbx]
00007ff8`1420b979 488bcb           mov     rcx, rbx
00007ff8`1420b97c 488b4010         mov     rax, qword ptr [rax+10h]
00007ff8`1420b980 ff15fac15500     call    qword ptr [SHELL32!_guard_dispatch_icall_fptr (00007ff8`14767b80)]
00007ff8`1420b986 e94cffffff       jmp     SHELL32!SHParseDisplayName+0x127 (00007ff8`1420b8d7)
00007ff8`1420b98b 4183242400       and     dword ptr [r12], 0
00007ff8`1420b990 e95dfeffff       jmp     SHELL32!SHParseDisplayName+0x42 (00007ff8`1420b7f2)
00007ff8`1420b995 44236ddf         and     r13d, dword ptr [rbp-21h]
00007ff8`1420b999 45892c24         mov     dword ptr [r12], r13d
00007ff8`1420b99d e92cffffff       jmp     SHELL32!SHParseDisplayName+0x11e (00007ff8`1420b8ce)
00007ff8`1420b9a2 488b4de7         mov     rcx, qword ptr [rbp-19h]
00007ff8`1420b9a6 488d55ef         lea     rdx, [rbp-11h]
00007ff8`1420b9aa 48ff15afce6600   call    qword ptr [SHELL32!_imp_IUnknown_GetWindow (00007ff8`14878860)]
00007ff8`1420b9b1 0f1f440000       nop     dword ptr [rax+rax]
00007ff8`1420b9b6 488b4de7         mov     rcx, qword ptr [rbp-19h]
00007ff8`1420b9ba 488b01           mov     rax, qword ptr [rcx]
00007ff8`1420b9bd 488b4010         mov     rax, qword ptr [rax+10h]
00007ff8`1420b9c1 ff15b9c15500     call    qword ptr [SHELL32!_guard_dispatch_icall_fptr (00007ff8`14767b80)]
00007ff8`1420b9c7 e9c0feffff       jmp     SHELL32!SHParseDisplayName+0xdc (00007ff8`1420b88
```

the astute reader noticed earlier that I had Time-Travel Debugging on. This wasn't by mistake. By using pykd I could easily programmatically control the commands sent to the debugger. So the basic idea was let's write a script that gives me a "timestamp" to travel back to the beginning of `SHParseDisplayName()`, and let's only allow this entire program to run `SHParseDisplayName()` however it calls it the program and then when the function is done, return back to that point in time where the function started. I thought this would be a pretty easy script to write - but as usual I totally miscalculated how long it would take me. Currently it's a hacky piece of shit that looks like this:

```
import pykd
import time
import sys
import random
from windbglib import Debugger
#from disasm import asm

tt_position = "41BB:DE"
#offset_done = 0x00007ff81420b903
offset_done = 0x00007ff81420b7f2
dbg = Debugger()
while(1):
    out = pykd.dbgCommand("p")
    print(out)
    current_offset = pykd.getIP()
    print("Current offset   offset to finish at")
    print(hex(current_offset), hex(offset_done))

    rcx_arg = pykd.addr64(pykd.reg("rcx"))

    num_bytes = random.randint(0,200)
    random_bytes = random.randbytes(num_bytes).hex()
    print("GENERATING RANDOM BYTES: ", str(random_bytes))


    print("=================GETTING RCX AND STUFF======================")
    print(rcx_arg)
    print(pykd.dbgCommand("dq @rcx"))
    print(pykd.dbgCommand("r"))
    pykd.writeBytes(rcx_arg, list(random_bytes))
    print("============================================================")

    print("WROTE RANDOM BYTES, SEE?????")
    print(pykd.dbgCommand("dq @rcx"))
    print(pykd.dbgCommand("r"))

    print("CHECKING FOR EXCEPTIONS!!!!")
    if pykd.pykd.eventType(0) != pykd.getLastEvent().type:
        print("UH OH LUCY, WE HAS A PROBLEM")
        print(pykd.getLastEvent().type)
        print(pykd.dbgCommand(".lastevent"))
        sys.exit(1)


    print("CHECKING TO SEE IF MAKE SHITTY JOKE!@::")
    if hex(current_offset) == hex(offset_done):
        print("done, going back... TO THE FUTURE (actually the past).")
        pykd.dbgCommand("!ttdext.tt {}".format(tt_position))



    #if last_instruction in out:
    time.sleep(3)
```

What is this doing? I'm manually viewing in WinDBG when the function ends, and when it does I jump right back to the time travel location (in this case `41BB:DE`). All the while I'm outputting some interesting info to make sure all is on track, and also telling it to stop if there's any kind of exception in the code. I can then simply look up the error code (buffer overflow, read access violation, etc). As for the arguments to the function, in low-level land they're always stored in RCX (and we know this is my user input) so I'm placing a bunch of random bytes into it between the size of 0 and 200. This script doesn't yet work, so don't use it. It needs one thing that I got stuck on and need to research further: when I try to write to the location RCX points to I get a write access violation. It seems that the page is likely read only. This is further validated when I see that the argument is of type `PCWSTR`, which stands for something like "pointer constant wide string". The constant is the keyword there, since it's not going to change, it doesn't need to place the data anywhere that allows for anything but reads, so it ends up on a read-only page. Now I just need to write a script that takes in an offset, finds its memory page, and marks that page as writable. The idea being that I execute only a tiny piece of the program, providing me a massive speedup, and also ensuring that I'm exactly copying the programs behavior. This seems like it would gain me a ton of cycles if I pin it down to only a few hundred instructions. BUT it's taking a while, and I really wanted to get back to hunting. I'll come back to this. I don't know if this is a technique being used out there, but I'm calling it Timecop Fuzzing, so you know, spread the word and shit.

Alright, so barring that let's see if we can make that function crash with a normal fuzzer, eh? This time let's try to get ourselves going with WinAFL or the new fuzzer I'm creating called FWA (Fuzzers With Attitude). We'll see, but so far so good. We've found something we KNOW is an unadulterated user input, so perhaps we're on our way to an exploit that causes the program to do funky things when it's name something. Stay tuned!










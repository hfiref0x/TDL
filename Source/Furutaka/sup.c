/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       SUP.C
*
*  VERSION:     1.15
*
*  DATE:        19 Apr 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* supGetSystemInfo
*
* Purpose:
*
* Wrapper for NtQuerySystemInformation.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT         c = 0;
    PVOID       Buffer = NULL;
    ULONG		Size = 0x1000;
    NTSTATUS    status;
    ULONG       memIO;
    PVOID       hHeap = NtCurrentPeb()->ProcessHeap;

    do {
        Buffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, (SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            RtlFreeHeap(hHeap, 0, Buffer);
            Buffer = NULL;
            Size *= 2;
            c++;
            if (c > 100) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        RtlFreeHeap(hHeap, 0, Buffer);
    }
    return NULL;
}

/*
* supGetNtOsBase
*
* Purpose:
*
* Return ntoskrnl base address.
*
*/
ULONG_PTR supGetNtOsBase(
    VOID
)
{
    PRTL_PROCESS_MODULES   miSpace;
    ULONG_PTR              NtOsBase = 0;

    miSpace = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (miSpace) {
        NtOsBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, miSpace);
    }
    return NtOsBase;
}

/*
* supQueryResourceData
*
* Purpose:
*
* Load resource by given id (win32 FindResource, SizeofResource, LockResource).
*
*/
PBYTE supQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
)
{
    NTSTATUS                    status;
    ULONG_PTR                   IdPath[3];
    IMAGE_RESOURCE_DATA_ENTRY  *DataEntry;
    PBYTE                       Data = NULL;
    ULONG                       SizeOfData = 0;

    if (DllHandle != NULL) {

        IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
        IdPath[1] = ResourceId;           //id
        IdPath[2] = 0;                    //lang

        status = LdrFindResource_U(DllHandle, (ULONG_PTR*)&IdPath, 3, &DataEntry);
        if (NT_SUCCESS(status)) {
            status = LdrAccessResource(DllHandle, DataEntry, (PVOID*)&Data, &SizeOfData);
            if (NT_SUCCESS(status)) {
                if (DataSize) {
                    *DataSize = SizeOfData;
                }
            }
        }
    }
    return Data;
}

/*
* supBackupVBoxDrv
*
* Purpose:
*
* Backup virtualbox driver file if it already installed.
*
*/
BOOL supBackupVBoxDrv(
    _In_ BOOL bRestore
)
{
    BOOL  bResult = FALSE;
    WCHAR szOldDriverName[MAX_PATH * 2];
    WCHAR szNewDriverName[MAX_PATH * 2];
    WCHAR szDriverDirName[MAX_PATH * 2];

    if (!GetSystemDirectory(szDriverDirName, MAX_PATH)) {
        return FALSE;
    }

    _strcat(szDriverDirName, TEXT("\\drivers\\"));

    if (bRestore) {
        _strcpy(szOldDriverName, szDriverDirName);
        _strcat(szOldDriverName, TEXT("VBoxDrv.backup"));
        if (PathFileExists(szOldDriverName)) {
            _strcpy(szNewDriverName, szDriverDirName);
            _strcat(szNewDriverName, TEXT("VBoxDrv.sys"));
            bResult = MoveFileEx(szOldDriverName, szNewDriverName,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        }
    }
    else {
        _strcpy(szOldDriverName, szDriverDirName);
        _strcat(szOldDriverName, TEXT("VBoxDrv.sys"));
        _strcpy(szNewDriverName, szDriverDirName);
        _strcat(szNewDriverName, TEXT("VBoxDrv.backup"));
        bResult = MoveFileEx(szOldDriverName, szNewDriverName,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    return bResult;
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file (or open existing) and write (append) buffer to it.
*
*/
SIZE_T supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append
)
{
    NTSTATUS           Status;
    DWORD              dwFlag;
    HANDLE             hFile = NULL;
    OBJECT_ATTRIBUTES  attr;
    UNICODE_STRING     NtFileName;
    IO_STATUS_BLOCK    IoStatus;
    LARGE_INTEGER      Position;
    ACCESS_MASK        DesiredAccess;
    PLARGE_INTEGER     pPosition = NULL;
    ULONG_PTR          nBlocks, BlockIndex;
    ULONG              BlockSize, RemainingSize;
    PBYTE              ptr = (PBYTE)Buffer;
    SIZE_T             BytesWritten = 0;

    if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE)
        return 0;

    DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
    dwFlag = FILE_OVERWRITE_IF;

    if (Append != FALSE) {
        DesiredAccess |= FILE_READ_ACCESS;
        dwFlag = FILE_OPEN_IF;
    }

    InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    __try {
        Status = NtCreateFile(&hFile, DesiredAccess, &attr,
            &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(Status))
            __leave;

        pPosition = NULL;

        if (Append != FALSE) {
            Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
            Position.HighPart = -1;
            pPosition = &Position;
        }

        if (Size < 0x80000000) {
            BlockSize = (ULONG)Size;
            Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
            if (!NT_SUCCESS(Status))
                __leave;

            BytesWritten += IoStatus.Information;
        }
        else {
            BlockSize = 0x7FFFFFFF;
            nBlocks = (Size / BlockSize);
            for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;

                ptr += BlockSize;
                BytesWritten += IoStatus.Information;
            }
            RemainingSize = (ULONG)(Size % BlockSize);
            if (RemainingSize != 0) {
                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;
                BytesWritten += IoStatus.Information;
            }
        }
    }
    __finally {
        if (hFile != NULL) {
            if (Flush != FALSE) NtFlushBuffersFile(hFile, &IoStatus);
            NtClose(hFile);
        }
        RtlFreeUnicodeString(&NtFileName);
    }
    return BytesWritten;
}

/*
* supDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Param->Buffer == NULL || Param->BufferSize == 0) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    if (Entry->Name.Buffer) {
        if (_strcmpi_w(Entry->Name.Buffer, Param->Buffer) == 0) {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

/*
* supEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam
)
{
    BOOL                cond = TRUE;
    ULONG               ctx, rlen;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    NTSTATUS            CallbackStatus;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      sname;

    POBJECT_DIRECTORY_INFORMATION    objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    status = STATUS_UNSUCCESSFUL;

    __try {

        // We can use root directory.
        if (pwszRootDirectory != NULL) {
            RtlSecureZeroMemory(&sname, sizeof(sname));
            RtlInitUnicodeString(&sname, pwszRootDirectory);
            InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else {
            if (hRootDirectory == NULL) {
                return STATUS_INVALID_PARAMETER_2;
            }
            hDirectory = hRootDirectory;
        }

        // Enumerate objects in directory.
        ctx = 0;
        do {

            rlen = 0;
            status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
            if (status != STATUS_BUFFER_TOO_SMALL)
                break;

            objinf = (POBJECT_DIRECTORY_INFORMATION)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, rlen);
            if (objinf == NULL)
                break;

            status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
            if (!NT_SUCCESS(status)) {
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);
                break;
            }

            CallbackStatus = CallbackProc(objinf, CallbackParam);

            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);

            if (NT_SUCCESS(CallbackStatus)) {
                status = STATUS_SUCCESS;
                break;
            }

        } while (cond);

        if (hDirectory != NULL) {
            NtClose(hDirectory);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*
* supIsObjectExists
*
* Purpose:
*
* Return TRUE if the given object exists, FALSE otherwise.
*
*/
BOOLEAN supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName
)
{
    OBJSCANPARAM Param;

    if (ObjectName == NULL) {
        return FALSE;
    }

    Param.Buffer = ObjectName;
    Param.BufferSize = (ULONG)_strlen(ObjectName);

    return NT_SUCCESS(supEnumSystemObjects(RootDirectory, NULL, supDetectObjectCallback, &Param));
}

/*
* supxStopServiceShowError
*
* Purpose:
*
* Display Function + LastError message for SCM part, Function limited to MAX_PATH.
*
*/
VOID supxStopServiceShowError(
    _In_ LPWSTR Function,
    _In_ DWORD ErrorCode)
{
    WCHAR szMessage[300];

    _strcpy(szMessage, TEXT("SCM: "));
    _strcat(szMessage, Function);
    _strcat(szMessage, TEXT(" failed ("));
    ultostr(ErrorCode, _strend(szMessage));
    _strcat(szMessage, TEXT(")"));
    cuiPrintText(szMessage, TRUE);
}

/*
* supStopVBoxService
*
* Purpose:
*
* Stop given VirtualBox service (unload kernel driver).
*
*/
BOOLEAN supStopVBoxService(
    _In_ SC_HANDLE schSCManager,
    _In_ LPWSTR szSvcName //MAX_PATH limit
)
{
    BOOLEAN bResult = FALSE;

    SC_HANDLE schService;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwStartTime = GetTickCount();
    DWORD dwBytesNeeded;
    DWORD dwTimeout = 30000; //30 seconds timeout for this proc.
    DWORD dwWaitTime;
    DWORD dwLastError;

    WCHAR szMessage[MAX_PATH * 2];

    _strcpy(szMessage, TEXT("SCM: Attempt to stop "));
    _strcat(szMessage, szSvcName);
    cuiPrintText(szMessage, TRUE);

    //
    // Open service, if service does not exist consider this as success and leave.
    //
    schService = OpenService(
        schSCManager,
        szSvcName,
        SERVICE_STOP |
        SERVICE_QUERY_STATUS);

    if (schService == NULL) {
        dwLastError = GetLastError();
        if (dwLastError == ERROR_SERVICE_DOES_NOT_EXIST) {
            cuiPrintText(TEXT("SCM: Service does not exist, skip"), TRUE);
            return TRUE;
        }
        else {
            supxStopServiceShowError(TEXT("OpenService"), GetLastError());
            return FALSE;
        }
    }

    //
    // Query service status.
    //
    if (!QueryServiceStatusEx(
        schService,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp,
        sizeof(SERVICE_STATUS_PROCESS),
        &dwBytesNeeded))
    {
        supxStopServiceShowError(TEXT("QueryServiceStatusEx"), GetLastError());
        goto stop_cleanup;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        cuiPrintText(TEXT("SCM: Service is already stopped"), TRUE);
        bResult = TRUE;
        goto stop_cleanup;
    }

    //
    // If service already in stop pending state, wait a little.
    //
    while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
    {
        cuiPrintText(TEXT("SCM: Service stop pending..."), TRUE);

        dwWaitTime = ssp.dwWaitHint / 10;

        if (dwWaitTime < 1000)
            dwWaitTime = 1000;
        else if (dwWaitTime > 10000)
            dwWaitTime = 10000;

        Sleep(dwWaitTime);

        if (!QueryServiceStatusEx(
            schService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded))
        {
            supxStopServiceShowError(TEXT("QueryServiceStatusEx"), GetLastError());
            goto stop_cleanup;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            cuiPrintText(TEXT("SCM: Service stopped successfully"), TRUE);
            bResult = TRUE;
            goto stop_cleanup;
        }

        //
        // 30 seconds execution timeout reached.
        //
        if (GetTickCount() - dwStartTime > dwTimeout) {
            cuiPrintText(TEXT("SCM: Service stop timed out.\n"), TRUE);
            goto stop_cleanup;
        }
    }

    //
    // Stop service.
    //
    if (!ControlService(
        schService,
        SERVICE_CONTROL_STOP,
        (LPSERVICE_STATUS)&ssp))
    {
        supxStopServiceShowError(TEXT("ControlService"), GetLastError());
        goto stop_cleanup;
    }

    //
    // Check whatever we need to wait for service stop.
    //
    while (ssp.dwCurrentState != SERVICE_STOPPED)
    {
        Sleep(ssp.dwWaitHint);
        if (!QueryServiceStatusEx(
            schService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded))
        {
            supxStopServiceShowError(TEXT("QueryServiceStatusEx"), GetLastError());
            goto stop_cleanup;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED)
            break;

        //
        // 30 seconds execution timeout reached.
        //
        if (GetTickCount() - dwStartTime > dwTimeout) {
            cuiPrintText(TEXT("SCM: Wait timed out"), TRUE);
            goto stop_cleanup;
        }
    }
    cuiPrintText(TEXT("SCM: Service stopped successfully"), TRUE);
    bResult = TRUE;

stop_cleanup:
    CloseServiceHandle(schService);

    return bResult;
}

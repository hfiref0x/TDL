/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       SUP.H
*
*  VERSION:     1.15
*
*  DATE:        19 Apr 2019
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef NTSTATUS(NTAPI *PENUMOBJECTSCALLBACK)(POBJECT_DIRECTORY_INFORMATION Entry, PVOID CallbackParam);

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    ULONG BufferSize;
} OBJSCANPARAM, *POBJSCANPARAM;

ULONG_PTR supGetNtOsBase(
    VOID);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass);

PBYTE supQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

BOOL supBackupVBoxDrv(
    _In_ BOOL bRestore);

SIZE_T supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append);

BOOLEAN supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName);

BOOLEAN supStopVBoxService(
    _In_ SC_HANDLE schSCManager,
    _In_ LPWSTR szSvcName);

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)

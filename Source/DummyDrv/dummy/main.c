/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.01
*
*  DATE:        20 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

/*
* DriverEntry
*
* Purpose:
*
* Driver base entry point.
*
*/
NTSTATUS DriverEntry(
    _In_  struct _DRIVER_OBJECT *DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    PEPROCESS Process;
    KIRQL Irql;
    PWSTR sIrql;

    /* This parameters are invalid due to nonstandard way of loading and should not be used. */
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Hello from kernel mode, system range start is %p, code mapped at %p\n", MmSystemRangeStart, DriverEntry);

    Process = PsGetCurrentProcess();
    DbgPrint("I'm at %s, Process : %lu (%p)\n",
        __FUNCTION__,
        (ULONG)PsGetCurrentProcessId(),
        Process);

    Irql = KeGetCurrentIrql();

    switch (Irql) {

    case PASSIVE_LEVEL:
        sIrql = L"PASSIVE_LEVEL";
        break;
    case APC_LEVEL:
        sIrql = L"APC_LEVEL";
        break;
    case DISPATCH_LEVEL:
        sIrql = L"DISPATCH_LEVEL";
        break;
    case CMCI_LEVEL:
        sIrql = L"CMCI_LEVEL";
        break;
    case CLOCK_LEVEL:
        sIrql = L"CLOCK_LEVEL";
        break;
    case IPI_LEVEL:
        sIrql = L"IPI_LEVEL";
        break;
    case HIGH_LEVEL:
        sIrql = L"HIGH_LEVEL";
        break;
    default:
        sIrql = L"Unknown Value";
        break;
    }

    DbgPrint("KeGetCurrentIrql=%ws\n", sIrql);

    return STATUS_SUCCESS;
}

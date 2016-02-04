/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        29 Jan 2016
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
	LARGE_INTEGER tm;
	PEPROCESS Process;

	tm.QuadPart = -10000000;

	/* This parameters are invalid due to nonstandard way of loading and should not be used. */
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("Hello from kernel mode, system range start is %p, code mapped at %p", MmSystemRangeStart, DriverEntry);

	Process = PsGetCurrentProcess();

	do {

		KeDelayExecutionThread(KernelMode, FALSE, &tm);
		
		DbgPrint("I'm at %s, Process : %lu (%p)",
			__FUNCTION__, 
			(ULONG)PsGetCurrentProcessId(),
			Process
			);


	} while (1);

	return STATUS_SUCCESS;
}

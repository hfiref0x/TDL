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
#include "main.h"

#define DEBUGPRINT

/*
* DevioctlDispatch
*
* Purpose:
*
* IRP_MJ_DEVICE_CONTROL dispatch.
*
*/
NTSTATUS DevioctlDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	NTSTATUS				status = STATUS_SUCCESS;
	ULONG					bytesIO = 0;
	PIO_STACK_LOCATION		stack;
	BOOLEAN					condition = FALSE;
	PINOUTPARAM             rp, wp;

	UNREFERENCED_PARAMETER(DeviceObject);

#ifdef DEBUGPRINT
	DbgPrint("%s IRP_MJ_DEVICE_CONTROL", __FUNCTION__);
#endif

	stack = IoGetCurrentIrpStackLocation(Irp);

	do {

		if (stack == NULL) {
			status = STATUS_INTERNAL_ERROR;
			break;
		}

		rp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
		wp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
		if (rp == NULL) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case DUMMYDRV_REQUEST1:

#ifdef DEBUGPRINT
			DbgPrint("%s DUMMYDRV_REQUEST1 hit", __FUNCTION__);
#endif			
			if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(INOUT_PARAM)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

#ifdef DEBUGPRINT
			DbgPrint("%s in params = %lx, %lx, %lx, %lx", __FUNCTION__, 
				rp->Param1, rp->Param2, rp->Param3, rp->Param4);
#endif

			wp->Param1 = 11111111;
			wp->Param2 = 22222222;
			wp->Param3 = 33333333;
			wp->Param4 = 44444444;

			status = STATUS_SUCCESS;
			bytesIO = sizeof(INOUT_PARAM);

			break;

		default:

#ifdef DEBUGPRINT
			DbgPrint("%s hit with invalid IoControlCode", __FUNCTION__);
#endif
			status = STATUS_INVALID_PARAMETER;
		};

	} while (condition);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

/*
* UnsupportedDispatch
*
* Purpose:
*
* Unused IRP_MJ_* dispatch.
*
*/
NTSTATUS UnsupportedDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

/*
* CreateDispatch
*
* Purpose:
*
* IRP_MJ_CREATE dispatch.
*
*/
NTSTATUS CreateDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

#ifdef DEBUGPRINT
	DbgPrint("%s Create", __FUNCTION__);
#endif

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

/*
* CloseDispatch
*
* Purpose:
*
* IRP_MJ_CLOSE dispatch.
*
*/
NTSTATUS CloseDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

#ifdef DEBUGPRINT
	DbgPrint("%s Close", __FUNCTION__);
#endif

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

VOID ListModules(
	_In_  struct _DRIVER_OBJECT *DriverObject
	)
{
	PLIST_ENTRY            entry0, entry1;
	KLDR_DATA_TABLE_ENTRY *section = (KLDR_DATA_TABLE_ENTRY*)DriverObject->DriverSection;

	if (section == NULL)
		return;

	entry0 = section->InLoadOrderLinks.Flink;
	entry1 = entry0;

	do {
		section = (KLDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(entry1, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		DbgPrint("Section=%p, %wZ", section, section->BaseDllName);
		entry1 = entry1->Flink;
	} while (entry1 != entry0);
}

/*
* DriverInitialize
*
* Purpose:
*
* Driver main.
*
*/
NTSTATUS DriverInitialize(
	_In_  struct _DRIVER_OBJECT *DriverObject,
	_In_  PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS        status;
	UNICODE_STRING  SymLink, DevName/*, DrvRefName*/;
	PDEVICE_OBJECT  devobj;
	ULONG           t;
	WCHAR szDevName[] = { L'\\', L'D', L'e', L'v', L'i', L'c', L'e', L'\\', L'T', L'D', L'L', L'D', 0 };
	WCHAR szSymLink[] = { L'\\', L'D', L'o', L's', L'D', L'e', L'v', L'i', L'c', L'e', L's', L'\\', L'T', L'D', L'L', L'D', 0 };
//	WCHAR szNullDrv[] = { L'\\', L'D', L'r', L'i', L'v', L'e', L'r', L'\\', L'N', L'u', L'l', L'l', 0 };
//	PDRIVER_OBJECT  driverObject;

	//RegistryPath is NULL
	UNREFERENCED_PARAMETER(RegistryPath);

#ifdef DEBUGPRINT
	DbgPrint("%s", __FUNCTION__);
#endif

	RtlInitUnicodeString(&DevName, szDevName);
	status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);

#ifdef DEBUGPRINT
	DbgPrint("%s IoCreateDevice(%wZ) = %lx", __FUNCTION__, DevName, status);
#endif

	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlInitUnicodeString(&SymLink, szSymLink);
	status = IoCreateSymbolicLink(&SymLink, &DevName);

#ifdef DEBUGPRINT
	DbgPrint("%s IoCreateSymbolicLink(%wZ) = %lx", __FUNCTION__, SymLink, status);
#endif

	devobj->Flags |= DO_BUFFERED_IO;

	for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->DriverUnload = NULL; //nonstandard way of driver loading, no unload

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;
/*
	RtlInitUnicodeString(&DrvRefName, szNullDrv);
	if (NT_SUCCESS(ObReferenceObjectByName(&DrvRefName, OBJ_CASE_INSENSITIVE, NULL, 0, 
		*IoDriverObjectType, KernelMode, NULL, &driverObject)))
	{
		DbgPrint("drvObj %p", driverObject);
		ListModules(driverObject);
		ObDereferenceObject(driverObject);
	}
	*/

	return status;
}

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
	NTSTATUS        status;
	UNICODE_STRING  drvName;
	WCHAR szDrvName[] = { L'\\', L'D', L'r', L'i', L'v', L'e', L'r', L'\\', L'T', L'D', L'L', L'D', 0 };

	/* This parameters are invalid due to nonstandard way of loading and should not be used. */
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

#ifdef DEBUGPRINT
	DbgPrint("%s", __FUNCTION__);
#endif

	RtlInitUnicodeString(&drvName, szDrvName);
	status = IoCreateDriver(&drvName, &DriverInitialize);

#ifdef DEBUGPRINT
	DbgPrint("%s IoCreateDriver(%wZ) = %lx", __FUNCTION__, drvName, status);
#endif

	return status;
}

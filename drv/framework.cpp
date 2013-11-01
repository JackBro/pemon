
#include <ntddk.h>
#include <ntimage.h>
#include "pefilter.h"
#include "../include/public.h"
#include "ntpath.h"

#define dprintf             DbgPrint
#define DEVICE_NAME         L"\\Device\\pefilter"
#define LINK_NAME           L"\\DosDevices\\pefilter"
#define LINK_GLOBAL_NAME    L"\\DosDevices\\Global\\pefilter"

PDEVICE_OBJECT g_devobj = NULL;

VOID UnicodeToChar(PUNICODE_STRING dst, char *src)
{
    ANSI_STRING string;
    RtlUnicodeStringToAnsiString(&string,dst, TRUE);
    strcpy(src,string.Buffer);
    RtlFreeAnsiString(&string);
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{   
    UNICODE_STRING strLink;
    //remove
    SetupImageNotify(NULL, NULL);
    RtlInitUnicodeString(&strLink, LINK_NAME);
    IoDeleteSymbolicLink(&strLink);
    IoDeleteDevice(pDriverObj->DeviceObject);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


BOOLEAN 
OnDemoDeny(ULONG ProcessId, 
    UNICODE_STRING* FullImagePath, 
    enum DISK_TYPE DeviceType, 
    enum IMAGE_TYPE ImageType,
    VOID* Context)
{
    UNICODE_STRING usDeviceType = {0};
    if (DeviceType == DT_USB) {
        RtlInitUnicodeString(&usDeviceType, L"USB");
    } else if (DeviceType == DT_REMOTE) {
        RtlInitUnicodeString(&usDeviceType, L"REMOTE");
    } else if (DeviceType == DT_DISK) {
        RtlInitUnicodeString(&usDeviceType, L"LOCAL");
    } else if (DeviceType == DT_CDROM) {  
        RtlInitUnicodeString(&usDeviceType, L"CDROM");
    } else {
        RtlInitUnicodeString(&usDeviceType, L"UNKNOWN");
    }

    UNICODE_STRING usImageType = {0};
    if (ImageType == IMAGE_EXE) {
        RtlInitUnicodeString(&usImageType,  L"EXE");
    } else if (ImageType == IMAGE_DLL) {
        RtlInitUnicodeString(&usImageType, L"DLL");
    } else if (ImageType == IMAGE_SYS) {
        RtlInitUnicodeString(&usImageType, L"SYS");
    } else {
        RtlInitUnicodeString(&usImageType, L"UNKNOWN");
    }

    BOOLEAN IsAllow= TRUE;

    ULONG ioctl = (ULONG)Context;

    if (ioctl == IOCTL_DEMO_DENY_NOTEPAD) {

        if (ImageType == IMAGE_EXE && 
            NULL != RtlSearchString(FullImagePath, L"NOTEPAD.EXE", FALSE)) {
            IsAllow = FALSE;
        }

    } else if (ioctl == IOCTL_DEMO_DENY_FFI) {

        if (ImageType == IMAGE_DLL &&
            NULL != RtlSearchString(FullImagePath, L"unarc.dll", FALSE)) {
            IsAllow = FALSE;
        }

    } else if (ioctl == IOCTL_DEMO_DENY_FILEMON) {

        if (ImageType == IMAGE_SYS && 
            NULL != RtlSearchString(FullImagePath, L"FILEM", FALSE)) {
            IsAllow = FALSE;
        }

    } else if (ioctl == IOCTL_DEMO_DENY_CDROM) {

        if (DeviceType == DT_CDROM) {
            IsAllow = FALSE;
        }

    } else if (ioctl == IOCTL_DEMO_DENY_USB) {

        if (DeviceType == DT_USB) {
            IsAllow = FALSE;
        }

    } else if (ioctl == IOCTL_DEMO_DENY_SMB) {

        if (DeviceType == DT_REMOTE) {
            IsAllow = FALSE;
        }
        
    } 

    DbgPrint("[pefilter]%S, %wZ, %wZ, %wZ\n\n",
        IsAllow ? L"ALLOW":L"DENY", 
        &usDeviceType, &usImageType, FullImagePath);

    return IsAllow;
}


NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION pIrpStack;
    ULONG uIoControlCode;
    PVOID pIoBuffer;
    ULONG uInSize;
    ULONG uOutSize;
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
    uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
    switch(uIoControlCode)
    {
    case IOCTL_DEMO_DENY_NOTEPAD:
    case IOCTL_DEMO_DENY_FFI:
    case IOCTL_DEMO_DENY_FILEMON:
    case IOCTL_DEMO_DENY_CDROM:
    case IOCTL_DEMO_DENY_USB:
    case IOCTL_DEMO_DENY_SMB:

        //nothing
        if (SetupImageNotify(OnDemoDeny, (PVOID*)uIoControlCode)) {
            status = STATUS_SUCCESS;    
        } else {
            status = STATUS_UNSUCCESSFUL;
        }
        break;

    default:
        break;
    }
    if(status == STATUS_SUCCESS)
        pIrp->IoStatus.Information = uOutSize;
    else
        pIrp->IoStatus.Information = 0; 
    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ustrLinkName;
    UNICODE_STRING ustrDevName;  
    PDEVICE_OBJECT pDevObj;
    pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    pDriverObj->DriverUnload = DriverUnload;
    RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
    status = IoCreateDevice(pDriverObj, 
        sizeof(DEVICE_EXTENSION), 
        &ustrDevName, 
        FILE_DEVICE_UNKNOWN, 
        0, FALSE, &pDevObj);
    if(!NT_SUCCESS(status)) return status;
    if(IoIsWdmVersionAvailable(1, 0x10))
        RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
    else
        RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
    status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);     
    if(!NT_SUCCESS(status))
    {
        IoDeleteDevice(pDevObj); 
        return status;
    }
    
    g_devobj = pDevObj;
    
    DbgPrint("[pefilter]Driver loaded!");

    return STATUS_SUCCESS;
}




#include <ntddk.h>
#include <ntimage.h>
#include "pefilter.h"
#include "ntpath.h"

extern DEVICE_OBJECT* g_devobj;

//
// IoControlCode values for storage devices
//

#define IOCTL_STORAGE_BASE FILE_DEVICE_MASS_STORAGE

#define IOCTL_STORAGE_QUERY_PROPERTY  \
    CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _STORAGE_BUS_TYPE {
    BusTypeUnknown = 0x00,
    BusTypeScsi,
    BusTypeAtapi,
    BusTypeAta,
    BusType1394,
    BusTypeSsa,
    BusTypeFibre,
    BusTypeUsb,
    BusTypeRAID,
    BusTypeiScsi,
    BusTypeSas,
    BusTypeSata,
    BusTypeSd,
    BusTypeMmc,
    BusTypeMax,
    BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, *PSTORAGE_BUS_TYPE;

typedef __struct_bcount(Size) struct _STORAGE_DEVICE_DESCRIPTOR {

    //
    // Sizeof(STORAGE_DEVICE_DESCRIPTOR)
    //

    ULONG Version;

    //
    // Total size of the descriptor, including the space for additional
    // data and id strings
    //

    ULONG Size;

    //
    // The SCSI-2 device type
    //

    UCHAR  DeviceType;

    //
    // The SCSI-2 device type modifier (if any) - this may be zero
    //

    UCHAR  DeviceTypeModifier;

    //
    // Flag indicating whether the device's media (if any) is removable.  This
    // field should be ignored for media-less devices
    //

    BOOLEAN RemovableMedia;

    //
    // Flag indicating whether the device can support mulitple outstanding
    // commands.  The actual synchronization in this case is the responsibility
    // of the port driver.
    //

    BOOLEAN CommandQueueing;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // vendor id string.  For devices with no such ID this will be zero
    //

    ULONG VendorIdOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // product id string.  For devices with no such ID this will be zero
    //

    ULONG ProductIdOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // product revision string.  For devices with no such string this will be
    // zero
    //

    ULONG ProductRevisionOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // serial number.  For devices with no serial number this will be zero
    //

    ULONG SerialNumberOffset;

    //
    // Contains the bus type (as defined above) of the device.  It should be
    // used to interpret the raw device properties at the end of this structure
    // (if any)
    //

    STORAGE_BUS_TYPE BusType;

    //
    // The number of bytes of bus-specific data which have been appended to
    // this descriptor
    //

    ULONG RawPropertiesLength;

    //
    // Place holder for the first byte of the bus specific property data
    //

    UCHAR  RawDeviceProperties[1];

} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

//
// define some initial property id's
//

typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty,
    StorageDeviceIdProperty,
    StorageDeviceUniqueIdProperty,              // See storduid.h for details
    StorageDeviceWriteCacheProperty,
    StorageMiniportProperty,
    StorageAccessAlignmentProperty
} STORAGE_PROPERTY_ID, *PSTORAGE_PROPERTY_ID;

//
// Types of queries
//

typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,          // Retrieves the descriptor
    PropertyExistsQuery,                // Used to test whether the descriptor is supported
    PropertyMaskQuery,                  // Used to retrieve a mask of writeable fields in the descriptor
    PropertyQueryMaxDefined     // use to validate the value
} STORAGE_QUERY_TYPE, *PSTORAGE_QUERY_TYPE;

typedef struct _STORAGE_PROPERTY_QUERY {

    //
    // ID of the property being retrieved
    //

    STORAGE_PROPERTY_ID PropertyId;

    //
    // Flags indicating the type of query being performed
    //

    STORAGE_QUERY_TYPE QueryType;

    //
    // Space for additional parameters if necessary
    //

    UCHAR  AdditionalParameters[1];

} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

BOOLEAN VxkCopyMemory( PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy )
{
    PMDL pMdl = NULL;
    PVOID pSafeAddress = NULL;
    pMdl = IoAllocateMdl( pSourceAddress, (ULONG)SizeOfCopy, FALSE, FALSE, NULL );
    if( !pMdl ) return FALSE;
    __try
    {
        MmProbeAndLockPages( pMdl, KernelMode, IoReadAccess );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl( pMdl );
        return FALSE;
    }
    pSafeAddress = MmGetSystemAddressForMdlSafe( pMdl, NormalPagePriority );
    if( !pSafeAddress ) return FALSE;
    RtlCopyMemory( pDestination, pSafeAddress, SizeOfCopy );
    MmUnlockPages( pMdl );
    IoFreeMdl( pMdl );
    return TRUE;
}

  
NTSTATUS SafeCopyMemory(ULONG ulAddrDst, ULONG ulAddrSrc, ULONG ulLenToCopy)  
{  
    NTSTATUS    status = STATUS_UNSUCCESSFUL;  
    ULONG       ulLen = 0;  
      
    KIRQL       irqlCur;  
    PMDL        pMdlSrc = NULL;  
    PMDL        pMdlDst = NULL;  
  
    PVOID       pMdlSafeSrc = NULL;   
    PVOID       pMdlSafeDst = NULL;  
  
    /// 校验所有要操作的字节地址  
    ulLen = (ulLenToCopy > 0) ? (ulLenToCopy - 1) : 0;  
    do  
    {  
        if (/*!MmIsAddressValid(((UCHAR *)ulAddrDst + ulLen))  || */
            !MmIsAddressValid(((UCHAR *)ulAddrSrc + ulLen)))  
        {  
            goto _SafeCopy_END;  
        }  
    } while (0 != ulLen--);  
  
    pMdlDst = IoAllocateMdl((PVOID)ulAddrDst, ulLenToCopy, FALSE, FALSE, NULL);  
    pMdlSrc = IoAllocateMdl((PVOID)ulAddrSrc, ulLenToCopy, FALSE, FALSE, NULL);  
    if ((NULL != pMdlSrc) && (NULL != pMdlDst))  
    {  
    __try  
        {  
            MmProbeAndLockPages(pMdlDst,UserMode,(LOCK_OPERATION)IoReadAccess);  
            MmProbeAndLockPages(pMdlSrc,KernelMode,(LOCK_OPERATION)(IoWriteAccess|IoReadAccess));  
        }  
    __except(EXCEPTION_EXECUTE_HANDLER)  
        {  
            status = GetExceptionCode();
            goto  _SafeCopy_END;  
        }  
    }  
  
    pMdlSafeDst = MmGetSystemAddressForMdlSafe(pMdlDst, NormalPagePriority);  
    pMdlSafeSrc = MmGetSystemAddressForMdlSafe(pMdlSrc, NormalPagePriority);  
    if((NULL != pMdlSafeDst) && (NULL != pMdlSafeSrc))  
    {  
        irqlCur = KeRaiseIrqlToDpcLevel();  
        memcpy(pMdlSafeDst, pMdlSafeSrc, ulLenToCopy);  
        KeLowerIrql(irqlCur);  
  
        status = STATUS_SUCCESS;  
    }  
  
_SafeCopy_END:  
    if (NULL != pMdlDst)  
    {  
        MmUnlockPages(pMdlDst);  
        IoFreeMdl(pMdlDst);  
    }  
  
    if (NULL != pMdlSrc)  
    {  
        MmUnlockPages(pMdlSrc);  
        IoFreeMdl(pMdlSrc);  
    }  
  
    return status;  
}  


void DenyLoadDriver(PVOID DriverEntry)
{
    // mov eax, C0000022
    // ret
    UCHAR fuck[]="\xB8\x22\x00\x00\xC0\xC2\x08\x00";
    VxkCopyMemory(DriverEntry,fuck,sizeof(fuck));
}

void DenyLoadExecute(PVOID EntryPoint)
{

    // xor eax, eax
    // ret
    UCHAR fuck[]="\x33\xC0\xC2\xC3";

    SafeCopyMemory((ULONG)EntryPoint, (ULONG)fuck, sizeof(fuck));

}

void DenyLoadDll(PVOID EntryPoint)
{
    // xor eax, eax
    // ret 0C
    UCHAR fuck[]="\x33\xC0\xC2\x0C\x00";
    SafeCopyMemory((ULONG)EntryPoint, (ULONG)fuck, sizeof(fuck));     
}


PDEVICE_OBJECT
IoGetBaseFileSystemDeviceObject(
    IN PFILE_OBJECT FileObject
    )

/*++

Routine Description:

    This routine returns the base (lowest-level) file system volume device
    object associated with a file.  I.e., it locates the file system w/o
    walking the attached device object list.

Arguments:

    FileObject - Supplies a pointer to the file object for which the base
        file system device object is to be returned.

Return Value:

    The function value is the lowest level volume device object associated
    w/the file.

--*/

{
    PDEVICE_OBJECT deviceObject;

    //
    // If the file object has a mounted Vpb, use its DeviceObject.
    //

    if (FileObject->Vpb != NULL && FileObject->Vpb->DeviceObject != NULL) {
        deviceObject = FileObject->Vpb->DeviceObject;

    //
    // Otherwise, if the real device has a VPB that indicates that it is
    // mounted, then use the file system device object associated with the
    // VPB.
    //

    } else if (!(FileObject->Flags & FO_DIRECT_DEVICE_OPEN) &&
               FileObject->DeviceObject->Vpb != NULL &&
               FileObject->DeviceObject->Vpb->DeviceObject != NULL) {

        deviceObject = FileObject->DeviceObject->Vpb->DeviceObject;

    //
    // Otherwise, just return the real device object.
    //

    } else {

        deviceObject = FileObject->DeviceObject;
    }

    ASSERT( deviceObject != NULL );

    //
    // Simply return the resultant file object.
    //

    return deviceObject;
}


NTSTATUS 
QueryDeviceType(PDEVICE_OBJECT DiskDeviceObject,BOOLEAN* IsUSBVolume) 
{ 
    NTSTATUS status = STATUS_UNSUCCESSFUL; 
    KEVENT WaitEvent; 
    STORAGE_PROPERTY_QUERY Query; 
    PIRP Irp; 
    UCHAR pBuffer[512]; 
    PSTORAGE_DEVICE_DESCRIPTOR Descriptor; 
    IO_STATUS_BLOCK IoStatus; 

    PAGED_CODE(); 

       // first set the query properties
   Query.PropertyId = StorageDeviceProperty;
   Query.QueryType = PropertyStandardQuery;

    // initialize the waitable event
   KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_QUERY_PROPERTY, 
        DiskDeviceObject, 
        (PVOID)&Query, sizeof(Query), (PVOID)pBuffer, 512, 
        FALSE, 
        &WaitEvent, &IoStatus); 
    if (NULL == Irp) // can't create new irp 
    { 
        DbgPrint(" BusTypeUnknown \n"); 
        return status; 
    } 

    status = IoCallDriver(DiskDeviceObject, Irp); 
    if (status == STATUS_PENDING) 
    { 
        status = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL); 
        status = IoStatus.Status; 
    } 

    if (!NT_SUCCESS(status)) 
    { 
        DbgPrint(" BusTypeUnknown \n"); 
        return status; 
    }

    Descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)pBuffer; 
    if(Descriptor->BusType == BusTypeUsb) 
    { 
        DbgPrint("GetStorageDeviceBusType SUCCEED: %d DevType:%x \n ", 
            Descriptor->BusType, DiskDeviceObject->DeviceType); 
        *IsUSBVolume = TRUE; 
    } 
    return status; 
}

BOOLEAN 
GetImageType(PVOID ImageBase, enum IMAGE_TYPE* ImageType)
{
    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PVOID pEntryPoint;
    pDOSHeader = (PIMAGE_DOS_HEADER)ImageBase;


#ifdef _AMD64_
    pNTHeader = (PIMAGE_NT_HEADERS)((ULONG64)ImageBase + pDOSHeader->e_lfanew);
#else
    pNTHeader = (PIMAGE_NT_HEADERS)((ULONG)ImageBase + pDOSHeader->e_lfanew);
#endif

    if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {

        *ImageType = IMAGE_DLL;

    } else if (pNTHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE) {

        *ImageType = IMAGE_SYS;
    } else {

        *ImageType = IMAGE_EXE;
    }

    return TRUE;
}

PVOID GetImageEntry(PVOID ImageBase)
{
    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PVOID pEntryPoint;
    pDOSHeader = (PIMAGE_DOS_HEADER)ImageBase;

#ifdef _AMD64_
    pNTHeader = (PIMAGE_NT_HEADERS)((ULONG64)ImageBase + pDOSHeader->e_lfanew);
#else
    pNTHeader = (PIMAGE_NT_HEADERS)((ULONG)ImageBase + pDOSHeader->e_lfanew);
#endif   

    switch(pNTHeader->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386: {
#ifdef _AMD64_
        pEntryPoint = (PVOID)((ULONG64)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);
#else 
        pEntryPoint = (PVOID)((ULONG)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);
#endif 
        break; }

#ifdef _AMD64_
    case IMAGE_FILE_MACHINE_AMD64: {
        pEntryPoint = (PVOID)((ULONG64)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);
        break; }
#endif

    default:
        return 0;
    }

    
    return pEntryPoint;
}


VOID LoadImageNotifyRoutine
(
    __in_opt PUNICODE_STRING  FullImageName,
    __in HANDLE  ProcessId,
    __in PIMAGE_INFO  ImageInfo
)
{
    DbgPrint("[pefilter]LoadImageNotifyRoutine %wZ\n", FullImageName);
 if (g_devobj == NULL || g_devobj->DeviceExtension == NULL) {
        return;
    }

    DEVICE_EXTENSION* devExt = (DEVICE_EXTENSION*)g_devobj->DeviceExtension;
    if (devExt->NotifyRoutine == NULL) {
        return;
    }

    PVOID pDrvEntry;
    char szFullImageName[260]={0};
    if(FullImageName!=NULL && MmIsAddressValid(FullImageName))
    {

        //判断文件类型

        enum IMAGE_TYPE FileType;
  
        if (GetImageType(ImageInfo->ImageBase, &FileType)) {

            //判断设备类型
            FILE_OBJECT* FileObject = NULL;
            DEVICE_OBJECT* DeviceObject = NULL;
            NTSTATUS    status = 0;
            BOOLEAN IsUsb = FALSE;

                //status = QueryDeviceType(DeviceObject, &IsUsb);

                enum DISK_TYPE DeviceType;
                //if (IsUsb) {
                //    DeviceType = DT_USB;
                //} else {
                    DeviceType = DT_DISK;
                //}

                UNICODE_STRING usVolumeName;
                WCHAR VolumeNameBuffer[MAX_FILE_PATH] = {0};
                RtlInitEmptyUnicodeString(&usVolumeName, VolumeNameBuffer, MAX_FILE_PATH);
                status = DosNameToVolumeName(FullImageName, &usVolumeName);
                if (NT_SUCCESS(status)) {

                    if (RtlSearchString(&usVolumeName, L"\\Device\\LanmanRedirector", FALSE) == usVolumeName.Buffer) {
                        DeviceType = DT_REMOTE;
                    } else if (RtlSearchString(&usVolumeName, L"\\Device\\Harddisk", FALSE) == usVolumeName.Buffer) {
                        DeviceType = DT_DISK;
                    } else if (RtlSearchString(&usVolumeName, L"\\Device\\CdRom", FALSE) == usVolumeName.Buffer) {
                        DeviceType = DT_CDROM;
                    } else {
                        DeviceType = DT_UNKNOWN;
                    }

                } else {
                    DeviceType = DT_REMOTE;
                }

                WCHAR DosNameBuffer[MAX_FILE_PATH] = {0};
                UNICODE_STRING usDosName = {0};
                RtlInitEmptyUnicodeString(&usDosName, DosNameBuffer, MAX_FILE_PATH);

                UNICODE_STRING* usImagePath = NULL;
                status = VolumeNameToDosName(FullImageName, &usDosName);
                if(status == STATUS_SUCCESS) {
                    usImagePath = &usDosName;
                } else {
                    usImagePath = FullImageName;
                }

                //调用回调函数
                BOOLEAN IsDeny = !devExt->NotifyRoutine((ULONG)ProcessId, 
                        usImagePath, 
                        DeviceType, 
                        FileType, devExt->Context);

                //根据回调函数， 决定是否加载
                if (IsDeny) {

                    PVOID Entry = (PVOID)GetImageEntry(ImageInfo->ImageBase);

                    switch(FileType) {
                    case IMAGE_EXE:
                        DenyLoadExecute(Entry);
                        break;

                    case IMAGE_DLL:
                        DenyLoadDll(Entry);
                        break;

                    case IMAGE_SYS:
                        DenyLoadDriver(Entry);
                        break;
                    }
                    
                } 
        
        }
    }
}


BOOLEAN
SetupImageNotify(IMAGE_ROUTINE OnNotify, VOID* Context)
{
    if (g_devobj == NULL) {
        return FALSE;
    }

    DEVICE_EXTENSION* devExt = (DEVICE_EXTENSION*)g_devobj->DeviceExtension;

    devExt->NotifyRoutine = OnNotify;
    devExt->Context = Context;

    if (OnNotify == NULL) {
        PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);
    } else {
        PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);
    }

    return TRUE;
}

#include <ntifs.h>
//#include <dsm.h>
#include <ntddstor.h>
#include <ntimage.h>
#include "pefilter.h"
#include "ntpath.h"

extern DEVICE_OBJECT* g_devobj;

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

  
NTSTATUS SafeCopyMemory(PVOID ulAddrDst, PVOID ulAddrSrc, ULONG ulLenToCopy)  
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
  
    pMdlDst = IoAllocateMdl(ulAddrDst, ulLenToCopy, FALSE, FALSE, NULL);  
    pMdlSrc = IoAllocateMdl(ulAddrSrc, ulLenToCopy, FALSE, FALSE, NULL);  
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

#ifdef _AMD64_
    UCHAR fuck[]="\xB8\x22\x00\x00\xC0\xC3";
#else
    UCHAR fuck[]="\xB8\x22\x00\x00\xC0\xC2\x08\x00";
#endif
    
    VxkCopyMemory(DriverEntry,fuck,sizeof(fuck));
}

void DenyLoadExecute(PVOID EntryPoint)
{

    // xor eax, eax
    // ret
#ifdef _AMD64_
    UCHAR fuck[]="\x33\xC0\xC3";
#else
    UCHAR fuck[]="\x33\xC0\xC3"; 
#endif
    SafeCopyMemory(EntryPoint, fuck, sizeof(fuck));
}

void DenyLoadDll(PVOID EntryPoint)
{
    // xor eax, eax
    // ret 0C
#ifdef _AMD64_
    UCHAR fuck[]="\x33\xC0\xC3";
#else
    UCHAR fuck[]="\x33\xC0\xC2\x0C\x00";
#endif
    SafeCopyMemory(EntryPoint, fuck, sizeof(fuck));     
}

/*
NTSTATUS CompletionRoutine(PDEVICE_OBJECT DeviceObject,

                                 PIRP Irp, PVOID Context)

{

  if(Irp->PendingReturned)

  {

     KeSetEvent((PRKEVENT)Context, IO_NO_INCREMENT, FALSE);

  }



  return STATUS_MORE_PROCESSING_REQUIRED;

}


NTSTATUS 
QueryDeviceType(PDEVICE_OBJECT DiskDeviceObject,BOOLEAN* IsUSBVolume) 
{ 
    NTSTATUS status = STATUS_UNSUCCESSFUL; 
    KEVENT WaitEvent; 
    
    PIRP Irp; 
    UCHAR pBuffer[512] = {0}; 
     
    IO_STATUS_BLOCK IoStatus; 

    PAGED_CODE(); 

       // first set the query properties
    STORAGE_PROPERTY_QUERY Query; 
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

    IoSetCompletionRoutine(Irp, CompletionRoutine,

                  &WaitEvent, TRUE, TRUE, TRUE);
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

    PSTORAGE_DEVICE_DESCRIPTOR Descriptor;
    Descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)pBuffer; 
    if(Descriptor->BusType == BusTypeUsb) 
    { 
        *IsUSBVolume = TRUE; 
    } 
    return status; 
}
*/


enum DISK_TYPE
QueryDiskType(FILE_OBJECT* ImageFileObject)
{
    NTSTATUS status;

    DEVICE_OBJECT* BaseFSDeviceObject = NULL;

    BaseFSDeviceObject = IoGetBaseFileSystemDeviceObject(ImageFileObject);
    if (BaseFSDeviceObject == NULL) {
        return DT_UNKNOWN;
    }

    DEVICE_OBJECT* DiskDeviceObject = NULL;
    status = IoGetDiskDeviceObject(BaseFSDeviceObject, &DiskDeviceObject);
    if (!NT_SUCCESS(status)) {

        // 如果是SMB共享，是没有Disk设备的
        if (BaseFSDeviceObject->Characteristics & FILE_REMOTE_DEVICE) {
            return DT_REMOTE;
        } else {
            return DT_UNKNOWN;
        }
    
    } else {

        if (DiskDeviceObject->Characteristics & FILE_REMOVABLE_MEDIA) {

            UNICODE_STRING usCdrom = {0};
            RtlInitUnicodeString(&usCdrom, L"\\Driver\\cdrom");

            if (DiskDeviceObject->DriverObject != NULL &&
                RtlCompareUnicodeString(&usCdrom, &DiskDeviceObject->DriverObject->DriverName, FALSE) == 0) {

                return DT_CDROM;

            } else {

                return DT_USB;    
            }
            
        } else if(DiskDeviceObject->Characteristics & FILE_READ_ONLY_DEVICE) {
            
            return DT_CDROM;

        }  else {

            return DT_DISK;
        }
    }
}


NTSTATUS
QueryFileDosName(FILE_OBJECT* ImageFileObject, UNICODE_STRING* usDosName)
{
    NTSTATUS status;

    DEVICE_OBJECT* BaseFSDeviceObject = NULL;
    BaseFSDeviceObject = IoGetBaseFileSystemDeviceObject(ImageFileObject);

    if (BaseFSDeviceObject == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    
    OBJECT_NAME_INFORMATION* ObjInfo = NULL;
    status = IoQueryFileDosDeviceName(ImageFileObject, &ObjInfo);
    
    if (NT_SUCCESS(status)) {

        // 有两种格式
        //1. \Device\HarddiskVolume2\Windows\System32\notepad.exe
        //2. C:\\Windows\System32\notepad.exe
        //如果是第1种格式， 就需要遍历A-Z所有的盘符， 直到和卷设备名称相符

        if (ObjInfo->Name.Buffer[1] == L':') {

        
            RtlCopyUnicodeString(usDosName, &ObjInfo->Name);

        } else {

            UNICODE_STRING usSymbolName = {0};
            WCHAR SymbolBuffer[16] = {L"\\??\\X:"};
            RtlInitUnicodeString(&usSymbolName, SymbolBuffer);

            for(WCHAR c = L'A' ; c < ('Z'+1); ++c ) {

                usSymbolName.Buffer[wcslen(L"\\??\\")] = c;
                
                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(
                    &oa,
                    &usSymbolName,
                    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                    NULL,NULL);
                
                HANDLE hSymbol;
                status = ZwOpenSymbolicLinkObject(
                    &hSymbol,
                    GENERIC_READ,
                    &oa);
                
                if( !NT_SUCCESS(status)){        
                    continue;
                }  

                WCHAR TargetBuffer[MAX_FILE_PATH] = {0};
                UNICODE_STRING usTarget = {0};
                RtlInitEmptyUnicodeString(&usTarget, TargetBuffer, sizeof(TargetBuffer));

                ULONG ReturnLength;
                status = ZwQuerySymbolicLinkObject(hSymbol, &usTarget, &ReturnLength);
                if( !NT_SUCCESS( status ) ) {
                    ZwClose(hSymbol);
                    hSymbol = NULL;
                    continue;
                }

                UNICODE_STRING usString = {0};
                usString.Length = usString.MaximumLength = usTarget.Length;
                usString.Buffer = ObjInfo->Name.Buffer;
                if (0 == RtlCompareUnicodeString(&usString, &usTarget, FALSE)) {

                    RtlCopyUnicodeString(usDosName, &usSymbolName);
                    RtlAppendUnicodeStringToString(usDosName, &ImageFileObject->FileName);

                    RtlRemoveUnicodeStringPrefix(usDosName, L"\\??\\");
                }

                ZwClose(hSymbol);
                hSymbol = NULL;

            }
            
        }

        ExFreePool(ObjInfo);
        ObjInfo = NULL;
    } 



    return status;
}


enum DISK_TYPE
GuessUnknownDiskType(UNICODE_STRING* usPath)
{
    NTSTATUS    status;

    UNICODE_STRING usVolumeName;
    WCHAR VolumeNameBuffer[MAX_FILE_PATH] = {0};
    RtlInitEmptyUnicodeString(&usVolumeName, VolumeNameBuffer, MAX_FILE_PATH);
    status = DosNameToVolumeName(usPath, &usVolumeName);
    if (NT_SUCCESS(status)) {

        if (RtlSearchString(&usVolumeName, L"\\Device\\LanmanRedirector", FALSE) == usVolumeName.Buffer) {

            return DT_REMOTE;

        } else if (RtlSearchString(&usVolumeName, L"\\Device\\Harddisk", FALSE) == usVolumeName.Buffer) {

            return DT_DISK;
            
        } else if (RtlSearchString(&usVolumeName, L"\\Device\\CdRom", FALSE) == usVolumeName.Buffer) {

            return DT_CDROM;

        } else {

            return DT_UNKNOWN;
        }

    } else {
        
        return DT_REMOTE;
    }

}
 
/*
enum DISK_TYPE
QueryDiskType(UNICODE_STRING* usPath)
{
    NTSTATUS    status;

    FILE_OBJECT* FileObject = NULL;
    DEVICE_OBJECT* FSDeviceObject = NULL;
    status = IoGetDeviceObjectPointer(usPath, FILE_READ_DATA | SYNCHRONIZE | DELETE, &FileObject, &FSDeviceObject);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    DEVICE_OBJECT* BaseFSDeviceObject = IoGetBaseFileSystemDeviceObject(FileObject);
    ObDereferenceObject(FileObject);
    FileObject = NULL;
    if (BaseFSDeviceObject == NULL) {
        return FALSE;
    }

    DEVICE_OBJECT* DiskDeviceObject = NULL;
    status = IoGetDiskDeviceObject(BaseFSDeviceObject, &DiskDeviceObject);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    if (DiskDeviceObject->Characteristics & FILE_REMOVABLE_MEDIA) {
        return TRUE;
    } else {
        return FALSE;
    }
}
*/

BOOLEAN 
GetImageType(PVOID ImageBase, enum IMAGE_TYPE* ImageType)
{
    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PVOID pEntryPoint;
    pDOSHeader = (PIMAGE_DOS_HEADER)ImageBase;


    pNTHeader = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + pDOSHeader->e_lfanew);

    switch(pNTHeader->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386: {

        if (pNTHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE) {

            *ImageType = IMAGE_PE32_SYS;

        } else if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {

            *ImageType = IMAGE_PE32_DLL;

        } else {

            *ImageType = IMAGE_PE32_EXE;
        }
        break; }
    case IMAGE_FILE_MACHINE_AMD64: {

        if (pNTHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE) {

            *ImageType = IMAGE_PE64_SYS;

        } else if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {

            *ImageType = IMAGE_PE64_DLL;

        } else {

            *ImageType = IMAGE_PE64_EXE;
        }
        break; }

    default:
        return FALSE;
        break;
    }

    return TRUE;
}

PVOID GetImageEntry(PVOID ImageBase)
{
    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PVOID pEntryPoint;
    pDOSHeader = (PIMAGE_DOS_HEADER)ImageBase;

    pNTHeader = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + pDOSHeader->e_lfanew);

    switch(pNTHeader->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386: {

        pEntryPoint = (PVOID)((PCHAR)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);

        break; }

#ifdef _AMD64_
    case IMAGE_FILE_MACHINE_AMD64: {
        pEntryPoint = (PVOID)((PCHAR)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);
        break; }
#endif

    default:
        return 0;
    }

    
    return pEntryPoint;
}

typedef enum WIN_VER_DETAIL {
    WINDOWS_VERSION_UNKNOWN,       // 0
    WINDOWS_VERSION_2K,
    WINDOWS_VERSION_XP,
    WINDOWS_VERSION_2K3,
    WINDOWS_VERSION_2K3_SP1_SP2,
    WINDOWS_VERSION_VISTA,
    WINDOWS_VERSION_7,
} WIN_VER_DETAIL;

typedef NTSTATUS (NTAPI * PFN_RtlGetVersion)(OUT PRTL_OSVERSIONINFOW lpVersionInformation);

WIN_VER_DETAIL GetWindowsVersion()
{
    RTL_OSVERSIONINFOEXW OSVersionInfoEx = { sizeof(RTL_OSVERSIONINFOEXW) };
    PFN_RtlGetVersion pfnRtlGetVersion = NULL;

    UNICODE_STRING usFuncName = {0};
    RtlInitUnicodeString(&usFuncName, L"RtlGetVersion"); 
    pfnRtlGetVersion = (PFN_RtlGetVersion)MmGetSystemRoutineAddress(&usFuncName); 
    if ( NULL == pfnRtlGetVersion) {
        PsGetVersion(&OSVersionInfoEx.dwMajorVersion,&OSVersionInfoEx.dwMinorVersion,
             &OSVersionInfoEx.dwBuildNumber,NULL);
    } else {
        pfnRtlGetVersion((PRTL_OSVERSIONINFOW)&OSVersionInfoEx);
    }

    if (5 == OSVersionInfoEx.dwMajorVersion) {

        switch (OSVersionInfoEx.dwMinorVersion){
        case 0:
            return WINDOWS_VERSION_2K;
        case 1:
            return WINDOWS_VERSION_XP;
        case 2:
            if (0 == OSVersionInfoEx.wServicePackMajor)
                return WINDOWS_VERSION_2K3;
            else
                 return WINDOWS_VERSION_2K3_SP1_SP2;
        }
    }

    if (6 == OSVersionInfoEx.dwMajorVersion) {

        switch (OSVersionInfoEx.dwMinorVersion) {
        case 0:
            return WINDOWS_VERSION_VISTA;
        case 1:
            return WINDOWS_VERSION_7;
        default:
            return WINDOWS_VERSION_7;
        }
    }
    return WINDOWS_VERSION_UNKNOWN;
}


VOID LoadImageNotifyRoutine
(
    __in_opt PUNICODE_STRING  FullImageName,
    __in HANDLE  ProcessId,
    __in PIMAGE_INFO  ImageInfo
)
{
    DbgPrint("[pefilter]LoadImageNotifyRoutine %wZ\n", FullImageName);

    if (ProcessId == 0) {
        DbgPrint("[pefilter]Found Driver\n");        
    }

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

            
            NTSTATUS    status = 0;

            //判断设备类型
            FILE_OBJECT* ImageFileObject = NULL;
            WIN_VER_DETAIL WinVer = GetWindowsVersion();
            if (WinVer >= WINDOWS_VERSION_VISTA ) {
                if (ImageInfo->ExtendedInfoPresent) {
                    IMAGE_INFO_EX* ImageInfoEx = 
                        CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
                    ImageFileObject = ImageInfoEx->FileObject;
                }
            } else {

                // XP环境下， 就需要自己获取FILE_OBJECT对象了
                OBJECT_ATTRIBUTES oa = {0};
                InitializeObjectAttributes (&oa, FullImageName, 
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                IO_STATUS_BLOCK iosb = {0};
                HANDLE  FileHandle = NULL;
                status = ZwOpenFile (&FileHandle, 
                        GENERIC_READ | SYNCHRONIZE, 
                        &oa, &iosb, 
                        FILE_SHARE_READ|FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
                if (NT_SUCCESS(status)) {
                     status = ObReferenceObjectByHandle(FileHandle,
                                                0,
                                                *IoFileObjectType,
                                                KernelMode,
                                                (PVOID *)&ImageFileObject,
                                                NULL );
                    ZwClose(FileHandle);
                    FileHandle = NULL;
                }

            }

            if (ImageFileObject != NULL) {

                enum DISK_TYPE DeviceType;
                DeviceType = QueryDiskType(ImageFileObject);
                if (DeviceType == DT_UNKNOWN) {
                    DeviceType = GuessUnknownDiskType(FullImageName);
                }

                WCHAR DosNameBuffer[MAX_FILE_PATH] = {0};
                UNICODE_STRING usDosName = {0};
                RtlInitEmptyUnicodeString(&usDosName, DosNameBuffer, sizeof(DosNameBuffer));

                UNICODE_STRING* usImagePath = NULL;
                //status = VolumeNameToDosName(FullImageName, &usDosName);
                status = QueryFileDosName(ImageFileObject, &usDosName);
                if(status == STATUS_SUCCESS) {
                    usImagePath = &usDosName;
                } else {
                    usImagePath = FullImageName;
                }

                if (WinVer < WINDOWS_VERSION_VISTA ) {
                    ObDereferenceObject(ImageFileObject);
                    ImageFileObject = NULL;
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
                    case IMAGE_PE32_EXE:
                    case IMAGE_PE64_EXE:
                        DenyLoadExecute(Entry);
                        break;

                    case IMAGE_PE32_DLL:
                    case IMAGE_PE64_DLL:
                        DenyLoadDll(Entry);
                        break;

                    case IMAGE_PE32_SYS:
                    case IMAGE_PE64_SYS:
                        DenyLoadDriver(Entry);
                        break;
                    }
                    
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
#ifndef PE_FILTER_KIMZHANG_HEADER
#define PE_FILTER_KIMZHANG_HEADER

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

enum DISK_TYPE
{
	DT_UNKNOWN = 0,
    DT_USB,
    DT_REMOTE,
    DT_DISK,
    DT_CDROM,
};

enum IMAGE_TYPE
{
    IMAGE_EXE,
    IMAGE_DLL,
    IMAGE_SYS,
};

typedef 
BOOLEAN
(*IMAGE_ROUTINE)(ULONG, UNICODE_STRING*, enum DISK_TYPE, enum IMAGE_TYPE, VOID*);

typedef struct _DEVICE_EXTENSION
{
    IMAGE_ROUTINE   NotifyRoutine;
    PVOID Context;
}DEVICE_EXTENSION;

BOOLEAN
SetupImageNotify(IMAGE_ROUTINE OnNotify, VOID* Context);

#ifdef __cplusplus
};
#endif

#endif
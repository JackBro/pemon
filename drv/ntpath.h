#ifndef PATHLINK_KIMZHANG_HEADER
#define PATHLINK_KIMZHANG_HEADER

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#define MAX_FILE_PATH		270

WCHAR* 
RtlSearchString( UNICODE_STRING* us, WCHAR* str, BOOLEAN bCaseSensitive);

VOID 
RtlRemoveUnicodeStringPrefix(UNICODE_STRING* us, const WCHAR* Prefix);

NTSTATUS  
VolumeNameToDosName(UNICODE_STRING* usVolumeName, UNICODE_STRING* usDosName);

NTSTATUS 
DosNameToVolumeName(UNICODE_STRING* usDosName, UNICODE_STRING* usVolumeName);

#ifdef __cplusplus
};
#endif

#endif
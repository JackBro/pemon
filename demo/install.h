#ifndef _IMAGEHOLD_INSTALL_HEADER_
#define _IMAGEHOLD_INSTALL_HEADER_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02

BOOLEAN
ManageDriver(
    __in LPCTSTR  DriverName,
    __in LPCTSTR  ServiceName,
    __in USHORT   Function
    );

BOOLEAN
SetupDriverName(
    __inout_bcount_full(BufferLength) PCHAR DriverLocation,
    __in ULONG BufferLength
    );

BOOL OpenDevice( IN LPCTSTR DriverName, HANDLE * lphDevice);

#ifdef __cplusplus
};
#endif

#endif
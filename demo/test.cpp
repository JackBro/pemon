#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winioctl.h>
#include "install.h"
#include "../include/public.h"

int 
main(int argc, char* argv[])
{

    HANDLE  hDevice = NULL;

    TCHAR driverLocation[MAX_PATH];
  //
    // open the device
    //

    
    if (!OpenDevice(DRIVER_NAME, &hDevice)) {

        DWORD errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {

            printf("CreateFile failed!  ERROR_FILE_NOT_FOUND = %d\n", errNum);

            return FALSE;
        }

        //
        // The driver is not started yet so let us the install driver.
        // First setup full path to driver name.
        //
        
        if (!SetupDriverName(driverLocation, sizeof(driverLocation) )) {

            return FALSE;
        }

        if (!ManageDriver(DRIVER_NAME,
                          driverLocation,
                          DRIVER_FUNC_INSTALL
                          )) {

            printf("Unable to install driver. \n");

            //
            // Error - remove driver.
            //

            ManageDriver(DRIVER_NAME,
                         driverLocation,
                         DRIVER_FUNC_REMOVE
                         );

            return FALSE;
        }

        //
        // Now open the device again.
        //
        if (!OpenDevice(DRIVER_NAME, &hDevice)){
            printf ( "Error: CreatFile Failed : %d\n", GetLastError());
            return FALSE;
        }

    }

    while( true) {

        printf("PEMonitor Demo :\n");
        printf("-----------------------------------------\n");
        printf("0. Exit\n");
        printf("1. Deny Notepad.exe\n");
        printf("2. Deny FFI's unarc.dll\n");
        printf("3. Deny Procmon's Driver(PROCMONxx.SYS)\n");
        printf("4. Deny Applications from CDROM\n");
        printf("5. Deny Applications from USB\n");
        printf("6. Deny Applications from SMB Share\n");
        printf("-----------------------------------------\n");
        printf("Please Press Number: ");

        int response = 0;
        if (1 != scanf("%d", &response) ) {
            continue;
        }

        DWORD ioctl;

        if (response == 0) {
            break;
        } else if (response == 1) {
            ioctl = IOCTL_DEMO_DENY_NOTEPAD;
        } else if (response == 2) {
            ioctl = IOCTL_DEMO_DENY_FFI;
        } else if (response == 3) {
            ioctl = IOCTL_DEMO_DENY_PROCMON;
        } else if (response == 4) {
            ioctl = IOCTL_DEMO_DENY_CDROM;
        } else if (response == 5) {
            ioctl = IOCTL_DEMO_DENY_USB;
        } else if (response == 6) {
            ioctl = IOCTL_DEMO_DENY_SMB;
        } else {
            continue;
        }

        BOOL bStatus = FALSE;
        DWORD ulReturnedLength = 0;
        bStatus = DeviceIoControl(
                        hDevice,            // Handle to device
                        ioctl,   		// IO Control code
                        NULL,         		// Input Buffer to driver.
                        0,  				// Length of input buffer in bytes.
                        NULL,            	// Output Buffer from driver.
                        0,     				// Length of output buffer in bytes.
                        &ulReturnedLength,  // Bytes placed in buffer.
                        NULL                // synchronous call
                        );

        if ( !bStatus ) {
            printf("Ioctl failed with code %d\n", GetLastError() );
            return 0;
        }

        printf("PEMonitor Setup Success!\n");

        printf("Now, System is working, if you want to exit, please close console directly!");
        printf("PEMonitor's driver will be uninstall automatically.");
        Sleep(INFINITE);
        break;

    }
    //
    // close the handle to the device.
    //
    CloseHandle(hDevice);

    //
    // Unload the driver.  Ignore any errors.
    //

    ManageDriver(DRIVER_NAME, driverLocation, DRIVER_FUNC_REMOVE);

    return TRUE;
}
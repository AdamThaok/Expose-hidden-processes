/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KernelDriver,
    0x791b37c4,0x2906,0x41e0,0xb9,0x80,0x69,0xeb,0x45,0xec,0x7a,0xeb);
// {791b37c4-2906-41e0-b980-69eb45ec7aeb}

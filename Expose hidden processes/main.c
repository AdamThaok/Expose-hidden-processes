#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Define IOCTL codes and structures matching the driver
#define IOCTL_GET_PROCESSES_STANDARD    0x22000C
#define IOCTL_GET_PROCESSES_EPROCESS    0x220010
#define IOCTL_GET_PROCESSES_THREADS     0x220014
#define IOCTL_GET_PROCESSES_HANDLES     0x220018
#define IOCTL_CROSS_REFERENCE_ALL       0x22001C

#define MAX_PROCESSES 2048

typedef struct _ENHANCED_PROCESS_INFO {
    ULONG ProcessId;
    CHAR ImageName[16];
    ULONG ParentProcessId;
    ULONG ThreadCount;
    ULONG HandleCount;
    BOOLEAN FoundInStandardEnum;
    BOOLEAN FoundInEProcessWalk;
    BOOLEAN FoundInThreadEnum;
    BOOLEAN FoundInHandleEnum;
    BOOLEAN IsSuspicious;
    ULONG DetectionFlags;
} ENHANCED_PROCESS_INFO, * PENHANCED_PROCESS_INFO;

void PrintProcessInfo(const char* method, PENHANCED_PROCESS_INFO info, ULONG count);
void PrintCrossReferenceResults(PENHANCED_PROCESS_INFO info, ULONG count);

int main() {
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\AdvancedProcessDetector",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device. Error: %u\n", GetLastError());
        return 1;
    }

    // Buffer for process information
    ENHANCED_PROCESS_INFO processInfo[MAX_PROCESSES];
    DWORD bytesReturned;
    BOOL result;

    // Standard Enumeration
    result = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESSES_STANDARD,
        NULL,
        0,
        processInfo,
        sizeof(processInfo),
        &bytesReturned,
        NULL
    );

    if (result) {
        PrintProcessInfo("STANDARD ENUMERATION", processInfo, bytesReturned / sizeof(ENHANCED_PROCESS_INFO));
    }
    else {
        printf("Standard enumeration failed. Error: %u\n", GetLastError());
    }

    // EPROCESS Walk
    result = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESSES_EPROCESS,
        NULL,
        0,
        processInfo,
        sizeof(processInfo),
        &bytesReturned,
        NULL
    );

    if (result) {
        PrintProcessInfo("EPROCESS WALK", processInfo, bytesReturned / sizeof(ENHANCED_PROCESS_INFO));
    }
    else {
        printf("EPROCESS walk failed. Error: %u\n", GetLastError());
    }

    // Thread-Based Detection
    result = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESSES_THREADS,
        NULL,
        0,
        processInfo,
        sizeof(processInfo),
        &bytesReturned,
        NULL
    );

    if (result) {
        PrintProcessInfo("THREAD ANALYSIS", processInfo, bytesReturned / sizeof(ENHANCED_PROCESS_INFO));
    }
    else {
        printf("Thread analysis failed. Error: %u\n", GetLastError());
    }

    // Handle-Based Detection
    result = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESSES_HANDLES,
        NULL,
        0,
        processInfo,
        sizeof(processInfo),
        &bytesReturned,
        NULL
    );

    if (result) {
        PrintProcessInfo("HANDLE ANALYSIS", processInfo, bytesReturned / sizeof(ENHANCED_PROCESS_INFO));
    }
    else {
        printf("Handle analysis failed. Error: %u\n", GetLastError());
    }

    // Cross-Reference Analysis
    result = DeviceIoControl(
        hDevice,
        IOCTL_CROSS_REFERENCE_ALL,
        NULL,
        0,
        processInfo,
        sizeof(processInfo),
        &bytesReturned,
        NULL
    );

    if (result) {
        PrintCrossReferenceResults(processInfo, bytesReturned / sizeof(ENHANCED_PROCESS_INFO));
    }
    else {
        printf("Cross-reference failed. Error: %u\n", GetLastError());
    }

    CloseHandle(hDevice);
    return 0;
}

void PrintProcessInfo(const char* method, PENHANCED_PROCESS_INFO info, ULONG count) {
    printf("\n===== %s (%d processes) =====\n", method, count);
    printf("%-8s %-16s %-8s %-8s %-8s\n", "PID", "Name", "PPID", "Threads", "Handles");

    for (ULONG i = 0; i < count; i++) {
        printf("%-8u %-16s %-8u %-8u %-8u\n",
            info[i].ProcessId,
            info[i].ImageName,
            info[i].ParentProcessId,
            info[i].ThreadCount,
            info[i].HandleCount
        );
    }
}

void PrintCrossReferenceResults(PENHANCED_PROCESS_INFO info, ULONG count) {
    printf("\n===== CROSS-REFERENCE ANALYSIS (%d processes) =====\n", count);
    printf("%-8s %-16s %-8s %-8s %-8s %-5s %-5s %-5s %-5s %s\n",
        "PID", "Name", "PPID", "Threads", "Handles",
        "Std", "EProc", "Thrd", "Hndl", "Flags"
    );

    for (ULONG i = 0; i < count; i++) {
        printf("%-8u %-16s %-8u %-8u %-8u "
            "%-5s %-5s %-5s %-5s ",
            info[i].ProcessId,
            info[i].ImageName,
            info[i].ParentProcessId,
            info[i].ThreadCount,
            info[i].HandleCount,
            info[i].FoundInStandardEnum ? "Yes" : "No",
            info[i].FoundInEProcessWalk ? "Yes" : "No",
            info[i].FoundInThreadEnum ? "Yes" : "No",
            info[i].FoundInHandleEnum ? "Yes" : "No"
        );

        // Print detection flags
        if (info[i].DetectionFlags) {
            if (info[i].DetectionFlags & 0x01) printf("STD ");
            if (info[i].DetectionFlags & 0x02) printf("EPROC ");
            if (info[i].DetectionFlags & 0x04) printf("THREAD ");
            if (info[i].DetectionFlags & 0x08) printf("HANDLE ");
            if (info[i].DetectionFlags & 0x10) printf("PID_GAP ");
            if (info[i].DetectionFlags & 0x20) printf("MEM ");
        }
        else {
            printf("None");
        }

        // Highlight suspicious processes
        if (info[i].IsSuspicious) {
            printf(" [SUSPICIOUS]");
        }

        printf("\n");
    }
}
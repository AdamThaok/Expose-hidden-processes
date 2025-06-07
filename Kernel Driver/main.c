#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

#define DEVICE_NAME L"\\Device\\AdvancedProcessDetector"
#define SYMLINK_NAME L"\\DosDevices\\AdvancedProcessDetector"

// IOCTL codes
#define IOCTL_GET_PROCESSES_STANDARD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESSES_EPROCESS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESSES_THREADS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESSES_HANDLES     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CROSS_REFERENCE_ALL       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_PROCESSES 2048

// Enhanced process information structure
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

// Add these structure definitions after your includes and before the existing typedefs

// Undocumented system information structures
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// Forward declarations for ZwQuerySystemInformation
NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation OPTIONAL,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

// Detection flags
#define DETECTION_STANDARD_ENUM     0x01
#define DETECTION_EPROCESS_WALK     0x02
#define DETECTION_THREAD_ANALYSIS   0x04
#define DETECTION_HANDLE_ANALYSIS   0x08
#define DETECTION_PID_GAP          0x10
#define DETECTION_MEMORY_SCAN      0x20

// EPROCESS field offsets (Windows 10/11 21H2)
#define EPROCESS_LINKS_OFFSET       0x448
#define EPROCESS_PID_OFFSET         0x440
#define EPROCESS_NAME_OFFSET        0x5a8
#define EPROCESS_THREAD_LIST_OFFSET 0x5e0
#define EPROCESS_PARENT_PID_OFFSET  0x3b0

// System information classes
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;

// System handle table entry structures
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

// Function declarations
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Detection method implementations
NTSTATUS StandardProcessEnumeration(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount);
NTSTATUS EProcessWalkDetection(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount);
NTSTATUS ThreadBasedDetection(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount);
NTSTATUS HandleBasedDetection(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount);
NTSTATUS CrossReferenceAnalysis(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount);

// Helper functions
PEPROCESS GetNextProcess(PEPROCESS CurrentProcess);
ULONG GetProcessIdFromEProcess(PEPROCESS Process);
PCHAR GetProcessNameFromEProcess(PEPROCESS Process);
ULONG GetParentProcessIdFromEProcess(PEPROCESS Process);
ULONG GetThreadCountFromEProcess(PEPROCESS Process);
BOOLEAN IsValidEProcess(PEPROCESS Process);
NTSTATUS GetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass, PVOID* Buffer, PULONG BufferSize);
NTSTATUS GetSystemThreadInformation(PVOID* ThreadInfo, PULONG BufferSize);
NTSTATUS GetSystemHandleInformation(PVOID* HandleInfo, PULONG BufferSize);
ULONG FindPidGaps(PENHANCED_PROCESS_INFO ProcessList, ULONG Count);
VOID AddDetectionFlag(PENHANCED_PROCESS_INFO ProcessList, ULONG Count, ULONG Pid, ULONG Flag);

// Global variables
PDEVICE_OBJECT g_DeviceObject = NULL;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING deviceName, symbolicLink;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLink, SYMLINK_NAME);

    // Create device
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    // Create symbolic link
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set up driver routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
    DriverObject->DriverUnload = DriverUnload;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("Advanced Process Detector loaded\n");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLink;
    RtlInitUnicodeString(&symbolicLink, SYMLINK_NAME);

    IoDeleteSymbolicLink(&symbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("Advanced Process Detector unloaded\n");
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outputBufferLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG information = 0;

    if (outputBufferLength < sizeof(ENHANCED_PROCESS_INFO) * MAX_PROCESSES) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ULONG processCount = 0;
    PENHANCED_PROCESS_INFO processList = (PENHANCED_PROCESS_INFO)outputBuffer;

    switch (ioControlCode) {
    case IOCTL_GET_PROCESSES_STANDARD:
        status = StandardProcessEnumeration(processList, &processCount);
        break;

    case IOCTL_GET_PROCESSES_EPROCESS:
        status = EProcessWalkDetection(processList, &processCount);
        break;

    case IOCTL_GET_PROCESSES_THREADS:
        status = ThreadBasedDetection(processList, &processCount);
        break;

    case IOCTL_GET_PROCESSES_HANDLES:
        status = HandleBasedDetection(processList, &processCount);
        break;

    case IOCTL_CROSS_REFERENCE_ALL:
        status = CrossReferenceAnalysis(processList, &processCount);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    if (NT_SUCCESS(status)) {
        information = processCount * sizeof(ENHANCED_PROCESS_INFO);
    }

cleanup:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS StandardProcessEnumeration(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount)
{
    NTSTATUS status;
    PVOID processInfo = NULL;
    ULONG bufferSize = 0;
    ULONG count = 0;

    // Get process information
    status = GetSystemInformation(SystemProcessInformation, &processInfo, &bufferSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)processInfo;

        while (current && count < MAX_PROCESSES) {
            ULONG pid = (ULONG)(ULONG_PTR)current->UniqueProcessId;

            if (pid != 0) {
                ProcessList[count].ProcessId = pid;
                ProcessList[count].ThreadCount = current->NumberOfThreads;
                ProcessList[count].DetectionFlags = DETECTION_STANDARD_ENUM;
                ProcessList[count].FoundInStandardEnum = TRUE;

                // Copy process name
                if (current->ImageName.Buffer && current->ImageName.Length > 0) {
                    ANSI_STRING ansiName;
                    UNICODE_STRING uniName = current->ImageName;

                    RtlUnicodeStringToAnsiString(&ansiName, &uniName, TRUE);
                    RtlStringCbCopyNA(ProcessList[count].ImageName, sizeof(ProcessList[count].ImageName),
                        ansiName.Buffer, min(ansiName.Length, 15));
                    RtlFreeAnsiString(&ansiName);
                }
                else {
                    RtlStringCbCopyA(ProcessList[count].ImageName, sizeof(ProcessList[count].ImageName), "System");
                }

                count++;
            }

            if (current->NextEntryOffset == 0) break;
            current = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)current + current->NextEntryOffset);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Exception during standard enumeration: 0x%X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }

    if (processInfo) {
        ExFreePool(processInfo);
    }

    *ProcessCount = count;
    return status;
}

NTSTATUS EProcessWalkDetection(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount)
{
    ULONG count = 0;
    PEPROCESS systemProcess = PsInitialSystemProcess;
    PEPROCESS currentProcess = systemProcess;

    __try {
        do {
            if (IsValidEProcess(currentProcess)) {
                ULONG pid = GetProcessIdFromEProcess(currentProcess);

                if (pid != 0 && count < MAX_PROCESSES) {
                    ProcessList[count].ProcessId = pid;
                    ProcessList[count].ParentProcessId = GetParentProcessIdFromEProcess(currentProcess);
                    ProcessList[count].ThreadCount = GetThreadCountFromEProcess(currentProcess);
                    ProcessList[count].DetectionFlags = DETECTION_EPROCESS_WALK;
                    ProcessList[count].FoundInEProcessWalk = TRUE;

                    // Get process name
                    PCHAR imageName = GetProcessNameFromEProcess(currentProcess);
                    if (imageName) {
                        RtlCopyMemory(ProcessList[count].ImageName, imageName,
                            min(strlen(imageName), 15));
                        ProcessList[count].ImageName[15] = '\0';
                    }
                    else {
                        RtlStringCbCopyA(ProcessList[count].ImageName, sizeof(ProcessList[count].ImageName), "Unknown");
                    }

                    count++;
                }
            }

            currentProcess = GetNextProcess(currentProcess);

        } while (currentProcess != systemProcess && currentProcess != NULL && count < MAX_PROCESSES);

        // Add PID gap detection flags
        ULONG gapCount = FindPidGaps(ProcessList, count);
        DbgPrint("EPROCESS walk found %d processes, %d PID gaps detected\n", count, gapCount);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Exception during EPROCESS walk: 0x%X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }

    *ProcessCount = count;
    return STATUS_SUCCESS;
}

NTSTATUS ThreadBasedDetection(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount)
{
    NTSTATUS status;
    PVOID threadInfo = NULL;
    ULONG bufferSize = 0;
    ULONG count = 0;

    // Get thread information
    status = GetSystemThreadInformation(&threadInfo, &bufferSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)threadInfo;

        while (processInfo && count < MAX_PROCESSES) {
            ULONG pid = HandleToUlong(processInfo->UniqueProcessId);

            if (pid != 0) {
                ProcessList[count].ProcessId = pid;
                ProcessList[count].ThreadCount = processInfo->NumberOfThreads;
                ProcessList[count].DetectionFlags = DETECTION_THREAD_ANALYSIS;
                ProcessList[count].FoundInThreadEnum = TRUE;

                // Copy process name
                if (processInfo->ImageName.Length > 0 && processInfo->ImageName.Buffer) {
                    ANSI_STRING ansiName;
                    UNICODE_STRING uniName = processInfo->ImageName;

                    RtlUnicodeStringToAnsiString(&ansiName, &uniName, TRUE);
                    RtlStringCbCopyNA(ProcessList[count].ImageName, sizeof(ProcessList[count].ImageName),
                        ansiName.Buffer, min(ansiName.Length, 15));
                    RtlFreeAnsiString(&ansiName);
                }
                else {
                    RtlStringCbCopyA(ProcessList[count].ImageName, sizeof(ProcessList[count].ImageName), "System");
                }

                count++;
            }

            if (processInfo->NextEntryOffset == 0) break;
            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Exception during thread analysis: 0x%X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }

    if (threadInfo) {
        ExFreePool(threadInfo);
    }

    *ProcessCount = count;
    return status;
}

NTSTATUS HandleBasedDetection(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount)
{
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG bufferSize = 0;
    ULONG count = 0;
    ULONG pidCounts[65536] = { 0 };  // Track handle counts per PID

    // Get handle information
    status = GetSystemHandleInformation(&handleInfo, &bufferSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        // First pass: count handles per process
        for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
            ULONG pid = (ULONG)handleInfo->Handles[i].UniqueProcessId;
            if (pid < 65536) {
                pidCounts[pid]++;
            }
        }

        // Second pass: create process entries
        for (ULONG i = 0; i < 65536 && count < MAX_PROCESSES; i++) {
            if (pidCounts[i] > 0) {
                ProcessList[count].ProcessId = i;
                ProcessList[count].HandleCount = pidCounts[i];
                ProcessList[count].DetectionFlags = DETECTION_HANDLE_ANALYSIS;
                ProcessList[count].FoundInHandleEnum = TRUE;

                // Try to get process name
                PEPROCESS process;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)i, &process))) {
                    PCHAR imageName = GetProcessNameFromEProcess(process);
                    if (imageName) {
                        RtlStringCbCopyNA(ProcessList[count].ImageName, sizeof(ProcessList[count].ImageName),
                            imageName, min(strlen(imageName), 15));
                    }
                    ObDereferenceObject(process);
                }

                if (ProcessList[count].ImageName[0] == '\0') {
                    RtlStringCbPrintfA(ProcessList[count].ImageName, sizeof(ProcessList[count].ImageName), "PID:%d", i);
                }

                count++;
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Exception during handle analysis: 0x%X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }

    if (handleInfo) {
        ExFreePool(handleInfo);
    }

    *ProcessCount = count;
    return status;
}

NTSTATUS CrossReferenceAnalysis(PENHANCED_PROCESS_INFO ProcessList, PULONG ProcessCount)
{
    NTSTATUS status = STATUS_SUCCESS;
    ENHANCED_PROCESS_INFO standardList[MAX_PROCESSES] = { 0 };
    ENHANCED_PROCESS_INFO eprocessList[MAX_PROCESSES] = { 0 };
    ENHANCED_PROCESS_INFO threadList[MAX_PROCESSES] = { 0 };
    ENHANCED_PROCESS_INFO handleList[MAX_PROCESSES] = { 0 };
    ULONG standardCount = 0, eprocessCount = 0, threadCount = 0, handleCount = 0;
    ULONG finalCount = 0;

    // Collect data from all detection methods
    StandardProcessEnumeration(standardList, &standardCount);
    EProcessWalkDetection(eprocessList, &eprocessCount);
    ThreadBasedDetection(threadList, &threadCount);
    HandleBasedDetection(handleList, &handleCount);

    // Cross-reference all findings using EPROCESS as ground truth
    for (ULONG i = 0; i < eprocessCount && finalCount < MAX_PROCESSES; i++) {
        ULONG pid = eprocessList[i].ProcessId;

        // Copy base information from EPROCESS walk
        RtlCopyMemory(&ProcessList[finalCount], &eprocessList[i], sizeof(ENHANCED_PROCESS_INFO));

        // Reset flags
        ProcessList[finalCount].FoundInStandardEnum = FALSE;
        ProcessList[finalCount].FoundInThreadEnum = FALSE;
        ProcessList[finalCount].FoundInHandleEnum = FALSE;
        ProcessList[finalCount].IsSuspicious = FALSE;

        // Check standard enumeration
        for (ULONG j = 0; j < standardCount; j++) {
            if (standardList[j].ProcessId == pid) {
                ProcessList[finalCount].FoundInStandardEnum = TRUE;
                ProcessList[finalCount].DetectionFlags |= DETECTION_STANDARD_ENUM;
                break;
            }
        }

        // Check thread enumeration
        for (ULONG j = 0; j < threadCount; j++) {
            if (threadList[j].ProcessId == pid) {
                ProcessList[finalCount].FoundInThreadEnum = TRUE;
                ProcessList[finalCount].DetectionFlags |= DETECTION_THREAD_ANALYSIS;
                break;
            }
        }

        // Check handle enumeration
        for (ULONG j = 0; j < handleCount; j++) {
            if (handleList[j].ProcessId == pid) {
                ProcessList[finalCount].FoundInHandleEnum = TRUE;
                ProcessList[finalCount].DetectionFlags |= DETECTION_HANDLE_ANALYSIS;
                ProcessList[finalCount].HandleCount = handleList[j].HandleCount;
                break;
            }
        }

        // Mark as suspicious if hidden from any method
        if (!ProcessList[finalCount].FoundInStandardEnum ||
            !ProcessList[finalCount].FoundInThreadEnum ||
            !ProcessList[finalCount].FoundInHandleEnum) {
            ProcessList[finalCount].IsSuspicious = TRUE;
        }

        // Add PID gap detection if applicable
        if (ProcessList[finalCount].DetectionFlags & DETECTION_PID_GAP) {
            ProcessList[finalCount].DetectionFlags |= DETECTION_PID_GAP;
        }

        finalCount++;
    }

    *ProcessCount = finalCount;
    return status;
}

// Helper function implementations
PEPROCESS GetNextProcess(PEPROCESS CurrentProcess)
{
    __try {
        if (!CurrentProcess || !MmIsAddressValid(CurrentProcess))
            return NULL;

        PLIST_ENTRY listEntry = (PLIST_ENTRY)((PUCHAR)CurrentProcess + EPROCESS_LINKS_OFFSET);
        if (!MmIsAddressValid(listEntry) || !MmIsAddressValid(listEntry->Flink))
            return NULL;

        PLIST_ENTRY nextEntry = listEntry->Flink;
        if ((ULONG_PTR)nextEntry < 0x10000)  // Basic sanity check
            return NULL;

        return (PEPROCESS)((PUCHAR)nextEntry - EPROCESS_LINKS_OFFSET);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

ULONG GetProcessIdFromEProcess(PEPROCESS Process)
{
    __try {
        if (!Process || !MmIsAddressValid(Process))
            return 0;

        PULONG pidPtr = (PULONG)((PUCHAR)Process + EPROCESS_PID_OFFSET);
        if (!MmIsAddressValid(pidPtr))
            return 0;

        return *pidPtr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

ULONG GetParentProcessIdFromEProcess(PEPROCESS Process)
{
    __try {
        if (!Process || !MmIsAddressValid(Process))
            return 0;

        PULONG ppidPtr = (PULONG)((PUCHAR)Process + EPROCESS_PARENT_PID_OFFSET);
        if (!MmIsAddressValid(ppidPtr))
            return 0;

        return *ppidPtr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

PCHAR GetProcessNameFromEProcess(PEPROCESS Process)
{
    __try {
        if (!Process || !MmIsAddressValid(Process))
            return NULL;

        PCHAR namePtr = (PCHAR)((PUCHAR)Process + EPROCESS_NAME_OFFSET);
        if (!MmIsAddressValid(namePtr))
            return NULL;

        return namePtr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

BOOLEAN IsValidEProcess(PEPROCESS Process)
{
    __try {
        if (!Process || (ULONG_PTR)Process < 0x10000)
            return FALSE;

        if (!MmIsAddressValid(Process))
            return FALSE;

        ULONG pid = GetProcessIdFromEProcess(Process);
        return (pid > 0 && pid < 65536);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

ULONG GetThreadCountFromEProcess(PEPROCESS Process)
{
    __try {
        if (!Process || !MmIsAddressValid(Process))
            return 0;

        PLIST_ENTRY threadListHead = (PLIST_ENTRY)((PUCHAR)Process + EPROCESS_THREAD_LIST_OFFSET);
        if (!threadListHead || !MmIsAddressValid(threadListHead))
            return 0;

        PLIST_ENTRY currentEntry = threadListHead->Flink;
        ULONG count = 0;

        while (currentEntry != threadListHead && count < 1000) { // Safety limit
            if (!MmIsAddressValid(currentEntry) || (ULONG_PTR)currentEntry < 0x10000)
                break;

            count++;
            currentEntry = currentEntry->Flink;
        }

        return count;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

NTSTATUS GetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass, PVOID* Buffer, PULONG BufferSize)
{
    NTSTATUS status;
    PVOID infoBuffer = NULL;
    ULONG size = 0;

    // Get required buffer size
    ZwQuerySystemInformation(InfoClass, NULL, 0, &size);

    while (size > 0) {
        infoBuffer = ExAllocatePool(PagedPool, size);
        if (!infoBuffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(InfoClass, infoBuffer, size, NULL);
        if (NT_SUCCESS(status)) {
            *Buffer = infoBuffer;
            *BufferSize = size;
            return status;
        }

        ExFreePool(infoBuffer);

        if (status != STATUS_INFO_LENGTH_MISMATCH)
            return status;

        size *= 2;  // Double buffer size and try again
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetSystemThreadInformation(PVOID* ThreadInfo, PULONG BufferSize)
{
    return GetSystemInformation(SystemProcessInformation, ThreadInfo, BufferSize);
}

NTSTATUS GetSystemHandleInformation(PVOID* HandleInfo, PULONG BufferSize)
{
    return GetSystemInformation(SystemExtendedHandleInformation, HandleInfo, BufferSize);
}

ULONG FindPidGaps(PENHANCED_PROCESS_INFO ProcessList, ULONG Count)
{
    ULONG gapCount = 0;
    ULONG minPid = 4;  // First usable PID
    ULONG maxPid = 0;

    // Find min and max PIDs
    for (ULONG i = 0; i < Count; i++) {
        if (ProcessList[i].ProcessId > maxPid) {
            maxPid = ProcessList[i].ProcessId;
        }
    }

    // Create a presence bitmap
    ULONG bitmapSize = (maxPid / 32) + 1;
    PULONG pidBitmap = ExAllocatePool(PagedPool, bitmapSize * sizeof(ULONG));
    if (!pidBitmap)
        return 0;

    RtlZeroMemory(pidBitmap, bitmapSize * sizeof(ULONG));

    // Mark existing PIDs
    for (ULONG i = 0; i < Count; i++) {
        ULONG pid = ProcessList[i].ProcessId;
        ULONG index = pid / 32;
        ULONG bit = pid % 32;

        if (index < bitmapSize) {
            pidBitmap[index] |= (1 << bit);
        }
    }

    // Find gaps and mark processes with adjacent gaps as suspicious
    for (ULONG pid = minPid; pid <= maxPid; pid++) {
        ULONG index = pid / 32;
        ULONG bit = pid % 32;

        if (index >= bitmapSize)
            continue;

        if (!(pidBitmap[index] & (1 << bit))) {
            gapCount++;

            // Mark previous and next processes (if they exist) as having PID gaps
            if (pid > minPid) {
                AddDetectionFlag(ProcessList, Count, pid - 1, DETECTION_PID_GAP);
            }
            if (pid < maxPid) {
                AddDetectionFlag(ProcessList, Count, pid + 1, DETECTION_PID_GAP);
            }
        }
    }

    ExFreePool(pidBitmap);
    return gapCount;
}

VOID AddDetectionFlag(PENHANCED_PROCESS_INFO ProcessList, ULONG Count, ULONG Pid, ULONG Flag)
{
    for (ULONG i = 0; i < Count; i++) {
        if (ProcessList[i].ProcessId == Pid) {
            ProcessList[i].DetectionFlags |= Flag;
            break;
        }
    }
}
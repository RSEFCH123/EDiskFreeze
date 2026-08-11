/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 RanShaoEFCH
 *
 * EDiskFreeze - A lightweight reboot-to-restore disk protection driver.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <srb.h>

#define MODULE_TYPE_DISK_HOOK  0x12345678
#define DISKHOOK_INTERNAL_IRP_FLAG 0x80000000UL
#define DISKHOOK_INTERNAL_MAGIC ((PVOID)0xDEADBEEFDEADBEEFULL)

// Protection ranges are absolute LBAs on Harddisk0. Runtime D53 changes are
// rejected; the driver loads the complete range set before installing hooks.
typedef struct _EDISK_PROTECTION_RANGE_ENTRY {
    ULONGLONG StartSector;
    ULONGLONG SectorCount;
} EDISK_PROTECTION_RANGE_ENTRY, *PEDISK_PROTECTION_RANGE_ENTRY;

#define EDISK_PROTECTION_METADATA_MAGIC 0x50444645UL
#define EDISK_PROTECTION_METADATA_V1_VERSION 1UL
#define EDISK_PROTECTION_METADATA_VERSION 2UL
#define EDISK_PROTECTION_METADATA_ENABLED 0x00000001UL
#define EDISK_MAX_PROTECTED_RANGES 30UL

// Legacy one-range format. Version 2 is always written, but version 1 remains
// readable so existing installations can be upgraded by the controller.
typedef struct _EDISK_PROTECTION_METADATA_V1 {
    ULONG Magic;
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG DiskNumber;
    ULONG Reserved;
    ULONGLONG StartSector;
    ULONGLONG SectorCount;
    ULONG Checksum;
    ULONG Reserved2;
} EDISK_PROTECTION_METADATA_V1, *PEDISK_PROTECTION_METADATA_V1;

// Version 2 occupies one complete 512-byte sector and stores up to 30
// independent ranges. CRC-32 uses polynomial 0xEDB88320 and is computed over
// all 512 bytes with Checksum treated as zero. RangeCount may be zero, which
// explicitly means that no partition is protected.
typedef struct _EDISK_PROTECTION_METADATA {
    ULONG Magic;
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG DiskNumber;
    ULONG RangeCount;
    ULONG Checksum;
    ULONG Reserved;
    EDISK_PROTECTION_RANGE_ENTRY Ranges[EDISK_MAX_PROTECTED_RANGES];
} EDISK_PROTECTION_METADATA, *PEDISK_PROTECTION_METADATA;

static_assert(sizeof(EDISK_PROTECTION_METADATA_V1) == 48,
    "Unexpected version 1 metadata layout");
static_assert(sizeof(EDISK_PROTECTION_METADATA) == 512,
    "Version 2 protection metadata must occupy one sector");

EXTERN_C NTSTATUS NTAPI ObReferenceObjectByName(IN PUNICODE_STRING ObjectName, IN ULONG64 Attributes, IN PACCESS_STATE PassedAccessState OPTIONAL, IN ACCESS_MASK DesiredAccess OPTIONAL, IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, IN OUT PVOID ParseContext OPTIONAL, OUT PVOID* Object);

typedef struct _COMMON_DEVICE_EXTENSION {
    ULONG ModuleType;
    PDEVICE_OBJECT pNextDeviceInStack;
    BOOLEAN IsSystemDisk;      // 是否为系统盘 (Harddisk0)
} COMMON_DEVICE_EXTENSION, * PCOMMON_DEVICE_EXTENSION;

typedef struct _DISK_PROTECT_WORK_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    PDEVICE_OBJECT TargetDevice;
    PWCHAR DeviceName;          // 设备名称（如 \Device\Harddisk0\DR0）
    ULONG DeviceNameLength;     // 字节长度
    HANDLE CallerPid;           // 发起写入的进程 PID
} DISK_PROTECT_WORK_CONTEXT, * PDISK_PROTECT_WORK_CONTEXT;

typedef struct _SECTOR_MAP_NODE {
    LIST_ENTRY  ListEntry;
    ULONGLONG   OrigSector;
    ULONGLONG   DiffSector;   // 差异区内的绝对扇区号
} SECTOR_MAP_NODE, * PSECTOR_MAP_NODE;

#define HASH_BUCKETS 4096
typedef struct _SECTOR_CACHE {
    LIST_ENTRY      Buckets[HASH_BUCKETS];
    KSPIN_LOCK      Lock;
    ULONGLONG       TotalSectors;
    BOOLEAN         Initialized;
    ULONGLONG       DiffAreaStart;   // 差异区起始扇区（绝对LBA）
    ULONGLONG       DiffAreaTotal;   // 差异区总扇区数
    ULONGLONG       DiffAreaUsed;    // 已分配扇区数（原子操作）
} SECTOR_CACHE, * PSECTOR_CACHE;

typedef struct _SECTOR_WORK_CONTEXT {
    WORK_QUEUE_ITEM     Item;
    PIRP                OriginalIrp;
    PDEVICE_OBJECT      DeviceObject;
    ULONGLONG           StartSector;
    ULONG               Length;
    PUCHAR              SrcBuffer;          // 已经复制好的写入数据（系统缓冲区）
    LARGE_INTEGER       ByteOffset;
    PKEVENT DoneEvent;
} SECTOR_WORK_CONTEXT, * PSECTOR_WORK_CONTEXT;

extern PIO_WORKITEM g_DiskProtectWorkItem;

EXTERN_C_START
NTSTATUS DiskHook_Initialize(PDRIVER_DISPATCH DeviceControl);
NTSTATUS DiskHook_EnumerateAndAttachToDisks(PDRIVER_OBJECT DriverObject);
NTSTATUS DiskHook_AttachToDeviceStack(PDRIVER_OBJECT DriverObject, PUNICODE_STRING DeviceName);
VOID DiskHook_Cleanup(PDRIVER_OBJECT DriverObject);

NTSTATUS DiskHook_DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS DiskHook_DispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//NTSTATUS DiskHook_DispatchSCSI(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DiskHook_DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DiskHook_SetProtectedRanges(
    ULONG DiskNumber,
    ULONG RangeCount,
    PEDISK_PROTECTION_RANGE_ENTRY Ranges);
NTSTATUS DiskHook_GetProtectedRanges(
    PEDISK_PROTECTION_METADATA Metadata);
NTSTATUS WriteOriginalSector(
    IN LARGE_INTEGER ByteOffset,
    IN ULONG Length,
    IN PVOID Buffer);
NTSTATUS WriteOriginalSectorWriteThrough(
    IN LARGE_INTEGER ByteOffset,
    IN ULONG Length,
    IN PVOID Buffer);
NTSTATUS ReadOriginalSector(ULONGLONG Sector, PUCHAR Buffer);
VOID DiskHook_Cleanup_Major();
EXTERN_C_END

extern PDEVICE_OBJECT g_ControlDeviceObject;  // 控制设备指针，用于区分 IOCTL
extern PDRIVER_DISPATCH g_OriginalDiskWrite;
extern PDRIVER_DISPATCH g_OriginalDiskDeviceControl;
extern PDEVICE_OBJECT g_SystemDiskDevice;
extern ULONGLONG dh_startsector;
extern ULONGLONG dh_endsector;
extern PDRIVER_OBJECT  g_DiskDriverObject;       // disk.sys 驱动对象
extern PDEVICE_OBJECT  g_SystemDiskDevice;       // 系统盘设备对象
extern PDRIVER_DISPATCH g_OriginalDiskRead;       // 原始 IRP_MJ_READ
extern PDRIVER_DISPATCH g_OriginalDiskWrite;      // 原始 IRP_MJ_WRITE
extern PDRIVER_DISPATCH g_OriginalDiskDeviceControl; // 原始 IOCTL 派遣

extern ULONGLONG dh_startsector;
extern ULONGLONG dh_endsector;

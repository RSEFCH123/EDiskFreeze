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
#include "diskhook.h"
#include "common.h"
#include <ntstrsafe.h>

#define MEM_PRESSURE_THRESHOLD 10 

PDRIVER_OBJECT   g_DiskDriverObject = NULL;
PDEVICE_OBJECT   g_SystemDiskDevice = NULL;
PDRIVER_DISPATCH g_OriginalDiskRead = NULL;
PDRIVER_DISPATCH g_OriginalDiskWrite = NULL;
PDRIVER_DISPATCH g_OriginalDiskDeviceControl = NULL;

PDEVICE_OBJECT   g_ControlDeviceObject = NULL;
PIO_WORKITEM     g_DiskProtectWorkItem = NULL;

SECTOR_CACHE g_SectorCache = { 0 };
ULONGLONG g_TotalPhysicalPages = 0;

// The default is the complete first physical disk for backward compatibility.
// A valid on-disk metadata record replaces this with an explicit range set.
ULONGLONG dh_startsector = 0;
ULONGLONG dh_endsector = MAXULONGLONG;
static ULONG g_TargetDiskNumber = 0;
static BOOLEAN g_ProtectedRangeConfigured = FALSE;
static ULONG g_ProtectedRangeCount = 0;
static EDISK_PROTECTION_RANGE_ENTRY
    g_ProtectedRanges[EDISK_MAX_PROTECTED_RANGES] = { 0 };
static KSPIN_LOCK g_ProtectedRangeLock;
static ULONGLONG g_ProtectionMetadataSector = MAXULONGLONG;
static NTSTATUS g_ProtectionMetadataLoadStatus = STATUS_NOT_FOUND;
static KMUTEX g_CacheWriteMutex;

extern NTSTATUS SectorCacheWrite(ULONGLONG StartSector, ULONG Length, PUCHAR SrcBuffer, LARGE_INTEGER ByteOffset);
static BOOLEAN GetDeviceBaseSector(PDEVICE_OBJECT DeviceObject, PULONGLONG BaseSector);

static BOOLEAN IsSectorProtected(ULONGLONG sector)
{
    KIRQL oldIrql;
    BOOLEAN isProtected = FALSE;

    KeAcquireSpinLock(&g_ProtectedRangeLock, &oldIrql);
    if (!g_ProtectedRangeConfigured) {
        isProtected = TRUE;
    }
    else {
        for (ULONG i = 0; i < g_ProtectedRangeCount; ++i) {
            ULONGLONG start = g_ProtectedRanges[i].StartSector;
            ULONGLONG end = start + g_ProtectedRanges[i].SectorCount - 1;
            if (sector >= start && sector <= end) {
                isProtected = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_ProtectedRangeLock, oldIrql);
    return isProtected;
}

static BOOLEAN GetProtectedIntersection(
    ULONGLONG startSector,
    ULONG firstSectorOffset,
    ULONG length,
    ULONGLONG* firstSector,
    ULONGLONG* lastSector)
{
    if (!length || firstSectorOffset >= 512 || !firstSector || !lastSector ||
        length - 1 > MAXULONG - firstSectorOffset)
        return FALSE;

    ULONGLONG sectorDelta = (firstSectorOffset + length - 1) / 512;
    if (startSector > MAXULONGLONG - sectorDelta)
        return FALSE;
    ULONGLONG requestLast = startSector + sectorDelta;
    KIRQL oldIrql;
    BOOLEAN intersects = FALSE;

    KeAcquireSpinLock(&g_ProtectedRangeLock, &oldIrql);
    if (!g_ProtectedRangeConfigured) {
        intersects = TRUE;
    }
    else {
        for (ULONG i = 0; i < g_ProtectedRangeCount; ++i) {
            ULONGLONG rangeStart = g_ProtectedRanges[i].StartSector;
            ULONGLONG rangeEnd = rangeStart + g_ProtectedRanges[i].SectorCount - 1;
            if (startSector <= rangeEnd && rangeStart <= requestLast) {
                intersects = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_ProtectedRangeLock, oldIrql);

    if (intersects) {
        // Callers only need to know whether interception is required. Returning
        // the whole request also lets the read path find mappings across more
        // than one non-contiguous protected range.
        *firstSector = startSector;
        *lastSector = requestLast;
    }
    return intersects;
}

static BOOLEAN SectorRangeOverlaps(
    ULONGLONG firstA,
    ULONGLONG lastA,
    ULONGLONG firstB,
    ULONGLONG lastB)
{
    return firstA <= lastB && firstB <= lastA;
}

static ULONG ProtectionMetadataChecksum(
    PVOID metadata,
    ULONG size,
    ULONG checksumOffset)
{
    ULONG crc = 0xFFFFFFFFUL;
    PUCHAR bytes = (PUCHAR)metadata;

    for (ULONG i = 0; i < size; ++i) {
        UCHAR value = (i >= checksumOffset && i < checksumOffset + sizeof(ULONG)) ?
            0 : bytes[i];
        crc ^= value;
        for (ULONG bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320UL & (-(LONG)(crc & 1)));
    }
    return crc ^ 0xFFFFFFFFUL;
}

ULONG GetHashIndex(ULONGLONG Sector)
{
    return (ULONG)(Sector % HASH_BUCKETS);
}

PSECTOR_MAP_NODE FindCacheNode(ULONGLONG Sector)
{
    PLIST_ENTRY head = &g_SectorCache.Buckets[GetHashIndex(Sector)];
    for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
        PSECTOR_MAP_NODE node = CONTAINING_RECORD(entry, SECTOR_MAP_NODE, ListEntry);
        if (node->OrigSector == Sector)
            return node;
    }
    return NULL;
}

// ======================== 核心修复：直接派遣读写原始/差异扇区 ========================

static NTSTATUS DiskReadRange(ULONGLONG Sector, ULONG Length, PUCHAR Buffer)
{
    if (!g_OriginalDiskRead || !g_SystemDiskDevice || !Buffer ||
        Length == 0 || (Length & 0x1FF) || Sector > (MAXULONGLONG / 512) ||
        Length > (MAXULONG - 511))
        return STATUS_INVALID_PARAMETER;

    PUCHAR ioBuffer = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPoolNx, Length, 'BdRE');
    if (!ioBuffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    CCHAR stackSize = g_SystemDiskDevice->StackSize + 1;
    PIRP irp = IoAllocateIrp(stackSize, FALSE);
    if (!irp) {
        ExFreePoolWithTag(ioBuffer, 'BdRE');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PMDL mdl = IoAllocateMdl(ioBuffer, Length, FALSE, FALSE, NULL);
    if (!mdl) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(ioBuffer, 'BdRE');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(mdl);

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp->MdlAddress = mdl;
    irp->UserBuffer = ioBuffer;
    irp->Tail.Overlay.Thread = KeGetCurrentThread();
    irp->Flags = IRP_NOCACHE | IRP_READ_OPERATION;
    irp->RequestorMode = KernelMode;

    IoSetCompletionRoutine(irp,
        [](PDEVICE_OBJECT, PIRP, PVOID context) -> NTSTATUS {
            KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }, &event, TRUE, TRUE, TRUE);

    PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(irp);
    stack->MajorFunction = IRP_MJ_READ;
    stack->Parameters.Read.Length = Length;
    stack->Parameters.Read.ByteOffset.QuadPart = Sector * 512;
    stack->DeviceObject = g_SystemDiskDevice;
    IoSetNextIrpStackLocation(irp);

    NTSTATUS status = g_OriginalDiskRead(g_SystemDiskDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }
    if (NT_SUCCESS(status) && irp->IoStatus.Information < Length)
        status = STATUS_DEVICE_DATA_ERROR;
    if (NT_SUCCESS(status)) {
        __try {
            RtlCopyMemory(Buffer, ioBuffer, Length);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }

    IoFreeMdl(mdl);
    IoFreeIrp(irp);
    ExFreePoolWithTag(ioBuffer, 'BdRE');
    return status;
}

static NTSTATUS DiskWriteRange(
    ULONGLONG Sector,
    ULONG Length,
    PUCHAR Buffer,
    BOOLEAN WriteThrough)
{
    if (!g_OriginalDiskWrite || !g_SystemDiskDevice || !Buffer ||
        Length == 0 || (Length & 0x1FF) || Sector > (MAXULONGLONG / 512) ||
        Length > (MAXULONG - 511))
        return STATUS_INVALID_PARAMETER;

    PUCHAR ioBuffer = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPoolNx, Length, 'BdWE');
    if (!ioBuffer)
        return STATUS_INSUFFICIENT_RESOURCES;
    __try {
        RtlCopyMemory(ioBuffer, Buffer, Length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS status = GetExceptionCode();
        ExFreePoolWithTag(ioBuffer, 'BdWE');
        return status;
    }

    CCHAR stackSize = g_SystemDiskDevice->StackSize + 1;
    PIRP irp = IoAllocateIrp(stackSize, FALSE);
    if (!irp) {
        ExFreePoolWithTag(ioBuffer, 'BdWE');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PMDL mdl = IoAllocateMdl(ioBuffer, Length, FALSE, FALSE, NULL);
    if (!mdl) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(ioBuffer, 'BdWE');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(mdl);

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp->MdlAddress = mdl;
    irp->UserBuffer = ioBuffer;
    irp->RequestorMode = KernelMode;
    irp->Flags = IRP_WRITE_OPERATION | IRP_NOCACHE | IRP_SYNCHRONOUS_API;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();

    IoSetCompletionRoutine(irp,
        [](PDEVICE_OBJECT, PIRP, PVOID context) -> NTSTATUS {
            KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }, &event, TRUE, TRUE, TRUE);

    PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(irp);
    stack->MajorFunction = IRP_MJ_WRITE;
    stack->DeviceObject = g_SystemDiskDevice;
    stack->Parameters.Write.Length = Length;
    stack->Parameters.Write.ByteOffset.QuadPart = Sector * 512;
    if (WriteThrough)
        stack->Flags |= SL_WRITE_THROUGH;
    IoSetNextIrpStackLocation(irp);

    NTSTATUS status = g_OriginalDiskWrite(g_SystemDiskDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    IoFreeMdl(mdl);
    IoFreeIrp(irp);
    ExFreePoolWithTag(ioBuffer, 'BdWE');
    return status;
}

NTSTATUS ReadOriginalSector(ULONGLONG Sector, PUCHAR Buffer)
{
    return DiskReadRange(Sector, 512, Buffer);
}

NTSTATUS WriteOriginalSector(
    IN LARGE_INTEGER ByteOffset,
    IN ULONG Length,
    IN PVOID Buffer)
{
    if (ByteOffset.QuadPart < 0 || (ByteOffset.QuadPart & 0x1FF))
        return STATUS_INVALID_PARAMETER;
    return DiskWriteRange((ULONGLONG)ByteOffset.QuadPart / 512,
        Length, (PUCHAR)Buffer, FALSE);
}

NTSTATUS WriteOriginalSectorWriteThrough(
    IN LARGE_INTEGER ByteOffset,
    IN ULONG Length,
    IN PVOID Buffer)
{
    if (ByteOffset.QuadPart < 0 || (ByteOffset.QuadPart & 0x1FF))
        return STATUS_INVALID_PARAMETER;
    return DiskWriteRange((ULONGLONG)ByteOffset.QuadPart / 512,
        Length, (PUCHAR)Buffer, TRUE);
}

// 读取差异区扇区：直接调用 g_OriginalDiskRead
NTSTATUS ReadDiffSector(ULONGLONG AbsSector, PUCHAR Buffer)
{
    return DiskReadRange(AbsSector, 512, Buffer);
}

// 写入差异区扇区：直接调用 g_OriginalDiskWrite
NTSTATUS WriteDiffSector(ULONGLONG AbsSector, PUCHAR Buffer)
{
    return DiskWriteRange(AbsSector, 512, Buffer, FALSE);
}

ULONGLONG AllocDiffSector()
{
    LONGLONG idx;
    do {
        idx = InterlockedCompareExchange64(
            (LONGLONG*)&g_SectorCache.DiffAreaUsed, 0, 0);
        if (idx < 0 || (ULONGLONG)idx >= g_SectorCache.DiffAreaTotal)
            return MAXULONGLONG;
    } while (InterlockedCompareExchange64(
        (LONGLONG*)&g_SectorCache.DiffAreaUsed, idx + 1, idx) != idx);

    if (g_SectorCache.DiffAreaStart > MAXULONGLONG - (ULONGLONG)idx)
        return MAXULONGLONG;
    return g_SectorCache.DiffAreaStart + (ULONGLONG)idx;
}

static ULONGLONG AllocDiffSectors(ULONG count)
{
    if (!count)
        return MAXULONGLONG;

    LONGLONG oldValue;
    do {
        oldValue = InterlockedCompareExchange64(
            (LONGLONG*)&g_SectorCache.DiffAreaUsed, 0, 0);
        if (oldValue < 0 || (ULONGLONG)oldValue > g_SectorCache.DiffAreaTotal -
            min((ULONGLONG)count, g_SectorCache.DiffAreaTotal))
            return MAXULONGLONG;
        if ((ULONGLONG)oldValue + count > g_SectorCache.DiffAreaTotal)
            return MAXULONGLONG;
    } while (InterlockedCompareExchange64(
        (LONGLONG*)&g_SectorCache.DiffAreaUsed,
        oldValue + count, oldValue) != oldValue);

    if (g_SectorCache.DiffAreaStart > MAXULONGLONG - (ULONGLONG)oldValue)
        return MAXULONGLONG;
    return g_SectorCache.DiffAreaStart + (ULONGLONG)oldValue;
}

// ======================== 核心修复：还原完整的扇区缓存写入逻辑 ========================

static NTSTATUS CacheOneSector(
    ULONGLONG sector,
    ULONG sectorOffset,
    ULONG copySize,
    PUCHAR source)
{
    KIRQL oldIrql;
    PSECTOR_MAP_NODE node;

    KeAcquireSpinLock(&g_SectorCache.Lock, &oldIrql);
    node = FindCacheNode(sector);
    ULONGLONG diffSector = node ? node->DiffSector : MAXULONGLONG;
    KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);

    // A complete overwrite never needs a read-modify-write cycle.
    if (diffSector != MAXULONGLONG && sectorOffset == 0 && copySize == 512) {
        LARGE_INTEGER offset;
        offset.QuadPart = (LONGLONG)(diffSector * 512);
        return WriteOriginalSector(offset, 512, source);
    }

    PUCHAR temp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, 'TmpB');
    if (!temp)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(temp, 512);

    NTSTATUS status;
    if (diffSector != MAXULONGLONG)
        status = ReadDiffSector(diffSector, temp);
    else if (IsSectorProtected(sector))
        status = (sectorOffset == 0 && copySize == 512) ? STATUS_SUCCESS : ReadOriginalSector(sector, temp);
    else
        status = (sectorOffset == 0 && copySize == 512) ? STATUS_SUCCESS : ReadOriginalSector(sector, temp);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(temp, 'TmpB');
        return status;
    }

    RtlCopyMemory(temp + sectorOffset, source, copySize);

    if (diffSector == MAXULONGLONG && !IsSectorProtected(sector)) {
        LARGE_INTEGER offset;
        offset.QuadPart = (LONGLONG)(sector * 512);
        status = WriteOriginalSector(offset, 512, temp);
        ExFreePoolWithTag(temp, 'TmpB');
        return status;
    }

    if (diffSector == MAXULONGLONG) {
        diffSector = AllocDiffSector();
        if (diffSector == MAXULONGLONG) {
            ExFreePoolWithTag(temp, 'TmpB');
            return STATUS_DISK_FULL;
        }
        LARGE_INTEGER diffOffset;
        diffOffset.QuadPart = (LONGLONG)(diffSector * 512);
        status = WriteOriginalSector(diffOffset, 512, temp);
        if (NT_SUCCESS(status)) {
            PSECTOR_MAP_NODE newNode = (PSECTOR_MAP_NODE)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(SECTOR_MAP_NODE), 'SecC');
            if (!newNode) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else {
                newNode->OrigSector = sector;
                newNode->DiffSector = diffSector;
                KeAcquireSpinLock(&g_SectorCache.Lock, &oldIrql);
                PSECTOR_MAP_NODE duplicate = FindCacheNode(sector);
                if (!duplicate) {
                    InsertHeadList(&g_SectorCache.Buckets[GetHashIndex(sector)], &newNode->ListEntry);
                    newNode = NULL;
                }
                KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);
                if (newNode)
                    ExFreePoolWithTag(newNode, 'SecC');
            }
        }
    }
    else {
        LARGE_INTEGER diffOffset;
        diffOffset.QuadPart = (LONGLONG)(diffSector * 512);
        status = WriteOriginalSector(diffOffset, 512, temp);
    }

    ExFreePoolWithTag(temp, 'TmpB');
    return status;
}

static NTSTATUS CacheNewFullRun(
    ULONGLONG startSector,
    ULONG sectorCount,
    PUCHAR source)
{
    if (!sectorCount || sectorCount > (MAXULONG / 512))
        return STATUS_INVALID_PARAMETER;

    PSECTOR_MAP_NODE* nodes = (PSECTOR_MAP_NODE*)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PSECTOR_MAP_NODE*) * sectorCount, 'SecA');
    if (!nodes)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(nodes, sizeof(PSECTOR_MAP_NODE*) * sectorCount);

    for (ULONG i = 0; i < sectorCount; ++i) {
        nodes[i] = (PSECTOR_MAP_NODE)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(SECTOR_MAP_NODE), 'SecC');
        if (!nodes[i]) {
            for (ULONG j = 0; j < i; ++j)
                ExFreePoolWithTag(nodes[j], 'SecC');
            ExFreePoolWithTag(nodes, 'SecA');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        nodes[i]->OrigSector = startSector + i;
    }

    ULONGLONG diffStart = AllocDiffSectors(sectorCount);
    if (diffStart == MAXULONGLONG) {
        for (ULONG i = 0; i < sectorCount; ++i)
            ExFreePoolWithTag(nodes[i], 'SecC');
        ExFreePoolWithTag(nodes, 'SecA');
        return STATUS_DISK_FULL;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)(diffStart * 512);
    NTSTATUS status = WriteOriginalSector(offset, sectorCount * 512, source);
    if (!NT_SUCCESS(status)) {
        for (ULONG i = 0; i < sectorCount; ++i)
            ExFreePoolWithTag(nodes[i], 'SecC');
        ExFreePoolWithTag(nodes, 'SecA');
        return status;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SectorCache.Lock, &oldIrql);
    for (ULONG i = 0; i < sectorCount; ++i) {
        nodes[i]->DiffSector = diffStart + i;
        if (!FindCacheNode(nodes[i]->OrigSector)) {
            InsertHeadList(&g_SectorCache.Buckets[GetHashIndex(nodes[i]->OrigSector)], &nodes[i]->ListEntry);
            nodes[i] = NULL;
        }
    }
    KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);

    for (ULONG i = 0; i < sectorCount; ++i)
        if (nodes[i])
            ExFreePoolWithTag(nodes[i], 'SecC');
    ExFreePoolWithTag(nodes, 'SecA');
    return STATUS_SUCCESS;
}

static NTSTATUS SectorCacheWriteLocked(ULONGLONG StartSector, ULONG Length, PUCHAR SrcBuffer, LARGE_INTEGER ByteOffset)
{
    if (!g_SectorCache.Initialized || !SrcBuffer || !Length || ByteOffset.QuadPart < 0)
        return STATUS_INVALID_PARAMETER;

    ULONGLONG currentSector = StartSector;
    ULONG remaining = Length;
    PUCHAR source = SrcBuffer;

    while (remaining) {
        ULONG sectorOffset = (ULONG)((ByteOffset.QuadPart + (source - SrcBuffer)) & 0x1FF);
        ULONG copySize = min(512 - sectorOffset, remaining);

        if (sectorOffset == 0 && copySize == 512) {
            ULONG fullRun = min(remaining / 512, 128UL); // 64 KiB batches keep pool usage bounded.
            BOOLEAN isProtected = IsSectorProtected(currentSector);
            ULONG run = 1;
            while (run < fullRun && IsSectorProtected(currentSector + run) == isProtected)
                ++run;

            if (isProtected) {
                ULONG uncachedRun = 0;
                KIRQL oldIrql;
                KeAcquireSpinLock(&g_SectorCache.Lock, &oldIrql);
                while (uncachedRun < run && !FindCacheNode(currentSector + uncachedRun))
                    ++uncachedRun;
                KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);
                if (uncachedRun > 1) {
                    NTSTATUS status = CacheNewFullRun(currentSector, uncachedRun, source);
                    if (!NT_SUCCESS(status))
                        return status;
                    currentSector += uncachedRun;
                    source += uncachedRun * 512;
                    remaining -= uncachedRun * 512;
                    continue;
                }
                if (uncachedRun == 0) {
                    ULONG cachedRun = 1;
                    ULONGLONG diffStart;
                    KeAcquireSpinLock(&g_SectorCache.Lock, &oldIrql);
                    PSECTOR_MAP_NODE first = FindCacheNode(currentSector);
                    diffStart = first ? first->DiffSector : MAXULONGLONG;
                    while (diffStart != MAXULONGLONG && cachedRun < run) {
                        PSECTOR_MAP_NODE next = FindCacheNode(currentSector + cachedRun);
                        if (!next || next->DiffSector != diffStart + cachedRun)
                            break;
                        ++cachedRun;
                    }
                    KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);

                    if (cachedRun > 1) {
                        LARGE_INTEGER offset;
                        offset.QuadPart = (LONGLONG)(diffStart * 512);
                        NTSTATUS status = WriteOriginalSector(
                            offset, cachedRun * 512, source);
                        if (!NT_SUCCESS(status))
                            return status;
                        currentSector += cachedRun;
                        source += cachedRun * 512;
                        remaining -= cachedRun * 512;
                        continue;
                    }
                }
            }
            else if (run > 1) {
                LARGE_INTEGER offset;
                offset.QuadPart = (LONGLONG)(currentSector * 512);
                NTSTATUS status = WriteOriginalSector(offset, run * 512, source);
                if (!NT_SUCCESS(status))
                    return status;
                currentSector += run;
                source += run * 512;
                remaining -= run * 512;
                continue;
            }
        }

        NTSTATUS status = CacheOneSector(currentSector, sectorOffset, copySize, source);
        if (!NT_SUCCESS(status))
            return status;
        source += copySize;
        remaining -= copySize;
        ++currentSector;
    }
    return STATUS_SUCCESS;
}

NTSTATUS SectorCacheWrite(ULONGLONG StartSector, ULONG Length, PUCHAR SrcBuffer, LARGE_INTEGER ByteOffset)
{
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    NTSTATUS status = KeWaitForSingleObject(
        &g_CacheWriteMutex, Executive, KernelMode, FALSE, NULL);
    if (!NT_SUCCESS(status))
        return status;
    status = SectorCacheWriteLocked(StartSector, Length, SrcBuffer, ByteOffset);
    KeReleaseMutex(&g_CacheWriteMutex, FALSE);
    return status;
}


VOID HandleScsiSrbPassThrough(PDEVICE_OBJECT DeviceObject, PSCSI_REQUEST_BLOCK Srb)
{
    if (!Srb || !g_SectorCache.Initialized) return;
    ULONGLONG baseSector;
    if (!GetDeviceBaseSector(DeviceObject, &baseSector)) return;

    PUCHAR cdb = Srb->Cdb;
    UCHAR opCode = cdb[0];
    ULONGLONG lba = 0;
    ULONG sectorCount = 0;
    BOOLEAN isWrite = FALSE;

    switch (opCode)
    {
    case 0x0A: // SCSIOP_WRITE (6字节)
        lba = ((cdb[1] & 0x1F) << 16) | (cdb[2] << 8) | cdb[3];
        sectorCount = cdb[4];
        if (sectorCount == 0) sectorCount = 256;
        isWrite = TRUE;
        break;
    case 0x2A: // SCSIOP_WRITE10
        lba = ((ULONGLONG)cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
        sectorCount = (cdb[7] << 8) | cdb[8];
        isWrite = TRUE;
        break;
    case 0xAA: // SCSIOP_WRITE12
        lba = ((ULONGLONG)cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
        sectorCount = ((ULONG)cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9];
        isWrite = TRUE;
        break;
    case 0x8A: // SCSIOP_WRITE16
        lba = ((ULONGLONG)cdb[2] << 56) | ((ULONGLONG)cdb[3] << 48) | ((ULONGLONG)cdb[4] << 40) | ((ULONGLONG)cdb[5] << 32) |
            ((ULONGLONG)cdb[6] << 24) | ((ULONGLONG)cdb[7] << 16) | ((ULONGLONG)cdb[8] << 8) | cdb[9];
        sectorCount = ((ULONG)cdb[10] << 24) | (cdb[11] << 16) | (cdb[12] << 8) | cdb[13];
        isWrite = TRUE;
        break;
    }

    if (isWrite && sectorCount > 0 && Srb->DataBuffer)
    {
        if (sectorCount <= MAXULONG / 512 &&
            Srb->DataTransferLength >= (sectorCount * 512) &&
            lba <= MAXULONGLONG - baseSector)
        {
            lba += baseSector;
            ULONGLONG protectedFirst;
            ULONGLONG protectedLast;
            if (!GetProtectedIntersection(
                lba, 0, sectorCount * 512, &protectedFirst, &protectedLast))
                return;
            LARGE_INTEGER byteOffset;
            byteOffset.QuadPart = lba * 512;

            NTSTATUS status = SectorCacheWrite(
                lba, sectorCount * 512, (PUCHAR)Srb->DataBuffer, byteOffset);
            Srb->SrbStatus = NT_SUCCESS(status) ? SRB_STATUS_SUCCESS : SRB_STATUS_ERROR;
        }
    }
}

// ======================== ATA 统一解析与影子重定向 ========================
BOOLEAN HandleAtaPassThroughIntercept(
    PDEVICE_OBJECT DeviceObject,
    PATA_PASS_THROUGH_EX AtaControl,
    BOOLEAN isDirect,
    PNTSTATUS CacheStatus)
{
    if (CacheStatus) *CacheStatus = STATUS_SUCCESS;
    if (!AtaControl || !g_SectorCache.Initialized) return FALSE;
    ULONGLONG baseSector;
    if (!GetDeviceBaseSector(DeviceObject, &baseSector)) return FALSE;

    UCHAR command = AtaControl->CurrentTaskFile[6];

    // 检测写盘指令 (0x30, 0x35, 0x24, 0x34, 0x39)
    if (command == 0x30 || command == 0x35 || command == 0x24 || command == 0x34 || command == 0x39)
    {
        ULONGLONG lba = 0;
        ULONG sectorCount = 0;

        if (command == 0x24 || command == 0x34 || command == 0x39) // LBA48 模式
        {
            lba = (ULONGLONG)AtaControl->CurrentTaskFile[3] | ((ULONGLONG)AtaControl->CurrentTaskFile[4] << 8) | ((ULONGLONG)AtaControl->CurrentTaskFile[5] << 16) |
                ((ULONGLONG)AtaControl->PreviousTaskFile[3] << 24) | ((ULONGLONG)AtaControl->PreviousTaskFile[4] << 32) | ((ULONGLONG)AtaControl->PreviousTaskFile[5] << 40);
            sectorCount = (ULONG)AtaControl->CurrentTaskFile[1] | ((ULONG)AtaControl->PreviousTaskFile[1] << 8);
        }
        else // LBA28 模式
        {
            lba = (ULONGLONG)AtaControl->CurrentTaskFile[3] | ((ULONGLONG)AtaControl->CurrentTaskFile[4] << 8) | ((ULONGLONG)AtaControl->CurrentTaskFile[5] << 16) | (((ULONGLONG)AtaControl->CurrentTaskFile[2] & 0x0F) << 24);
            sectorCount = AtaControl->CurrentTaskFile[1];
            if (sectorCount == 0) sectorCount = 256;
        }

        if (sectorCount > 0 && sectorCount <= MAXULONG / 512 &&
            lba <= MAXULONGLONG - baseSector)
        {
            lba += baseSector;
            ULONGLONG protectedFirst;
            ULONGLONG protectedLast;
            if (!GetProtectedIntersection(
                lba, 0, sectorCount * 512, &protectedFirst, &protectedLast))
                return FALSE;
            PUCHAR dataBuffer = NULL;

            // 复用 DataBufferOffset 字段，避开成员缺少的编译报错
            if (isDirect) {
                dataBuffer = (PUCHAR)AtaControl->DataBufferOffset; // DIRECT 模式下此处存放硬编码缓冲区指针
            }
            else {
                if (AtaControl->DataBufferOffset != 0) {
                    dataBuffer = (PUCHAR)AtaControl + AtaControl->DataBufferOffset; // 普通模式下存放字节偏移量
                }
            }

            if (dataBuffer != NULL)
            {
                LARGE_INTEGER byteOffset;
                byteOffset.QuadPart = lba * 512;

                // 完美对齐 4 个参数调用
                NTSTATUS status = SectorCacheWrite(
                    lba, sectorCount * 512, dataBuffer, byteOffset);
                if (CacheStatus) *CacheStatus = status;

                if (NT_SUCCESS(status))
                    AtaControl->CurrentTaskFile[6] = 0x00;
                return TRUE;
            }
        }
    }
    return FALSE;
}
// ======================== 下层标准派遣 Hook 挂接 ========================

NTSTATUS DiskHook_DispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    ULONGLONG deviceBaseSector;
    if (!g_SectorCache.Initialized || !GetDeviceBaseSector(DeviceObject, &deviceBaseSector))
        return g_OriginalDiskRead(DeviceObject, Irp);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG length = stack->Parameters.Read.Length;
    if (!length || stack->Parameters.Read.ByteOffset.QuadPart < 0)
        return g_OriginalDiskRead(DeviceObject, Irp);

    ULONGLONG relativeStart = stack->Parameters.Read.ByteOffset.QuadPart / 512;
    if (deviceBaseSector > MAXULONGLONG - relativeStart)
        return g_OriginalDiskRead(DeviceObject, Irp);
    ULONGLONG startSec = deviceBaseSector + relativeStart;
    ULONGLONG protectedFirst;
    ULONGLONG protectedLast;
    if (!GetProtectedIntersection(startSec,
        (ULONG)(stack->Parameters.Read.ByteOffset.QuadPart & 0x1FF),
        length, &protectedFirst, &protectedLast))
        return g_OriginalDiskRead(DeviceObject, Irp);

    BOOLEAN needCache = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_SectorCache.Lock, &irql);
    for (ULONGLONG sec = protectedFirst; sec <= protectedLast; sec++) {
        if (sec >= g_SectorCache.TotalSectors)
            break;
        if (FindCacheNode(sec)) {
            needCache = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SectorCache.Lock, irql);

    if (!needCache)
        return g_OriginalDiskRead(DeviceObject, Irp);

    PUCHAR dest = Irp->MdlAddress ?
        (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority) :
        (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    if (!dest) {
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PUCHAR destPtr = dest;
    ULONG remaining = length;
    ULONGLONG curSector = startSec;
    LARGE_INTEGER byteOffset = stack->Parameters.Read.ByteOffset;
    NTSTATUS status = STATUS_SUCCESS;

    while (remaining) {
        ULONG sectorOff = (ULONG)((byteOffset.QuadPart + (destPtr - dest)) & 0x1FF);
        ULONG copySize = min(512 - sectorOff, remaining);

        KeAcquireSpinLock(&g_SectorCache.Lock, &irql);
        PSECTOR_MAP_NODE node = FindCacheNode(curSector);
        ULONGLONG diffSec = node ? node->DiffSector : MAXULONGLONG;
        KeReleaseSpinLock(&g_SectorCache.Lock, irql);

        if (sectorOff == 0 && copySize == 512) {
            ULONG maxRun = min(remaining / 512, 128UL);
            ULONG run = 1;
            if (diffSec != MAXULONGLONG) {
                while (run < maxRun) {
                    KeAcquireSpinLock(&g_SectorCache.Lock, &irql);
                    PSECTOR_MAP_NODE next = FindCacheNode(curSector + run);
                    BOOLEAN contiguous = next && next->DiffSector == diffSec + run;
                    KeReleaseSpinLock(&g_SectorCache.Lock, irql);
                    if (!contiguous)
                        break;
                    ++run;
                }
                status = DiskReadRange(diffSec, run * 512, destPtr);
            }
            else {
                while (run < maxRun) {
                    KeAcquireSpinLock(&g_SectorCache.Lock, &irql);
                    BOOLEAN mapped = FindCacheNode(curSector + run) != NULL;
                    KeReleaseSpinLock(&g_SectorCache.Lock, irql);
                    if (mapped)
                        break;
                    ++run;
                }
                status = DiskReadRange(curSector, run * 512, destPtr);
            }
            if (!NT_SUCCESS(status))
                break;
            destPtr += run * 512;
            remaining -= run * 512;
            curSector += run;
            continue;
        }

        PUCHAR temp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, 'TmpB');
        if (!temp) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        status = diffSec != MAXULONGLONG ? ReadDiffSector(diffSec, temp) :
            ReadOriginalSector(curSector, temp);
        if (NT_SUCCESS(status))
            RtlCopyMemory(destPtr, temp + sectorOff, copySize);
        ExFreePoolWithTag(temp, 'TmpB');
        if (!NT_SUCCESS(status))
            break;
        destPtr += copySize;
        remaining -= copySize;
        ++curSector;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? length : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DiskHook_DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    ULONGLONG deviceBaseSector;
    if (!g_SectorCache.Initialized || !GetDeviceBaseSector(DeviceObject, &deviceBaseSector))
        return g_OriginalDiskWrite(DeviceObject, Irp);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG length = stack->Parameters.Write.Length;
    if (!length || stack->Parameters.Write.ByteOffset.QuadPart < 0)
        return g_OriginalDiskWrite(DeviceObject, Irp);

    ULONGLONG relativeStart = stack->Parameters.Write.ByteOffset.QuadPart / 512;
    if (deviceBaseSector > MAXULONGLONG - relativeStart)
        return g_OriginalDiskWrite(DeviceObject, Irp);
    ULONGLONG startSector = deviceBaseSector + relativeStart;
    ULONGLONG protectedFirst;
    ULONGLONG protectedLast;
    if (!GetProtectedIntersection(startSector,
        (ULONG)(stack->Parameters.Write.ByteOffset.QuadPart & 0x1FF),
        length, &protectedFirst, &protectedLast))
        return g_OriginalDiskWrite(DeviceObject, Irp);

    PVOID sysBuffer = Irp->MdlAddress ?
        MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority) :
        Irp->AssociatedIrp.SystemBuffer;
    if (!sysBuffer)
        return g_OriginalDiskWrite(DeviceObject, Irp);

    LARGE_INTEGER byteOffset = stack->Parameters.Write.ByteOffset;
    if (deviceBaseSector > MAXULONGLONG / 512 ||
        (ULONGLONG)byteOffset.QuadPart > MAXULONGLONG - deviceBaseSector * 512)
        return g_OriginalDiskWrite(DeviceObject, Irp);
    byteOffset.QuadPart += (LONGLONG)(deviceBaseSector * 512);

    NTSTATUS status = SectorCacheWrite(startSector, length, (PUCHAR)sysBuffer, byteOffset);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? length : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// 获取磁盘总扇区数等其他辅助函数维持原样
NTSTATUS GetDiskSize(PDEVICE_OBJECT DiskDevice, PLARGE_INTEGER DiskSize)
{
    if (!DiskDevice || !DiskSize)
        return STATUS_INVALID_PARAMETER;

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IO_STATUS_BLOCK ioStatus = { 0 };
    GET_LENGTH_INFORMATION lengthInfo = { 0 };

    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_DISK_GET_LENGTH_INFO,
        DiskDevice,
        NULL,
        0,
        &lengthInfo,
        sizeof(lengthInfo),
        FALSE,
        &event,
        &ioStatus);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = IoCallDriver(DiskDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }
    if (NT_SUCCESS(status) && !NT_SUCCESS(ioStatus.Status))
        status = ioStatus.Status;
    if (NT_SUCCESS(status) &&
        (lengthInfo.Length.QuadPart <= 0 ||
            (lengthInfo.Length.QuadPart & 0x1FF) != 0))
        status = STATUS_INVALID_DEVICE_STATE;
    if (NT_SUCCESS(status))
        *DiskSize = lengthInfo.Length;
    return status;
}
/*
NTSTATUS DiskHook_DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    ULONGLONG unusedBaseSector;
    if (!g_OriginalDiskDeviceControl || !GetDeviceBaseSector(DeviceObject, &unusedBaseSector))
    {
        return g_OriginalDiskDeviceControl(DeviceObject, Irp);
    }

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctlCode)
    {
    case IOCTL_SCSI_PASS_THROUGH:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    {
        PSCSI_PASS_THROUGH pSpt = (PSCSI_PASS_THROUGH)Irp->AssociatedIrp.SystemBuffer;
        if (pSpt)
        {
            SCSI_REQUEST_BLOCK srb = { 0 };
            srb.CdbLength = pSpt->CdbLength;
            srb.DataTransferLength = pSpt->DataTransferLength;

            ULONG copyLen = (pSpt->CdbLength > 16) ? 16 : pSpt->CdbLength;
            RtlCopyMemory(srb.Cdb, pSpt->Cdb, copyLen);

            if (ioctlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT) {
                PSCSI_PASS_THROUGH_DIRECT pSptd = (PSCSI_PASS_THROUGH_DIRECT)Irp->AssociatedIrp.SystemBuffer;
                srb.DataBuffer = pSptd->DataBuffer;
            }
            else {
                if (pSpt->DataBufferOffset > 0) {
                    srb.DataBuffer = (PUCHAR)pSpt + pSpt->DataBufferOffset;
                }
            }

            HandleScsiSrbPassThrough(DeviceObject, &srb);

            if (srb.SrbStatus == SRB_STATUS_SUCCESS)
            {
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = stack->Parameters.DeviceIoControl.OutputBufferLength;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_SUCCESS;
            }
        }
    }
    break;

    case IOCTL_ATA_PASS_THROUGH:
    case IOCTL_ATA_PASS_THROUGH_DIRECT:
    {
        PATA_PASS_THROUGH_EX pAta = (PATA_PASS_THROUGH_EX)Irp->AssociatedIrp.SystemBuffer;
        if (pAta)
        {
            BOOLEAN isDirect = (ioctlCode == IOCTL_ATA_PASS_THROUGH_DIRECT);

            NTSTATUS cacheStatus;
            if (HandleAtaPassThroughIntercept(DeviceObject, pAta, isDirect, &cacheStatus))
            {
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = stack->Parameters.DeviceIoControl.OutputBufferLength;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_SUCCESS;
            }
        }
    }
    break;

    default:
        break;
    }

    return g_OriginalDiskDeviceControl(DeviceObject, Irp);
}
*/
NTSTATUS DiskHook_DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    ULONGLONG unusedBaseSector;
    if (!g_OriginalDiskDeviceControl || !GetDeviceBaseSector(DeviceObject, &unusedBaseSector))
    {
        return g_OriginalDiskDeviceControl(DeviceObject, Irp);
    }

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    // ======================== 1. 防蓝屏安全守护 ========================
    // 如果当前 IRQL 在 DISPATCH_LEVEL 或以上，严禁进你的位图/缓存逻辑。
    // 为了防止其强行穿透并保护内核稳定，这里直接拒绝并返回失败，不冒任何风险。
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED; // 直接返回拒绝
        Irp->IoStatus.Information = 0;               // 失败时输出缓冲区有效数据为 0
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    switch (ioctlCode)
    {
        // ======================== 2. SCSI 直通拦截 ========================
    case IOCTL_SCSI_PASS_THROUGH:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    {
        PSCSI_PASS_THROUGH pSpt = (PSCSI_PASS_THROUGH)Irp->AssociatedIrp.SystemBuffer;
        if (pSpt)
        {
            SCSI_REQUEST_BLOCK srb = { 0 };
            srb.CdbLength = pSpt->CdbLength;
            srb.DataTransferLength = pSpt->DataTransferLength;

            ULONG copyLen = (pSpt->CdbLength > 16) ? 16 : pSpt->CdbLength;
            RtlCopyMemory(srb.Cdb, pSpt->Cdb, copyLen);

            if (ioctlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT) {
                PSCSI_PASS_THROUGH_DIRECT pSptd = (PSCSI_PASS_THROUGH_DIRECT)Irp->AssociatedIrp.SystemBuffer;
                srb.DataBuffer = pSptd->DataBuffer;
            }
            else {
                if (pSpt->DataBufferOffset > 0) {
                    srb.DataBuffer = (PUCHAR)pSpt + pSpt->DataBufferOffset;
                }
            }

            // 解析 CDB 命令并重定向到你的影子系统缓存中
            HandleScsiSrbPassThrough(DeviceObject, &srb);

            // 如果属于拦截的写盘操作并且成功扔进了影子缓存，则在此处安全截断，不让它碰物理盘
            if (srb.SrbStatus != 0)
            {
                NTSTATUS cacheStatus = (srb.SrbStatus == SRB_STATUS_SUCCESS) ?
                    STATUS_SUCCESS : STATUS_IO_DEVICE_ERROR;
                Irp->IoStatus.Status = cacheStatus;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return cacheStatus;
            }
        }
    }
    break;

    // ======================== 3. ATA 直通拦截 ========================
    case IOCTL_ATA_PASS_THROUGH:
    case IOCTL_ATA_PASS_THROUGH_DIRECT:
    {
        PATA_PASS_THROUGH_EX pAta = (PATA_PASS_THROUGH_EX)Irp->AssociatedIrp.SystemBuffer;
        if (pAta)
        {
            BOOLEAN isDirect = (ioctlCode == IOCTL_ATA_PASS_THROUGH_DIRECT);

            // 如果是物理写盘命令，内部会把数据写进影子系统差异区
            NTSTATUS cacheStatus;
            if (HandleAtaPassThroughIntercept(DeviceObject, pAta, isDirect, &cacheStatus))
            {
                // 核心修改：停止伪造 CurrentTaskFile[6] = 0x00，直接给应用层返回拒绝失败
                Irp->IoStatus.Status = cacheStatus;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return cacheStatus;
            }
        }
    }
    break;

    // ======================== 4. 彻底封死隐蔽逃逸通道 ========================
    // 专门针对企图通过微型端口、原生NVMe控制码、底层固件刷写指令绕过标准文件系统的恶意病毒
    case IOCTL_SCSI_MINIPORT:
    case 0x002D1400: // 某些非公开物理扇区修改指令
    {
        // 一律在入口处暴力熔断，直接返回拒绝访问。
        // 物理磁盘连看都看不见这串 IRP，物理盘坚如磐石，还原绝不可能被破！
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    default:
        break;
    }

    // 正常的非写盘控制（如查询大小、查询几何参数、获取盘符拓扑）继续放行给底层，维持系统稳定
    return g_OriginalDiskDeviceControl(DeviceObject, Irp);
}

NTSTATUS DiskHook_SetProtectedRanges(
    ULONG DiskNumber,
    ULONG RangeCount,
    PEDISK_PROTECTION_RANGE_ENTRY Ranges)
{
    if (DiskNumber != g_TargetDiskNumber ||
        RangeCount > EDISK_MAX_PROTECTED_RANGES ||
        (RangeCount && !Ranges))
        return STATUS_INVALID_PARAMETER;
    if (!g_SectorCache.TotalSectors)
        return STATUS_INVALID_DEVICE_STATE;

    ULONGLONG diffEnd = MAXULONGLONG;
    if (g_SectorCache.DiffAreaTotal &&
        g_SectorCache.DiffAreaStart <= MAXULONGLONG - (g_SectorCache.DiffAreaTotal - 1))
        diffEnd = g_SectorCache.DiffAreaStart + g_SectorCache.DiffAreaTotal - 1;

    for (ULONG i = 0; i < RangeCount; ++i) {
        ULONGLONG start = Ranges[i].StartSector;
        ULONGLONG count = Ranges[i].SectorCount;
        if (!count || start > MAXULONGLONG - (count - 1)) {
            DbgPrint("EDiskFreeze: protected range %lu has an invalid length\n", i);
            return STATUS_INTEGER_OVERFLOW;
        }
        ULONGLONG end = start + count - 1;
        if (end >= g_SectorCache.TotalSectors) {
            DbgPrint("EDiskFreeze: protected range %lu ends at LBA %llu, disk ends at %llu\n",
                i, end, g_SectorCache.TotalSectors - 1);
            return STATUS_END_OF_FILE;
        }
        if (diffEnd != MAXULONGLONG && SectorRangeOverlaps(
            start, end, g_SectorCache.DiffAreaStart, diffEnd)) {
            DbgPrint("EDiskFreeze: protected range %lu overlaps diff area %llu-%llu\n",
                i, g_SectorCache.DiffAreaStart, diffEnd);
            return STATUS_CONFLICTING_ADDRESSES;
        }
        if (g_ProtectionMetadataSector != MAXULONGLONG &&
            g_ProtectionMetadataSector >= start &&
            g_ProtectionMetadataSector <= end) {
            DbgPrint("EDiskFreeze: protected range %lu contains metadata LBA %llu\n",
                i, g_ProtectionMetadataSector);
            return STATUS_ACCESS_DENIED;
        }

        for (ULONG previous = 0; previous < i; ++previous) {
            ULONGLONG previousEnd = Ranges[previous].StartSector +
                Ranges[previous].SectorCount - 1;
            if (SectorRangeOverlaps(start, end,
                Ranges[previous].StartSector, previousEnd)) {
                DbgPrint("EDiskFreeze: protected ranges %lu and %lu overlap\n",
                    previous, i);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedRangeLock, &oldIrql);
    RtlZeroMemory(g_ProtectedRanges, sizeof(g_ProtectedRanges));
    if (RangeCount)
        RtlCopyMemory(g_ProtectedRanges, Ranges,
            RangeCount * sizeof(EDISK_PROTECTION_RANGE_ENTRY));
    g_ProtectedRangeCount = RangeCount;
    g_ProtectedRangeConfigured = TRUE;

    // Retain the old globals as a diagnostic bounding range only.
    dh_startsector = 0;
    dh_endsector = 0;
    if (RangeCount) {
        dh_startsector = g_ProtectedRanges[0].StartSector;
        dh_endsector = dh_startsector + g_ProtectedRanges[0].SectorCount - 1;
        for (ULONG i = 1; i < RangeCount; ++i) {
            dh_startsector = min(dh_startsector, g_ProtectedRanges[i].StartSector);
            dh_endsector = max(dh_endsector,
                g_ProtectedRanges[i].StartSector +
                g_ProtectedRanges[i].SectorCount - 1);
        }
    }
    KeReleaseSpinLock(&g_ProtectedRangeLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS DiskHook_GetProtectedRanges(PEDISK_PROTECTION_METADATA Metadata)
{
    if (!Metadata)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Metadata, sizeof(*Metadata));
    Metadata->Magic = EDISK_PROTECTION_METADATA_MAGIC;
    Metadata->Version = EDISK_PROTECTION_METADATA_VERSION;
    Metadata->Size = sizeof(*Metadata);
    Metadata->Flags = EDISK_PROTECTION_METADATA_ENABLED;
    Metadata->DiskNumber = g_TargetDiskNumber;
    Metadata->Reserved = (ULONG)g_ProtectionMetadataLoadStatus;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedRangeLock, &oldIrql);
    if (!g_ProtectedRangeConfigured) {
        Metadata->RangeCount = 1;
        Metadata->Ranges[0].StartSector = 0;
        Metadata->Ranges[0].SectorCount = g_SectorCache.TotalSectors;
    }
    else {
        Metadata->RangeCount = g_ProtectedRangeCount;
        if (g_ProtectedRangeCount)
            RtlCopyMemory(Metadata->Ranges, g_ProtectedRanges,
                g_ProtectedRangeCount * sizeof(EDISK_PROTECTION_RANGE_ENTRY));
    }
    KeReleaseSpinLock(&g_ProtectedRangeLock, oldIrql);

    Metadata->Checksum = ProtectionMetadataChecksum(
        Metadata, sizeof(*Metadata),
        FIELD_OFFSET(EDISK_PROTECTION_METADATA, Checksum));
    return STATUS_SUCCESS;
}

static NTSTATUS LoadProtectionMetadata(ULONGLONG metadataSector, ULONGLONG totalSectors)
{
    if (metadataSector >= totalSectors || metadataSector == MAXULONGLONG)
        return STATUS_NOT_FOUND;

    UCHAR sectorBuffer[512] = { 0 };
    NTSTATUS status = ReadOriginalSector(metadataSector, sectorBuffer);
    if (!NT_SUCCESS(status))
        return status;

    PEDISK_PROTECTION_METADATA metadata =
        (PEDISK_PROTECTION_METADATA)sectorBuffer;
    if (metadata->Magic != EDISK_PROTECTION_METADATA_MAGIC ||
        !(metadata->Flags & EDISK_PROTECTION_METADATA_ENABLED) ||
        metadata->DiskNumber != g_TargetDiskNumber)
        return STATUS_DATA_ERROR;

    if (metadata->Version == EDISK_PROTECTION_METADATA_VERSION) {
        if (metadata->Size != sizeof(EDISK_PROTECTION_METADATA) ||
            metadata->RangeCount > EDISK_MAX_PROTECTED_RANGES ||
            metadata->Checksum != ProtectionMetadataChecksum(
                metadata, sizeof(*metadata),
                FIELD_OFFSET(EDISK_PROTECTION_METADATA, Checksum)))
            return STATUS_DATA_ERROR;

        status = DiskHook_SetProtectedRanges(
            metadata->DiskNumber, metadata->RangeCount, metadata->Ranges);
    }
    else if (metadata->Version == EDISK_PROTECTION_METADATA_V1_VERSION) {
        PEDISK_PROTECTION_METADATA_V1 legacy =
            (PEDISK_PROTECTION_METADATA_V1)sectorBuffer;
        if (legacy->Size != sizeof(*legacy) || !legacy->SectorCount ||
            legacy->Checksum != ProtectionMetadataChecksum(
                legacy, sizeof(*legacy),
                FIELD_OFFSET(EDISK_PROTECTION_METADATA_V1, Checksum)))
            return STATUS_DATA_ERROR;

        EDISK_PROTECTION_RANGE_ENTRY range = {
            legacy->StartSector, legacy->SectorCount
        };
        status = DiskHook_SetProtectedRanges(
            legacy->DiskNumber, 1, &range);
    }
    else {
        return STATUS_REVISION_MISMATCH;
    }

    if (NT_SUCCESS(status))
        DbgPrint("EDiskFreeze: loaded %lu protected range(s) from metadata LBA %llu\n",
            g_ProtectedRangeCount, metadataSector);
    return status;
}

#define MAX_TRACKED_PARTITION_DEVICES 128
typedef struct _TRACKED_PARTITION_DEVICE {
    PDEVICE_OBJECT DeviceObject;
    ULONGLONG BaseSector;
} TRACKED_PARTITION_DEVICE;

static TRACKED_PARTITION_DEVICE g_TrackedPartitions[MAX_TRACKED_PARTITION_DEVICES];
static ULONG g_TrackedPartitionCount = 0;

static NTSTATUS QueryPartitionOffset(PDEVICE_OBJECT DeviceObject, PULONGLONG BaseSector)
{
    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IO_STATUS_BLOCK ioStatus = { 0 };
    PARTITION_INFORMATION_EX info = {  };
    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_DISK_GET_PARTITION_INFO_EX,
        DeviceObject,
        NULL,
        0,
        &info,
        sizeof(info),
        FALSE,
        &event,
        &ioStatus);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = IoCallDriver(DeviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }
    if (NT_SUCCESS(status)) {
        if (info.StartingOffset.QuadPart < 0 ||
            (info.StartingOffset.QuadPart & 0x1FF))
            return STATUS_INVALID_PARAMETER;
        *BaseSector = (ULONGLONG)info.StartingOffset.QuadPart / 512;
    }
    return status;
}

static VOID BuildTrackedPartitionMap(PDRIVER_OBJECT DiskDriver)
{
    g_TrackedPartitionCount = 0;
    if (g_SystemDiskDevice && g_TrackedPartitionCount < MAX_TRACKED_PARTITION_DEVICES) {
        g_TrackedPartitions[g_TrackedPartitionCount].DeviceObject = g_SystemDiskDevice;
        g_TrackedPartitions[g_TrackedPartitionCount].BaseSector = 0;
        ++g_TrackedPartitionCount;
    }

    // Partition devices are named Harddisk0\PartitionN. Resolve each name to
    // the disk.sys device object so filesystem I/O can be translated to an
    // absolute LBA before it reaches the shadow map.
    for (ULONG partition = 1;
         partition < MAX_TRACKED_PARTITION_DEVICES &&
         g_TrackedPartitionCount < MAX_TRACKED_PARTITION_DEVICES;
         ++partition) {
        WCHAR nameBuffer[64] = { 0 };
        UNICODE_STRING name;
        RtlStringCchPrintfW(nameBuffer, RTL_NUMBER_OF(nameBuffer),
            L"\\Device\\Harddisk0\\Partition%lu", partition);
        RtlInitUnicodeString(&name, nameBuffer);

        PFILE_OBJECT fileObject = NULL;
        PDEVICE_OBJECT topDevice = NULL;
        if (!NT_SUCCESS(IoGetDeviceObjectPointer(
            &name, FILE_READ_ATTRIBUTES, &fileObject, &topDevice)))
            continue;

        PDEVICE_OBJECT diskDevice = NULL;
        for (PDEVICE_OBJECT candidate = DiskDriver->DeviceObject;
             candidate;
             candidate = candidate->NextDevice) {
            PDEVICE_OBJECT stackTop = IoGetAttachedDeviceReference(candidate);
            BOOLEAN matches = (stackTop == topDevice);
            ObDereferenceObject(stackTop);
            if (matches) {
                diskDevice = candidate;
                break;
            }
        }

        if (diskDevice) {
            ULONGLONG baseSector = 0;
            if (NT_SUCCESS(QueryPartitionOffset(diskDevice, &baseSector))) {
                g_TrackedPartitions[g_TrackedPartitionCount].DeviceObject = diskDevice;
                g_TrackedPartitions[g_TrackedPartitionCount].BaseSector = baseSector;
                ++g_TrackedPartitionCount;
            }
        }
        ObDereferenceObject(fileObject);
    }
}

static BOOLEAN GetDeviceBaseSector(PDEVICE_OBJECT DeviceObject, PULONGLONG BaseSector)
{
    for (ULONG i = 0; i < g_TrackedPartitionCount; ++i) {
        if (g_TrackedPartitions[i].DeviceObject == DeviceObject) {
            *BaseSector = g_TrackedPartitions[i].BaseSector;
            return TRUE;
        }
    }
    return FALSE;
}


NTSTATUS InitSectorCache(PDEVICE_OBJECT DiskDevice)
{
    KeInitializeSpinLock(&g_ProtectedRangeLock);
    KeInitializeMutex(&g_CacheWriteMutex, 0);
    g_ProtectedRangeConfigured = FALSE;
    g_ProtectedRangeCount = 0;
    g_ProtectionMetadataLoadStatus = STATUS_NOT_FOUND;
    RtlZeroMemory(g_ProtectedRanges, sizeof(g_ProtectedRanges));
    dh_startsector = 0;
    dh_endsector = MAXULONGLONG;

    UNICODE_STRING regPath;
    RtlInitUnicodeString(&regPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EDiskFreezeDrv64\\Parameters");

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING valName;
    UCHAR kvBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONGLONG)];
    PKEY_VALUE_PARTIAL_INFORMATION kvi = (PKEY_VALUE_PARTIAL_INFORMATION)kvBuf;
    ULONG resLen;
    ULONGLONG metadataSector = MAXULONGLONG;

    RtlInitUnicodeString(&valName, L"DiffStartSector");
    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvi, sizeof(kvBuf), &resLen);
    if (!NT_SUCCESS(status) || kvi->DataLength < sizeof(ULONGLONG)) { ZwClose(hKey); return STATUS_INVALID_PARAMETER; }
    g_SectorCache.DiffAreaStart = *(ULONGLONG*)kvi->Data;

    RtlInitUnicodeString(&valName, L"DiffTotalSectors");
    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvi, sizeof(kvBuf), &resLen);
    if (!NT_SUCCESS(status) || kvi->DataLength < sizeof(ULONGLONG)) { ZwClose(hKey); return STATUS_INVALID_PARAMETER; }
    g_SectorCache.DiffAreaTotal = *(ULONGLONG*)kvi->Data;

    // Optional: the UI and the driver agree on this reserved metadata LBA.
    // If absent, the sector immediately before the diff area is used.
    RtlInitUnicodeString(&valName, L"ProtectionInfoSector");
    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvi, sizeof(kvBuf), &resLen);
    if (NT_SUCCESS(status) && kvi->DataLength >= sizeof(ULONGLONG))
        metadataSector = *(ULONGLONG*)kvi->Data;
    ZwClose(hKey);

    g_SectorCache.DiffAreaUsed = 0;
    LARGE_INTEGER diskSize;
    status = GetDiskSize(DiskDevice, &diskSize);
    if (!NT_SUCCESS(status)) return status;

    ULONGLONG totalSectors = diskSize.QuadPart / 512;
    if (!totalSectors || !g_SectorCache.DiffAreaTotal ||
        g_SectorCache.DiffAreaStart >= totalSectors ||
        g_SectorCache.DiffAreaTotal > totalSectors - g_SectorCache.DiffAreaStart)
        return STATUS_INVALID_PARAMETER;

    if (metadataSector == MAXULONGLONG && g_SectorCache.DiffAreaStart)
        metadataSector = g_SectorCache.DiffAreaStart - 1;
    g_ProtectionMetadataSector = metadataSector;

    dh_endsector = totalSectors - 1;

    for (int i = 0; i < HASH_BUCKETS; i++)
        InitializeListHead(&g_SectorCache.Buckets[i]);

    KeInitializeSpinLock(&g_SectorCache.Lock);
    g_SectorCache.TotalSectors = totalSectors;
    g_SectorCache.Initialized = TRUE;

    status = LoadProtectionMetadata(metadataSector, totalSectors);
    g_ProtectionMetadataLoadStatus = status;
    if (!NT_SUCCESS(status))
        DbgPrint("EDiskFreeze: no valid protection metadata at LBA %llu (0x%08X), using full-disk compatibility range\n",
            metadataSector, status);
    return STATUS_SUCCESS;
}

VOID CleanupSectorCache()
{
    if (!g_SectorCache.Initialized) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_SectorCache.Lock, &irql);
    for (int i = 0; i < HASH_BUCKETS; i++) {
        while (!IsListEmpty(&g_SectorCache.Buckets[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&g_SectorCache.Buckets[i]);
            PSECTOR_MAP_NODE node = CONTAINING_RECORD(entry, SECTOR_MAP_NODE, ListEntry);
            ExFreePoolWithTag(node, 'SecC');
        }
    }
    g_SectorCache.TotalSectors = 0;
    g_SectorCache.DiffAreaUsed = 0;
    g_SectorCache.Initialized = FALSE;
    KeReleaseSpinLock(&g_SectorCache.Lock, irql);
}

// 挂钩与环境清洗逻辑保持原样，由于不再发送给 topDevice，免去了对象引用的追踪麻烦
NTSTATUS DiskHook_SetToMajorFunction(PDRIVER_DISPATCH DeviceControl)
{
    PDRIVER_OBJECT drv;
    UNICODE_STRING uniPath;
    RtlInitUnicodeString(&uniPath, L"\\Driver\\disk");
    NTSTATUS status = ObReferenceObjectByName(&uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&drv);
    if (!NT_SUCCESS(status)) return status;

    PFILE_OBJECT pfo;
    PDEVICE_OBJECT pTop;
    UNICODE_STRING sysName;
    RtlInitUnicodeString(&sysName, L"\\Device\\Harddisk0\\DR0");
    status = IoGetDeviceObjectPointer(&sysName, FILE_READ_ATTRIBUTES, &pfo, &pTop);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(drv);
        return status;
    }
    ObDereferenceObject(pfo);

    PDEVICE_OBJECT pDev = drv->DeviceObject;
    while (pDev) {
        PDEVICE_OBJECT pStackTop = IoGetAttachedDeviceReference(pDev);
        ObDereferenceObject(pStackTop);
        if (pStackTop == pTop) {
            g_SystemDiskDevice = pDev;
            break;
        }
        pDev = pDev->NextDevice;
    }
    if (!g_SystemDiskDevice) {
        ObDereferenceObject(drv);
        return STATUS_NOT_FOUND;
    }

    g_OriginalDiskRead = drv->MajorFunction[IRP_MJ_READ];
    g_OriginalDiskWrite = drv->MajorFunction[IRP_MJ_WRITE];
    g_OriginalDiskDeviceControl = drv->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    g_DiskDriverObject = drv;

    BuildTrackedPartitionMap(drv);

    status = InitSectorCache(g_SystemDiskDevice);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(drv);
        return status;
    }

    _InterlockedExchangePointer((PVOID*)&drv->MajorFunction[IRP_MJ_READ], DiskHook_DispatchRead);
    _InterlockedExchangePointer((PVOID*)&drv->MajorFunction[IRP_MJ_WRITE], DiskHook_DispatchWrite);
    _InterlockedExchangePointer((PVOID*)&drv->MajorFunction[IRP_MJ_DEVICE_CONTROL], DeviceControl);

    return STATUS_SUCCESS;
}

VOID DiskHook_Cleanup_Major()
{
    if (g_DiskDriverObject) {
        _InterlockedExchangePointer((PVOID*)&g_DiskDriverObject->MajorFunction[IRP_MJ_READ], g_OriginalDiskRead);
        _InterlockedExchangePointer((PVOID*)&g_DiskDriverObject->MajorFunction[IRP_MJ_WRITE], g_OriginalDiskWrite);
        _InterlockedExchangePointer((PVOID*)&g_DiskDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], g_OriginalDiskDeviceControl);
        ObDereferenceObject(g_DiskDriverObject);
        g_DiskDriverObject = NULL;
    }
    CleanupSectorCache();
    RtlZeroMemory(g_TrackedPartitions, sizeof(g_TrackedPartitions));
    g_TrackedPartitionCount = 0;
}

NTSTATUS DiskHook_Initialize(PDRIVER_DISPATCH DeviceControl)
{
    return DiskHook_SetToMajorFunction(DeviceControl);
}

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

extern NTSTATUS SectorCacheWrite(ULONGLONG StartSector, ULONG Length, PUCHAR SrcBuffer, LARGE_INTEGER ByteOffset);

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

// 读取原始扇区：彻底抛弃 IoCallDriver，直接调用 g_OriginalDiskRead
NTSTATUS ReadOriginalSector(ULONGLONG Sector, PUCHAR Buffer)
{
    if (!g_OriginalDiskRead || !g_SystemDiskDevice)
        return STATUS_UNSUCCESSFUL;

    // 分配 IRP，栈空间多给 1 层留给我们自己充当底层完成位置
    CCHAR stackSize = g_SystemDiskDevice->StackSize + 1;
    PIRP irp = IoAllocateIrp(stackSize, FALSE);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    PMDL mdl = IoAllocateMdl(Buffer, 512, FALSE, FALSE, NULL);
    if (!mdl) {
        IoFreeIrp(irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl); IoFreeIrp(irp);
        return GetExceptionCode();
    }

    irp->MdlAddress = mdl;
    irp->UserBuffer = Buffer;
    irp->Tail.Overlay.Thread = KeGetCurrentThread();
    irp->Flags = IRP_NOCACHE | IRP_READ_OPERATION;
    irp->RequestorMode = KernelMode;

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    // 设置完成例程。注意：IoSetCompletionRoutine 会写入“下一层”栈空间
    IoSetCompletionRoutine(irp,
        [](PDEVICE_OBJECT, PIRP, PVOID ctx) -> NTSTATUS {
            KeSetEvent((PKEVENT)ctx, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }, &event, TRUE, TRUE, TRUE);

    // 填充下一层（即 disk.sys 应该看到的内容）的参数
    PIO_STACK_LOCATION irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_READ;
    irpSp->Parameters.Read.Length = 512;
    irpSp->Parameters.Read.ByteOffset.QuadPart = Sector * 512;
    irpSp->DeviceObject = g_SystemDiskDevice;

    // 手工推进栈指针，让刚才填充的参数成为 disk.sys 执行时的 CurrentStackLocation
    IoSetNextIrpStackLocation(irp);

    // 重点：直接调用原始派遣指针！不走任何上层过滤，不引发 Hook 递归
    NTSTATUS status = g_OriginalDiskRead(g_SystemDiskDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    MmUnlockPages(mdl); IoFreeMdl(mdl); IoFreeIrp(irp);
    return status;
}

NTSTATUS WriteOriginalSector(
    IN LARGE_INTEGER ByteOffset,
    IN ULONG Length,
    IN PVOID Buffer)
{
    if (!g_OriginalDiskWrite || !g_SystemDiskDevice) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!Buffer || Length == 0 || (ByteOffset.QuadPart & 0x1FF) || (Length & 0x1FF)) {
        return STATUS_INVALID_PARAMETER;
    }

    CCHAR stackSize = g_SystemDiskDevice->StackSize + 1;
    PIRP pIrp = IoAllocateIrp(stackSize, FALSE);
    if (!pIrp) return STATUS_INSUFFICIENT_RESOURCES;

    PMDL pMdl = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
    if (!pMdl) {
        IoFreeIrp(pIrp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(pMdl);
        IoFreeIrp(pIrp);
        return GetExceptionCode();
    }

    KEVENT kEvent;
    KeInitializeEvent(&kEvent, NotificationEvent, FALSE);

    pIrp->MdlAddress = pMdl;
    pIrp->UserEvent = &kEvent;
    pIrp->RequestorMode = KernelMode;
    pIrp->Flags = IRP_WRITE_OPERATION | IRP_NOCACHE | IRP_SYNCHRONOUS_API;
    pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
    pIrp->Tail.Overlay.OriginalFileObject = NULL;   // 不需要文件对象

    IoSetCompletionRoutine(pIrp,
        [](PDEVICE_OBJECT, PIRP Irp, PVOID Context) -> NTSTATUS {
            KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }, &kEvent, TRUE, TRUE, TRUE);

    PIO_STACK_LOCATION pIoStack = IoGetNextIrpStackLocation(pIrp);
    pIoStack->MajorFunction = IRP_MJ_WRITE;
    pIoStack->FileObject = NULL;                     // 可设为 NULL
    pIoStack->DeviceObject = g_SystemDiskDevice;
    pIoStack->Parameters.Write.Length = Length;
    pIoStack->Parameters.Write.ByteOffset = ByteOffset;

    IoSetNextIrpStackLocation(pIrp);

    NTSTATUS status = g_OriginalDiskWrite(g_SystemDiskDevice, pIrp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);
        status = pIrp->IoStatus.Status;
    }

    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);
    IoFreeIrp(pIrp);
    return status;
}

// 读取差异区扇区：直接调用 g_OriginalDiskRead
NTSTATUS ReadDiffSector(ULONGLONG AbsSector, PUCHAR Buffer)
{
    if (!g_OriginalDiskRead || !g_SystemDiskDevice)
        return STATUS_UNSUCCESSFUL;

    CCHAR stackSize = g_SystemDiskDevice->StackSize + 1;
    PIRP irp = IoAllocateIrp(stackSize, FALSE);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    PMDL mdl = IoAllocateMdl(Buffer, 512, FALSE, FALSE, NULL);
    if (!mdl) {
        IoFreeIrp(irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl); IoFreeIrp(irp);
        return GetExceptionCode();
    }

    irp->MdlAddress = mdl;
    irp->UserBuffer = Buffer;
    irp->Tail.Overlay.Thread = KeGetCurrentThread();
    irp->Flags = IRP_NOCACHE | IRP_READ_OPERATION;
    irp->RequestorMode = KernelMode;

    KEVENT ev;
    KeInitializeEvent(&ev, NotificationEvent, FALSE);
    IoSetCompletionRoutine(irp,
        [](PDEVICE_OBJECT, PIRP, PVOID ctx) -> NTSTATUS {
            KeSetEvent((PKEVENT)ctx, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }, &ev, TRUE, TRUE, TRUE);

    PIO_STACK_LOCATION sp = IoGetNextIrpStackLocation(irp);
    sp->MajorFunction = IRP_MJ_READ;
    sp->Parameters.Read.Length = 512;
    sp->Parameters.Read.ByteOffset.QuadPart = AbsSector * 512;
    sp->DeviceObject = g_SystemDiskDevice;

    IoSetNextIrpStackLocation(irp);

    NTSTATUS status = g_OriginalDiskRead(g_SystemDiskDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    MmUnlockPages(mdl); IoFreeMdl(mdl); IoFreeIrp(irp);
    return status;
}

// 写入差异区扇区：直接调用 g_OriginalDiskWrite
NTSTATUS WriteDiffSector(ULONGLONG AbsSector, PUCHAR Buffer)
{
    if (!g_OriginalDiskWrite || !g_SystemDiskDevice)
        return STATUS_UNSUCCESSFUL;

    CCHAR stackSize = g_SystemDiskDevice->StackSize + 1;
    PIRP irp = IoAllocateIrp(stackSize, FALSE);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    PMDL mdl = IoAllocateMdl(Buffer, 512, FALSE, FALSE, NULL);
    if (!mdl) {
        IoFreeIrp(irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl); IoFreeIrp(irp);
        return GetExceptionCode();
    }

    irp->MdlAddress = mdl;
    irp->UserBuffer = Buffer;
    irp->Tail.Overlay.Thread = KeGetCurrentThread();
    irp->Flags = IRP_NOCACHE | IRP_WRITE_OPERATION;
    irp->RequestorMode = KernelMode;

    KEVENT ev;
    KeInitializeEvent(&ev, NotificationEvent, FALSE);
    IoSetCompletionRoutine(irp,
        [](PDEVICE_OBJECT, PIRP, PVOID ctx) -> NTSTATUS {
            KeSetEvent((PKEVENT)ctx, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }, &ev, TRUE, TRUE, TRUE);

    PIO_STACK_LOCATION sp = IoGetNextIrpStackLocation(irp);
    sp->MajorFunction = IRP_MJ_WRITE;
    sp->Parameters.Write.Length = 512;
    sp->Parameters.Write.ByteOffset.QuadPart = AbsSector * 512;
    sp->DeviceObject = g_SystemDiskDevice;

    IoSetNextIrpStackLocation(irp);

    NTSTATUS status = g_OriginalDiskWrite(g_SystemDiskDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    MmUnlockPages(mdl); IoFreeMdl(mdl); IoFreeIrp(irp);
    return status;
}

ULONGLONG AllocDiffSector()
{
    LONGLONG idx = InterlockedIncrement64((LONGLONG*)&g_SectorCache.DiffAreaUsed) - 1;
    if ((ULONGLONG)idx >= g_SectorCache.DiffAreaTotal) {
        InterlockedDecrement64((LONGLONG*)&g_SectorCache.DiffAreaUsed);
        return MAXULONGLONG;
    }
    return g_SectorCache.DiffAreaStart + (ULONGLONG)idx;
}

// ======================== 核心修复：还原完整的扇区缓存写入逻辑 ========================

NTSTATUS SectorCacheWrite(ULONGLONG StartSector, ULONG Length, PUCHAR SrcBuffer, LARGE_INTEGER ByteOffset)
{
    if (!g_SectorCache.Initialized || !SrcBuffer || Length == 0)
        return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    ULONGLONG curSector = StartSector;
    ULONG remaining = Length;
    PUCHAR src = SrcBuffer;
    NTSTATUS status = STATUS_SUCCESS;

    while (remaining > 0) {
        ULONG sectorOff = (ULONG)((ByteOffset.QuadPart + (src - SrcBuffer)) % 512);
        ULONG copySize = min(512 - sectorOff, remaining);

        // 仅在查找节点时持有自旋锁，绝不在持有锁时做耗时或同步 IO 
        KeAcquireSpinLock(&g_SectorCache.Lock, &oldIrql);
        PSECTOR_MAP_NODE node = FindCacheNode(curSector);
        KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);

        if (!node) {
            // 场景 1: 该扇区从未被缓存过
            PUCHAR temp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, 'TmpB');
            if (!temp) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
            RtlZeroMemory(temp, 512);

            // 如果不是写满整整 512 字节，属于非对齐非完整写入，必须先读取原盘数据进行合并 (Read-Modify-Write)
            if (sectorOff != 0 || copySize != 512) {
                status = ReadOriginalSector(curSector, temp);
                if (!NT_SUCCESS(status)) { ExFreePoolWithTag(temp, 'TmpB'); break; }
            }

            ULONGLONG diffSec = AllocDiffSector();
            if (diffSec == MAXULONGLONG) {
                ExFreePoolWithTag(temp, 'TmpB');
                status = STATUS_DISK_FULL;
                break;
            }

            // 合并新旧数据并写入物理差异区
            RtlCopyMemory(temp + sectorOff, src, copySize);
            status = WriteDiffSector(diffSec, temp);
            ExFreePoolWithTag(temp, 'TmpB');
            if (!NT_SUCCESS(status)) break;

            // 建立哈希映射节点
            PSECTOR_MAP_NODE newNode = (PSECTOR_MAP_NODE)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(SECTOR_MAP_NODE), 'SecC');
            if (!newNode) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
            newNode->OrigSector = curSector;
            newNode->DiffSector = diffSec;

            // 重新拿锁写入映射表
            KeAcquireSpinLock(&g_SectorCache.Lock, &oldIrql);
            PSECTOR_MAP_NODE dup = FindCacheNode(curSector);
            if (dup) {
                // 并发竞态处理：在释放锁的空档里被其他线程捷足先登了
                KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);
                ExFreePoolWithTag(newNode, 'SecC');

                // 重新读取刚才别人写进去的差异区数据进行合并更新
                PUCHAR buf2 = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, 'TmpB');
                if (!buf2) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
                status = ReadDiffSector(dup->DiffSector, buf2);
                if (!NT_SUCCESS(status)) { ExFreePoolWithTag(buf2, 'TmpB'); break; }
                RtlCopyMemory(buf2 + sectorOff, src, copySize);
                status = WriteDiffSector(dup->DiffSector, buf2);
                ExFreePoolWithTag(buf2, 'TmpB');
                if (!NT_SUCCESS(status)) break;
            }
            else {
                InsertHeadList(&g_SectorCache.Buckets[GetHashIndex(curSector)], &newNode->ListEntry);
                RtlSetBit(&g_SectorCache.Bitmap, (ULONG)curSector);
                KeReleaseSpinLock(&g_SectorCache.Lock, oldIrql);
            }
        }
        else {
            // 场景 2: 该扇区之前已经被重定向缓存过了，直接更新已存在的重定向块
            PUCHAR buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, 'TmpB');
            if (!buf) { status = STATUS_INSUFFICIENT_RESOURCES; break; }

            status = ReadDiffSector(node->DiffSector, buf);
            if (!NT_SUCCESS(status)) { ExFreePoolWithTag(buf, 'TmpB'); break; }

            RtlCopyMemory(buf + sectorOff, src, copySize);
            status = WriteDiffSector(node->DiffSector, buf);
            ExFreePoolWithTag(buf, 'TmpB');
            if (!NT_SUCCESS(status)) break;
        }

        src += copySize;
        remaining -= copySize;
        curSector++;
    }

    return status;
}


VOID HandleScsiSrbPassThrough(PDEVICE_OBJECT DeviceObject, PSCSI_REQUEST_BLOCK Srb)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    if (!Srb || !g_SectorCache.Initialized) return;

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
        if (Srb->DataTransferLength >= (sectorCount * 512))
        {
            LARGE_INTEGER byteOffset;
            byteOffset.QuadPart = lba * 512;

            // 完美对齐 4 个参数调用，拦截物理直通写入
            SectorCacheWrite(lba, sectorCount * 512, (PUCHAR)Srb->DataBuffer, byteOffset);
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
        }
    }
}

// ======================== ATA 统一解析与影子重定向 ========================
BOOLEAN HandleAtaPassThroughIntercept(PATA_PASS_THROUGH_EX AtaControl, BOOLEAN isDirect)
{
    if (!AtaControl || !g_SectorCache.Initialized) return FALSE;

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

        if (sectorCount > 0)
        {
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
                SectorCacheWrite(lba, sectorCount * 512, dataBuffer, byteOffset);

                AtaControl->CurrentTaskFile[6] = 0x00; // 抹除硬件层指令
                return TRUE;
            }
        }
    }
    return FALSE;
}
// ======================== 下层标准派遣 Hook 挂接 ========================

NTSTATUS DiskHook_DispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // 直接彻底取消 DriverContext 判定，因为外部生成的正常 IRP 压根进不来递归
    if (DeviceObject != g_SystemDiskDevice || !g_SectorCache.Initialized)
        return g_OriginalDiskRead(DeviceObject, Irp);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG length = stack->Parameters.Read.Length;
    if (length == 0)
        return g_OriginalDiskRead(DeviceObject, Irp);

    ULONGLONG startSec = stack->Parameters.Read.ByteOffset.QuadPart / 512;
    ULONGLONG endSec = (stack->Parameters.Read.ByteOffset.QuadPart + length - 1) / 512;

    BOOLEAN needCache = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_SectorCache.Lock, &irql);
    for (ULONGLONG sec = startSec; sec <= endSec; sec++) {
        if (RtlCheckBit(&g_SectorCache.Bitmap, (ULONG)sec)) {
            needCache = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SectorCache.Lock, irql);

    if (!needCache)
        return g_OriginalDiskRead(DeviceObject, Irp);

    PUCHAR dest = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
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

    while (remaining > 0) {
        ULONG sectorOff = (ULONG)((byteOffset.QuadPart + (destPtr - dest)) % 512);
        ULONG copySize = min(512 - sectorOff, remaining);

        KeAcquireSpinLock(&g_SectorCache.Lock, &irql);
        PSECTOR_MAP_NODE node = FindCacheNode(curSector);
        ULONGLONG diffSec = node ? node->DiffSector : MAXULONGLONG;
        KeReleaseSpinLock(&g_SectorCache.Lock, irql);

        PUCHAR temp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, 'TmpB');
        if (!temp) { status = STATUS_INSUFFICIENT_RESOURCES; break; }

        if (diffSec != MAXULONGLONG)
            status = ReadDiffSector(diffSec, temp);
        else
            status = ReadOriginalSector(curSector, temp);

        if (!NT_SUCCESS(status)) { ExFreePoolWithTag(temp, 'TmpB'); break; }
        RtlCopyMemory(destPtr, temp + sectorOff, copySize);
        ExFreePoolWithTag(temp, 'TmpB');

        destPtr += copySize;
        remaining -= copySize;
        curSector++;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? length : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DiskHook_DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject != g_SystemDiskDevice || !g_SectorCache.Initialized)
        return g_OriginalDiskWrite(DeviceObject, Irp);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG length = stack->Parameters.Write.Length;
    if (length == 0)
        return g_OriginalDiskWrite(DeviceObject, Irp);

    if (!Irp->MdlAddress)
        return g_OriginalDiskWrite(DeviceObject, Irp);

    PVOID sysBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (!sysBuffer)
        return g_OriginalDiskWrite(DeviceObject, Irp);

    ULONGLONG startSector = stack->Parameters.Write.ByteOffset.QuadPart / 512;
    LARGE_INTEGER byteOffset = stack->Parameters.Write.ByteOffset;

    NTSTATUS status = SectorCacheWrite(startSector, length, (PUCHAR)sysBuffer, byteOffset);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? length : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// 获取磁盘总扇区数等其他辅助函数维持原样
NTSTATUS GetDiskSize(PDEVICE_OBJECT DiskDevice, PLARGE_INTEGER DiskSize)
{
    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    DISK_GEOMETRY geom = { 0 };

    PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY, DiskDevice, NULL, 0, &geom, sizeof(geom), FALSE, &event, NULL);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = IoCallDriver(DiskDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }
    if (NT_SUCCESS(status)) {
        DiskSize->QuadPart = geom.Cylinders.QuadPart * geom.TracksPerCylinder * geom.SectorsPerTrack * geom.BytesPerSector;
    }
    return status;
}
/*
NTSTATUS DiskHook_DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject != g_SystemDiskDevice || !g_OriginalDiskDeviceControl)
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

            if (HandleAtaPassThroughIntercept(pAta, isDirect))
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
    if (DeviceObject != g_SystemDiskDevice || !g_OriginalDiskDeviceControl)
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
            if (srb.SrbStatus == SRB_STATUS_SUCCESS)
            {
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
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
            if (HandleAtaPassThroughIntercept(pAta, isDirect))
            {
                // 核心修改：停止伪造 CurrentTaskFile[6] = 0x00，直接给应用层返回拒绝失败
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
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


NTSTATUS InitSectorCache(PDEVICE_OBJECT DiskDevice)
{
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

    RtlInitUnicodeString(&valName, L"DiffStartSector");
    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvi, sizeof(kvBuf), &resLen);
    if (!NT_SUCCESS(status)) { ZwClose(hKey); return status; }
    g_SectorCache.DiffAreaStart = *(ULONGLONG*)kvi->Data;

    RtlInitUnicodeString(&valName, L"DiffTotalSectors");
    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvi, sizeof(kvBuf), &resLen);
    if (!NT_SUCCESS(status)) { ZwClose(hKey); return status; }
    g_SectorCache.DiffAreaTotal = *(ULONGLONG*)kvi->Data;
    ZwClose(hKey);

    g_SectorCache.DiffAreaUsed = 0;
    LARGE_INTEGER diskSize;
    status = GetDiskSize(DiskDevice, &diskSize);
    if (!NT_SUCCESS(status)) return status;

    ULONGLONG totalSectors = diskSize.QuadPart / 512;
    if (totalSectors > 0xFFFFFFFF) totalSectors = 0xFFFFFFFF;

    ULONG bitmapBytes = (ULONG)((totalSectors + 7) / 8);
    g_SectorCache.BitmapBuffer = (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED, bitmapBytes, 'mBsh');
    if (!g_SectorCache.BitmapBuffer) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_SectorCache.BitmapBuffer, bitmapBytes);
    RtlInitializeBitMap(&g_SectorCache.Bitmap, g_SectorCache.BitmapBuffer, (ULONG)totalSectors);

    for (int i = 0; i < HASH_BUCKETS; i++)
        InitializeListHead(&g_SectorCache.Buckets[i]);

    KeInitializeSpinLock(&g_SectorCache.Lock);
    g_SectorCache.TotalSectors = (ULONG)totalSectors;
    g_SectorCache.Initialized = TRUE;
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
    if (g_SectorCache.BitmapBuffer) {
        ExFreePoolWithTag(g_SectorCache.BitmapBuffer, 'BMap');
        g_SectorCache.BitmapBuffer = NULL;
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
}

NTSTATUS DiskHook_Initialize(PDRIVER_DISPATCH DeviceControl)
{
    return DiskHook_SetToMajorFunction(DeviceControl);
}

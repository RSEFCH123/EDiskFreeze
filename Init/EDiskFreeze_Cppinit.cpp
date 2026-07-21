#include <windows.h>
#include <winioctl.h>
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

#define REG_KEY L"SYSTEM\\CurrentControlSet\\Services\\EDiskFreezeDrv64\\Parameters"

// 获取系统盘物理磁盘号和系统分区信息
BOOL GetSystemDiskInfo(DWORD* outDiskNum, ULONGLONG* outDiskTotalBytes,
    ULONGLONG* outSysPartStartBytes, ULONGLONG* outSysPartSizeBytes,
    DWORD* outSysPartNum)
{
    // 找系统盘盘符
    WCHAR sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    WCHAR driveLetter = sysDir[0]; // 通常是 C

    WCHAR volPath[8];
    swprintf_s(volPath, L"%c:\\", driveLetter);

    // 获取卷的物理磁盘号
    WCHAR volDevice[32];
    swprintf_s(volDevice, L"\\\\.\\%c:", driveLetter);
    HANDLE hVol = CreateFileW(volDevice, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return FALSE;

    VOLUME_DISK_EXTENTS extents;
    DWORD bytesRet;
    if (!DeviceIoControl(hVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        NULL, 0, &extents, sizeof(extents), &bytesRet, NULL)) {
        CloseHandle(hVol);
        return FALSE;
    }
    CloseHandle(hVol);

    *outDiskNum = extents.Extents[0].DiskNumber;
    ULONGLONG sysPartStart = extents.Extents[0].StartingOffset.QuadPart;
    ULONGLONG sysPartSize = extents.Extents[0].ExtentLength.QuadPart;

    // 打开物理磁盘
    WCHAR diskPath[32];
    swprintf_s(diskPath, L"\\\\.\\PhysicalDrive%lu", *outDiskNum);
    HANDLE hDisk = CreateFileW(diskPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return FALSE;

    // 获取磁盘总大小
    DISK_GEOMETRY_EX geomEx;
    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL, 0, &geomEx, sizeof(geomEx), &bytesRet, NULL)) {
        CloseHandle(hDisk);
        return FALSE;
    }
    *outDiskTotalBytes = geomEx.DiskSize.QuadPart;

    // 获取分区布局，找到系统分区号
    DWORD layoutSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) +
        sizeof(PARTITION_INFORMATION_EX) * 32;
    BYTE* layoutBuf = (BYTE*)malloc(layoutSize);
    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL, 0, layoutBuf, layoutSize, &bytesRet, NULL)) {
        free(layoutBuf); CloseHandle(hDisk); return FALSE;
    }

    DRIVE_LAYOUT_INFORMATION_EX* layout = (DRIVE_LAYOUT_INFORMATION_EX*)layoutBuf;
    *outSysPartNum = 0;
    for (DWORD i = 0; i < layout->PartitionCount; i++) {
        PARTITION_INFORMATION_EX* p = &layout->PartitionEntry[i];
        if (p->PartitionNumber == 0) continue;
        if ((ULONGLONG)p->StartingOffset.QuadPart == sysPartStart) {
            *outSysPartNum = p->PartitionNumber;
            break;
        }
    }

    free(layoutBuf);
    CloseHandle(hDisk);

    *outSysPartStartBytes = sysPartStart;
    *outSysPartSizeBytes = sysPartSize;
    return (*outSysPartNum != 0);
}

// 按磁盘总大小决定差异区大小
// sysPartFreeBytes: 系统分区当前空闲字节数
// maxShrinkBytes:   diskpart shrink querymax 报告的实际可压缩字节数（0表示未知/跳过此限制）
ULONGLONG CalcDiffSizeBytes(ULONGLONG diskTotalBytes, ULONGLONG sysPartFreeBytes,
    ULONGLONG maxShrinkBytes, BOOL* outFailed)
{
    *outFailed = FALSE;
    ULONGLONG GB = 1024ULL * 1024 * 1024;

    // 至少为系统分区保留 5 GB，避免 Windows 运转困难
    const ULONGLONG RESERVE = 5ULL * GB;

    ULONGLONG wanted;
    if (diskTotalBytes < 32ULL * GB) wanted = 4ULL * GB;
    else if (diskTotalBytes < 64ULL * GB) wanted = 8ULL * GB;
    else if (diskTotalBytes < 256ULL * GB) wanted = 20ULL * GB;
    else                                    wanted = 20ULL * GB;

    // 受文件系统实际可压缩量限制（若已查询）
    if (maxShrinkBytes > 0 && wanted > maxShrinkBytes)
        wanted = maxShrinkBytes;

    // 逐级退：不能超过 wanted，且压缩后系统分区至少剩 RESERVE
    ULONGLONG candidates[] = { wanted, 20ULL * GB, 8ULL * GB, 4ULL * GB };
    for (int i = 0; i < 4; i++) {
        if (candidates[i] > wanted) continue; // 不能比期望值大
        if (sysPartFreeBytes > candidates[i] + RESERVE)
            return candidates[i];
    }

    *outFailed = TRUE;
    return 0;
}

// 获取卷空闲空间
ULONGLONG GetVolumeFreeBytes(WCHAR driveLetter)
{
    WCHAR path[8];
    swprintf_s(path, L"%c:\\", driveLetter);
    ULARGE_INTEGER freeBytes;
    if (!GetDiskFreeSpaceExW(path, &freeBytes, NULL, NULL))
        return 0;
    return freeBytes.QuadPart;
}

BOOL WriteRegistry(ULONGLONG startLBA, ULONGLONG totalSectors)
{
    HKEY hKey;
    LONG ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY,
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (ret != ERROR_SUCCESS) return FALSE;

    RegSetValueExW(hKey, L"DiffStartSector", 0, REG_QWORD,
        (BYTE*)&startLBA, sizeof(ULONGLONG));
    RegSetValueExW(hKey, L"DiffTotalSectors", 0, REG_QWORD,
        (BYTE*)&totalSectors, sizeof(ULONGLONG));

    RegCloseKey(hKey);
    return TRUE;
}

// 运行 diskpart shrink querymax，返回文件系统实际允许的最大压缩量(MB)
// 失败或无法解析时返回 0
ULONGLONG QueryMaxShrinkMB(DWORD diskNum, DWORD partNum)
{
    WCHAR scriptPath[MAX_PATH], outPath[MAX_PATH];
    GetTempPathW(MAX_PATH, scriptPath);
    GetTempPathW(MAX_PATH, outPath);
    wcscat_s(scriptPath, L"qmax_script.txt");
    wcscat_s(outPath, L"qmax_out.txt");

    FILE* f;
    _wfopen_s(&f, scriptPath, L"w");
    if (!f) return 0;
    fprintf(f, "select disk %lu\n", diskNum);
    fprintf(f, "select partition %lu\n", partNum);
    fprintf(f, "shrink querymax\n");
    fclose(f);

    // 用 cmd /c 把 diskpart stdout 重定向到临时文件
    WCHAR cmd[MAX_PATH * 2 + 64];
    swprintf_s(cmd, L"cmd.exe /c diskpart /s \"%s\" > \"%s\" 2>&1",
        scriptPath, outPath);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DeleteFileW(scriptPath);
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteFileW(scriptPath);

    // 解析输出：找紧跟 " MB" 的数字（中/英文 Windows 输出格式均适用）
    FILE* out;
    _wfopen_s(&out, outPath, L"r");
    ULONGLONG maxMB = 0;
    if (out) {
        char line[512];
        while (fgets(line, sizeof(line), out)) {
            char* mb = strstr(line, " MB");
            if (!mb) mb = strstr(line, " mb");
            if (!mb) continue;
            // 向左找数字
            char* p = mb - 1;
            while (p >= line && *p == ' ') p--;
            if (p < line || !isdigit((unsigned char)*p)) continue;
            while (p > line && isdigit((unsigned char)*(p - 1))) p--;
            ULONGLONG v = (ULONGLONG)atoll(p);
            if (v > 0) { maxMB = v; break; }
        }
        fclose(out);
    }
    DeleteFileW(outPath);
    return maxMB;
}

BOOL RunDiskpart(const WCHAR* scriptPath)
{
    WCHAR cmd[MAX_PATH + 32];
    swprintf_s(cmd, L"diskpart /s \"%s\"", scriptPath);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return FALSE;

    WaitForSingleObject(pi.hProcess, 60000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (exitCode == 0);
}

int wmain()
{
    // 需要管理员权限
    DWORD diskNum;
    ULONGLONG diskTotalBytes, sysPartStart, sysPartSize;
    DWORD sysPartNum;

    printf("Reading disk info...\n");
    if (!GetSystemDiskInfo(&diskNum, &diskTotalBytes, &sysPartStart, &sysPartSize, &sysPartNum)) {
        printf("Failed to get system disk info.\n");
        return 1;
    }

    WCHAR sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    WCHAR driveLetter = sysDir[0];

    ULONGLONG freeBytes = GetVolumeFreeBytes(driveLetter);
    printf("Disk total: %llu GB, Partition free: %llu GB\n",
        diskTotalBytes / (1024 * 1024 * 1024),
        freeBytes / (1024 * 1024 * 1024));

    // 先查文件系统实际可压缩量，避免 diskpart 报"压缩太大"
    printf("Querying max shrinkable size...\n");
    ULONGLONG maxShrinkMB = QueryMaxShrinkMB(diskNum, sysPartNum);
    if (maxShrinkMB > 0)
        printf("Max shrinkable: %llu MB\n", maxShrinkMB);
    else
        printf("querymax unavailable, will rely on free-space estimate.\n");
    ULONGLONG maxShrinkBytes = maxShrinkMB * 1024ULL * 1024;

    BOOL failed;
    ULONGLONG diffSizeBytes = CalcDiffSizeBytes(diskTotalBytes, freeBytes,
        maxShrinkBytes, &failed);
    if (failed) {
        ULONGLONG GB = 1024ULL * 1024 * 1024;

        // 计算强制安装时实际能用的大小：可压缩量 - 1GB 保底，最小 1GB
        ULONGLONG forceMax = (maxShrinkBytes > 0) ? maxShrinkBytes : freeBytes;
        ULONGLONG forceSizeBytes = 0;
        if (forceMax > 1ULL * GB)
            forceSizeBytes = forceMax - 1ULL * GB; // 强制模式只留 1GB
        // 向下对齐到 1MB
        forceSizeBytes = (forceSizeBytes / (1024ULL * 1024)) * (1024ULL * 1024);

        printf("\n");
        printf("警告：磁盘空间不足！\n");
        printf("  当前 C 盘空闲: %llu MB\n", freeBytes / (1024 * 1024));
        printf("  最小安全需求: 4096 MB (差异区) + 5120 MB (系统保留) = 9216 MB\n");
        if (forceSizeBytes > 0) {
            printf("  强制安装可用: %llu MB (仅留 1GB 给系统，存在风险)\n",
                forceSizeBytes / (1024 * 1024));
        }
        else {
            printf("  空间过小，无法强制安装。\n");
            return 1;
        }
        printf("\n是否强制安装？系统分区剩余空间将极少，可能导致系统不稳定。[y/N] ");
        fflush(stdout);

        char answer[8] = {};
        if (!fgets(answer, sizeof(answer), stdin) ||
            (answer[0] != 'y' && answer[0] != 'Y')) {
            printf("已取消。\n");
            return 1;
        }

        printf("用户确认强制安装，差异区大小: %llu MB\n",
            forceSizeBytes / (1024 * 1024));
        diffSizeBytes = forceSizeBytes;
    }

    ULONGLONG diffSizeMB = diffSizeBytes / (1024 * 1024);
    printf("Will create diff partition: %llu MB\n", diffSizeMB);

    // 生成 diskpart 脚本
    WCHAR scriptPath[MAX_PATH];
    GetTempPathW(MAX_PATH, scriptPath);
    wcscat_s(scriptPath, L"diffpart.txt");

    FILE* f;
    _wfopen_s(&f, scriptPath, L"w");
    if (!f) { printf("Failed to create script.\n"); return 1; }

    fprintf(f, "select disk %lu\n", diskNum);
    fprintf(f, "select partition %lu\n", sysPartNum);
    fprintf(f, "shrink desired=%llu minimum=%llu\n", diffSizeMB, diffSizeMB);
    fprintf(f, "create partition primary\n");
    fprintf(f, "set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac\n"); // Windows RE / 隐藏用途GUID，不会被自动挂载
    fprintf(f, "gpt attributes=0x8000000000000000\n"); // 不自动分配盘符
    fclose(f);

    printf("Running diskpart...\n");
    if (!RunDiskpart(scriptPath)) {
        printf("diskpart failed.\n");
        DeleteFileW(scriptPath);
        return 1;
    }
    DeleteFileW(scriptPath);

    // diskpart shrink后新分区紧接在系统分区末尾
    // 系统分区新大小 = 原大小 - diffSizeBytes
    // 新分区起始 = sysPartStart + (sysPartSize - diffSizeBytes)
    // 对齐到1MB
    ULONGLONG oneMB = 1024ULL * 1024;
    ULONGLONG shrinkAligned = (diffSizeBytes / oneMB) * oneMB;
    ULONGLONG newPartStart = sysPartStart + sysPartSize - shrinkAligned;
    // 再对齐到1MB边界
    newPartStart = (newPartStart / oneMB) * oneMB;
    ULONGLONG newPartStartLBA = newPartStart / 512;
    ULONGLONG diffTotalSectors = shrinkAligned / 512;

    printf("DiffStartSector: %llu\n", newPartStartLBA);
    printf("DiffTotalSectors: %llu\n", diffTotalSectors);

    if (!WriteRegistry(newPartStartLBA, diffTotalSectors)) {
        printf("Failed to write registry.\n");
        return 1;
    }

    printf("Done. Please reboot to take effect.\n");
    return 0;
}
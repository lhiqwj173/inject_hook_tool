#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

#include "../../sharedata.hpp"
#include "../../module_helper.hpp"

// 获取进程句柄
HANDLE GetThePidOfTargetProcess(DWORD pid)
{
    HANDLE hProcee = ::OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD, 0, pid);
    return hProcee;
}

// 获取模块句柄
HMODULE GetProcessModuleHandleByName(DWORD pid, LPCSTR ModuleName)
{
    MODULEENTRY32 ModuleInfo;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (!hSnapshot)
    {
        return 0;
    }
    ZeroMemory(&ModuleInfo, sizeof(MODULEENTRY32));
    ModuleInfo.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnapshot, &ModuleInfo))
    {
        return 0;
    }
    do
    {
        if (!lstrcmpi(ModuleInfo.szModule, ModuleName))
        {
            CloseHandle(hSnapshot);
            return ModuleInfo.hModule;
        }
    } while (Module32Next(hSnapshot, &ModuleInfo));
    CloseHandle(hSnapshot);
    return 0;
}

// 进程注入
BOOL DoInjection(char *DllPath, HANDLE hProcess)
{
    DWORD BufSize = strlen(DllPath) + 1;
    LPVOID AllocAddr = VirtualAllocEx(hProcess, NULL, BufSize, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, AllocAddr, DllPath, BufSize, NULL);
    PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");

    HANDLE hRemoteThread;
    hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pfnStartAddr, AllocAddr, 0, NULL);
    if (hRemoteThread)
    {
        printf("注入成功\n");
        return true;
    }
    else
    {
        printf("注入失败\n");
        return false;
    }
}

void UnInject(int pID, DWORD addr)
{
    // 获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);

    // 获取LoadLibraryA函数的地址
    HMODULE hModule = LoadLibrary("KERNEL32.DLL");
    LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");

    // 创建远程线程-并获取线程的句柄
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, (LPVOID)addr, 0, NULL);

    // 等待线程事件
    WaitForSingleObject(hThread, 2000);

    // 防止内存泄露
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main()
{
    // 1135
    char *dll = (char *)"D:\\code\\inject_hook_tool\\sharemem_test\\Release\\sharemem_test.dll";

    // 获取函数地址偏移
    DWORD func_diff = module_helper::get_func_diff(dll, (char *)"thread_func");
    printf("获取函数偏移：%x\n", func_diff);

    // 更具 title 获取 pid
    DWORD pid = 0;
    HWND hwnd = FindWindow(NULL, TEXT("代码注入器QQ:150330575—外挂教程上www.yjxsoft.com"));
    // HWND hwnd = FindWindow("TdxW_MainFrame_Class", NULL);
    GetWindowThreadProcessId(hwnd, &pid);

    module_helper::Up();
    HANDLE hP = GetThePidOfTargetProcess(pid);

    // 获得PE文件句柄
    HANDLE hFile = CreateFile(dll, GENERIC_ALL, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);

    // 创建一个新的文件映射内核对象
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);

    // 将一个文件映射对象映射到内存,得到指向映射到内存的第一个字节的指针pbFile
    PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    // 检查
    if (INVALID_HANDLE_VALUE == hFile || NULL == hMapping || NULL == pbFile)
    {
        if (NULL != pbFile)
        {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping)
        {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }

        return 0;
    }

    // pDosHeader指向DOS头起始位置
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbFile;
    printf("PE Header e_lfanew：0x%x\n", pDosHeader->e_lfanew);

    // 计算PE头位置
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);

    // 计算DLL模块镜像大小
    DWORD dwSizeOfImage = (DWORD)pNTHeader->OptionalHeader.SizeOfImage;
    printf("SizeOfImage: 0x%08X\n", dwSizeOfImage);

    UnmapViewOfFile(pbFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    // 注入
    DoInjection(dll, hP);

    DWORD addr_start = 0;
    while (1)
    {
        addr_start = (DWORD)GetProcessModuleHandleByName(pid, "sharemem_test.dll");
        if (addr_start > 0)
        {
            break;
        }
    }

    // 申请内存
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD dwOldProtect;
    LPVOID lpaddress = VirtualAllocEx(hProcess, NULL, dwSizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    printf("分配地址：0x%x\n", (DWORD)lpaddress);
    VirtualProtectEx(hProcess, lpaddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // // 测试调用远程函数
    // DWORD cll_func1 = addr_start + func_diff;
    // CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)cll_func1, NULL, 0, NULL);
    // printf("调用远程函数0x%x error:%d\n", cll_func1, GetLastError());

    // 保存数组
    BYTE *code = new BYTE[dwSizeOfImage];
    DWORD lp_copy = (DWORD)lpaddress;
    DWORD lp_start = addr_start;
    printf("原地址 = 0x%x 拷贝地址 = 0x%x\n", addr_start, (DWORD)lpaddress);

    ReadProcessMemory(hProcess, (LPCVOID)lp_start, code, dwSizeOfImage, NULL);
    WriteProcessMemory(hProcess, (LPVOID)lp_copy, code, dwSizeOfImage, NULL);
    // for (int i = 0; i < dwSizeOfImage; i++, lp_start++, lp_copy++)
    // {
    //     ReadProcessMemory(hProcess, (LPCVOID)lp_start, code, 1, NULL);
    //     WriteProcessMemory(hProcess, (LPVOID)lp_copy, code, 1, NULL);
    // }

    // 卸载原dll
    UnInject(pid, addr_start);

    // 还原DLL镜像至原地址
    DWORD returnValue = (DWORD)VirtualAllocEx(hProcess, (LPVOID)addr_start, dwSizeOfImage + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("原地址 = 0x%x 新地址 = 0x%x\n", addr_start, returnValue);

    ReadProcessMemory(hProcess, (LPCVOID)lpaddress, code, dwSizeOfImage, NULL);
    WriteProcessMemory(hProcess, (LPVOID)addr_start, code, dwSizeOfImage, NULL);
    VirtualProtectEx(hProcess, (LPVOID)addr_start, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 删除多余的内存
    BOOL res = VirtualFreeEx(hProcess, (LPVOID)lpaddress, 0, MEM_RELEASE);

    printf("还原完成! DLL隐藏完成!\n");

    // 调用远程函数
    DWORD cll_func2 = returnValue + func_diff;
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)cll_func2, (LPVOID)returnValue, 0, NULL);
    printf("调用远程函数0x%x 0x%x error:%d\n", cll_func2, (DWORD)returnValue, GetLastError());

    getchar();
    return 0;
}

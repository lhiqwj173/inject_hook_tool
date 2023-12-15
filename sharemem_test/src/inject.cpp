#include <windows.h>
#include <iostream>
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

int main()
{
    sharedata d({sharedata::SIZE_T, sharedata::SIZE_T}, "TEST");
    if (d.init())
    {
        // 更具 title 获取 pid
        DWORD pid = 0;
        HWND hwnd = FindWindow(NULL, TEXT("代码注入器QQ:150330575—外挂教程上www.yjxsoft.com"));
        GetWindowThreadProcessId(hwnd, &pid);

        module_helper::Up();
        HANDLE hP = GetThePidOfTargetProcess(pid);
        // 开始注入
        // 这里填写Dll路径
        // DoInjection((char *)"D:\\code\\inject_hook_tool\\sharemem_test\\Release\\sharemem_test.dll", hP);
        DoInjection((char *)"D:\\code\\inject_hook_tool\\free_fail_test\\dllmain.dll", hP);

        while (1)
        {
            d.cache_update();
            printf("1: %zu 2: %zu\n", *(size_t *)d.read(0), *(size_t *)d.read(1));

            Sleep(1000);
        }
    }
}

#include <windows.h>
#include <iostream>
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

// 获取进程句柄
HANDLE GetThePidOfTargetProcess(DWORD pid)
{
    HANDLE hProcee = ::OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD, 0, pid);
    return hProcee;
}
// 提升权限
void Up()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid = luid;
    AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
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
    // 输入PID
    DWORD pid;
    std::cout << "请输入PID: ";
    std::cin >> pid;

    Up();
    HANDLE hP = GetThePidOfTargetProcess(pid);
    // 开始注入
    // 这里填写Dll路径
    DoInjection((char *)"D:\\code\\hook\\inject\\Release\\inject_test.dll", hP);
}
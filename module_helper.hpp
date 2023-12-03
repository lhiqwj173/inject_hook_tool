#pragma once
#include <windows.h>
#include <iostream>

class module_helper
{
private:
    inline static DWORD oldp = NULL;
    inline static DWORD newp = NULL;

public:
    // 新开辟空间 隐藏dll
    static DWORD HideModule(HMODULE hModule)
    {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;                          // DOS 头
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew); // NT 头

        // 1.申请空间
        PBYTE mem = (PBYTE)VirtualAlloc(0, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (NULL == mem)
        {
            // 申请空间失败,做些啥.....
            return NULL;
        }

        // 2.拷贝到新的空间
        memcpy(mem, (void *)hModule, pNt->OptionalHeader.SizeOfImage);

        // 3.修复重定位   数据目录第6项是重定位表
        PIMAGE_BASE_RELOCATION rBase = (PIMAGE_BASE_RELOCATION)((DWORD)mem + pNt->OptionalHeader.DataDirectory[5].VirtualAddress);
        DWORD n = 0;
        DWORD Base = (DWORD)mem;
        DWORD offset = (DWORD)mem - (DWORD)hModule; //
        if (offset == 0)
            (DWORD) mem;

        typedef struct RELOCATIONITEM
        {
            WORD value : 12;
            WORD attr : 4;

        } *PRELOCATIONITEM;
        PRELOCATIONITEM rItem;
        DWORD *item;
        while (true)
        {
            if (rBase->SizeOfBlock == 0)
                break;
            rItem = (PRELOCATIONITEM)((PBYTE)rBase + 8);
            n = (rBase->SizeOfBlock - 8) / 2;
            for (int i = 0; i < n; ++i)
            {
                if (3 == rItem[i].attr)
                {
                    item = (DWORD *)(Base + rBase->VirtualAddress + rItem[i].value);
                    *item = (*item + offset);
                }
            }

            rBase = (PIMAGE_BASE_RELOCATION)((PBYTE)rBase + rBase->SizeOfBlock); // 指向下一个结构
        }

        oldp = (DWORD)hModule;
        newp = (DWORD)mem;

        return newp;
    }

    // 返回新的函数地址
    static DWORD new_func(DWORD func)
    {
        return newp + (func - oldp);
    }

    // 提升权限
    static bool Up()
    {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            printf("打开进程的访问令牌失败\n");
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            printf("查看进程相关的特权信息失败\n");
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        tp.Privileges[0].Luid = luid;
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
        {
            printf("调整令牌特权失败\n");
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }
};
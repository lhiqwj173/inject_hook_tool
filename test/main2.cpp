/************************************************************************/
/* 把当前进程的所有DLL（除开需要隐藏的那个）都使用LoadLibrary再次加载一边，增加引用计数，                */
/* 使得Free时对应的DLL资源不释放                                            */
/************************************************************************/
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>

void LockAllModules()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 me = {sizeof(me)};

        BOOL fOk = Module32First(hSnapshot, &me);
        for (fOk = Module32Next(hSnapshot, &me); fOk; fOk = Module32Next(hSnapshot, &me))
        {
            // 跳过第一个(自身)
            std::string wInfo = me.szModule;
            if (wInfo != "dlls.dll")
                LoadLibrary(me.szModule); // 加载除了dlls.dll以外的所有内存
        }
    }
}

BOOL CopycatAndHide(HMODULE hDll)
{
    // 整体思路：先把DLL加载到当前进程，然后将该加载的DLL再备份到当前进程空间；
    // 接下来该DLL再Free了，此时进程再访问该DLL的话会出错；
    // Free后，再把预先备份的DLL数据还原，而且还原的数据地址是原先DLL加载的地址
    // 如此，进程内再调用该DLL的话，由于数据完整，一切OK

    DWORD g_dwImageSize = 0;
    VOID *g_lpNewImage = NULL;

    IMAGE_DOS_HEADER *pDosHeader;
    IMAGE_NT_HEADERS *pNtHeader;
    IMAGE_OPTIONAL_HEADER *pOptionalHeader;
    LPVOID lpBackMem = 0;
    DWORD dwOldProtect;
    DWORD dwCount = 30;

    pDosHeader = (IMAGE_DOS_HEADER *)hDll;
    pNtHeader = (IMAGE_NT_HEADERS *)(pDosHeader->e_lfanew + (DWORD)hDll);
    pOptionalHeader = (IMAGE_OPTIONAL_HEADER *)&pNtHeader->OptionalHeader;

    LockAllModules();

    // 找一块内存把需要隐藏而且已经加载到内存的DLL备份
    // SizeOfImage，4个字节，表示程序调入后占用内存大小（字节），等于所有段的长度之和。
    lpBackMem = VirtualAlloc(0, pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpBackMem)
        return FALSE;
    if (!VirtualProtect((LPVOID)hDll, pOptionalHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return FALSE;

    g_dwImageSize = pOptionalHeader->SizeOfImage;
    memcpy(lpBackMem, (LPVOID)hDll, g_dwImageSize);
    // 抹掉PE头
    // memset(lpBackMem, 0, 0x200);
    *((PBYTE)hDll + pOptionalHeader->AddressOfEntryPoint) = (BYTE)0xc3;

    //  DWORD dwRet =0;
    // Free掉DLL
    do
    {
        dwCount--;
    } while (FreeLibrary(hDll) && dwCount);

    // 把备份的DLL数据还原回来，使得预先引用该DLL的程序能够继续正常运行
    g_lpNewImage = VirtualAlloc((LPVOID)hDll, g_dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (g_lpNewImage != (LPVOID)hDll)
        return FALSE;

    memcpy(g_lpNewImage, lpBackMem, g_dwImageSize);
    VirtualFree(lpBackMem, 0, MEM_RELEASE);

    return TRUE;
}

int main()
{
    HMODULE = GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
    CopycatAndHide(NULL);
}
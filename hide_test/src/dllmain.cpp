#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <Psapi.h>

#pragma comment(lib, "user32.lib")

std::string get_module_name(HMODULE h)
{
	char dllPath[MAX_PATH];
	GetModuleFileName(h, dllPath, MAX_PATH);

	// 提取文件名部分
	char *dllFileName = dllPath;
	char *lastSeparator = strrchr(dllPath, '\\');
	if (lastSeparator != NULL)
	{
		dllFileName = lastSeparator + 1;
	}
	else
	{
		char *lastSlash = strrchr(dllPath, '/');
		if (lastSlash != NULL)
		{
			dllFileName = lastSlash + 1;
		}
	}

	return dllFileName;
}

void LockAllModules(std::string need_hide, std::string self)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 me = {sizeof(me)};

		BOOL fOk = Module32First(hSnapshot, &me);
		for (fOk = Module32Next(hSnapshot, &me); fOk; fOk = Module32Next(hSnapshot, &me))
		{
			// 跳过第一个(自身)
			std::string Info = me.szModule;
			if (Info != need_hide && Info != self)
				LoadLibrary(me.szModule);
		}
	}
}

BOOL CopycatAndHide(std::string need_hide, std::string self)
{
	// 整体思路：先把DLL加载到当前进程，然后将该加载的DLL再备份到当前进程空间；
	// 接下来该DLL再Free了，此时进程再访问该DLL的话会出错；
	// Free后，再把预先备份的DLL数据还原，而且还原的数据地址是原先DLL加载的地址
	// 如此，进程内再调用该DLL的话，由于数据完整，一切OK

	HMODULE hDll = GetModuleHandle(need_hide.data());
	if (!hDll)
	{
		// MessageBox(NULL, "获取模块失败", "提示", MB_OK);
		return FALSE;
	}
	// MessageBox(NULL, (std::to_string((int)hDll)).data(), "提示", MB_OK);

	DWORD g_dwImageSize = 0;
	VOID *g_lpNewImage = NULL;

	IMAGE_DOS_HEADER *pDosHeader;
	IMAGE_NT_HEADERS *pNtHeader;
	IMAGE_OPTIONAL_HEADER *pOptionalHeader;
	LPVOID lpBackMem = 0;
	DWORD dwOldProtect;
	DWORD dwCount = 100;

	pDosHeader = (IMAGE_DOS_HEADER *)hDll;
	pNtHeader = (IMAGE_NT_HEADERS *)(pDosHeader->e_lfanew + (DWORD)hDll);
	pOptionalHeader = (IMAGE_OPTIONAL_HEADER *)&pNtHeader->OptionalHeader;

	LockAllModules(need_hide, self);

	// 找一块内存把需要隐藏而且已经加载到内存的DLL备份
	// SizeOfImage，4个字节，表示程序调入后占用内存大小（字节），等于所有段的长度之和。
	lpBackMem = VirtualAlloc(0, pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpBackMem)
	{
		// MessageBox(NULL, "VirtualAlloc 备份地址失败", "提示", MB_OK);
		return FALSE;
	}
	if (!VirtualProtect((LPVOID)hDll, pOptionalHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		// MessageBox(NULL, "VirtualProtect 备份地址失败", "提示", MB_OK);
		return FALSE;
	}

	// MessageBox(NULL, (std::string("备份地址: ") + std::to_string((DWORD)lpBackMem)).data(), "提示", MB_OK);
	g_dwImageSize = pOptionalHeader->SizeOfImage;
	memcpy(lpBackMem, (LPVOID)hDll, g_dwImageSize);

	// 抹掉PE头
	memset(lpBackMem, 0, 0x200);
	*((PBYTE)hDll + pOptionalHeader->AddressOfEntryPoint) = (BYTE)0xc3;

	//  DWORD dwRet =0;
	// Free掉DLL
	do
	{
		dwCount--;
	} while (FreeLibrary(hDll) && dwCount);

	// 卸载检查
	HMODULE _needhide = GetModuleHandle(need_hide.data());
	if (_needhide != NULL)
	{
		// MessageBox(NULL, (std::string("卸载失败 error:") + std::to_string(GetLastError())).data(), "提示", MB_OK);
		VirtualFree(lpBackMem, 0, MEM_RELEASE);
		return FALSE;
	}
	else
	{
		// 把备份的DLL数据还原回来，使得预先引用该DLL的程序能够继续正常运行
		g_lpNewImage = VirtualAlloc((LPVOID)hDll, g_dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (g_lpNewImage != (LPVOID)hDll)
		{
			// MessageBox(NULL, "VirtualAlloc 源地址失败", "提示", MB_OK);
			return FALSE;
		}

		memcpy(g_lpNewImage, lpBackMem, g_dwImageSize);
		VirtualFree(lpBackMem, 0, MEM_RELEASE);

		return TRUE;
	}
}

BOOL WINAPI DllMain(_In_ void *_DllHandle, _In_ unsigned long _Reason, _In_opt_ void *_Reserved)
{
	switch (_Reason)
	{
	case DLL_PROCESS_ATTACH:
	{
		std::string self = get_module_name((HMODULE)_DllHandle);
		// std::string need_hide = "hook.dll";
		std::string need_hide = "dllmain.dll";
		// std::string need_hide = "helper.dll";
		// std::string need_hide = "sharemem_test.dll";

		// MessageBox(NULL, (std::string("开始隐藏: ") + need_hide).data(), "提示", MB_OK);

		if (CopycatAndHide(need_hide, self))
		{
			// MessageBox(NULL, "隐藏成功", "提示", MB_OK);
		}
		else
		{
			// 退出程序
			TerminateProcess(GetCurrentProcess(), 1);
		}
	}
	break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	return FALSE; // 完毕后直接卸载
}

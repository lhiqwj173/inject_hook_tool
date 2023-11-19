#include <windows.h>
#include <thread>
#pragma comment(lib, "User32.lib")

#include "../../hook.hpp"

DWORD HideModule(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;						  // DOS 头
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
	return (DWORD)mem;
}

void dll_func1(LPVOID notUse)
{
	MessageBox(NULL, "dll_func1", "提示", MB_OK);
}

void thread_func(LPVOID notUse)
{
	while (1)
	{
		dll_func1(NULL);
		Sleep(5000);
	}
}

void pop_esp_data(PCONTEXT p)
{
	// p->Esp: 0x0019F65C
	// [p->Esp]: 0x0041A860
	// [[p->Esp]]: http://yonken.blogcn.com

	// 弹窗
	MessageBox(NULL, (char *)(*(char **)(p->Esp)), "esp data:", MB_OK);

	// 更改数据
	const char *szStr = "hook";
	*(DWORD *)(p->Esp) = (DWORD)szStr;

	// 弹窗
	MessageBox(NULL, (char *)(*(char **)(p->Esp)), "new data:", MB_OK);

	// 原代码
	__asm mov ecx, edi;

	p->Eip += 2;
}

void dll_hook_func(LPVOID notUse)
{
	// hook
	hooker *h = hooker::get_instance();

	///////////////////////////////////////
	// 00405BEE               |.  8BCF          mov ecx,edi  << 目标位置 8B替换成CC, 读取esp中的字符串，手动执行__asm mov ecx,edi, 处理完毕后 eip+=2
	// 00405BF0               |.  C64424 18 01  mov byte ptr ss:[esp+0x18],0x1
	///////////////////////////////////////
	size_t addr = (size_t)GetModuleHandle(NULL) + 0x5BEE;
	h->set_hook(addr, pop_esp_data);
}

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD ul_reason_for_call,
					  LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		MessageBox(NULL, "注入成功", "提示", MB_OK);
		DWORD newModule = HideModule(hModule);
		if (newModule)
		{
			MessageBox(NULL, "隐藏dll", "提示", MB_OK);
			LPTHREAD_START_ROUTINE new_dll_func1 = (LPTHREAD_START_ROUTINE)(newModule + ((DWORD)dll_func1 - (DWORD)hModule));
			new_dll_func1(NULL);

			// hook
			LPTHREAD_START_ROUTINE new_dll_hook_func = (LPTHREAD_START_ROUTINE)(newModule + ((DWORD)dll_hook_func - (DWORD)hModule));
			new_dll_hook_func(NULL);

			// 创建线程
			LPTHREAD_START_ROUTINE new_thread_func = (LPTHREAD_START_ROUTINE)(newModule + ((DWORD)thread_func - (DWORD)hModule));
			HANDLE hThread = CreateThread(NULL, 0, new_thread_func, NULL, 0, NULL);
			if (hThread != NULL)
			{
				// 分离线程
				CloseHandle(hThread);
			}
		}

		MessageBox(NULL, "卸载原dll", "提示", MB_OK);
	}
	break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	return FALSE; // 返回false相当于卸载模块
}

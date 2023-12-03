#include <windows.h>
#include <thread>
#pragma comment(lib, "User32.lib")
#include "../../hook.hpp"
#include "../../sharedata.hpp"
#include "../../module_helper.hpp"

// 共享内存
sharedata *get_sharedata()
{
	static sharedata d({sharedata::SIZE_T, sharedata::SIZE_T}, "TEST");
	return &d;
}

void pop_esp_data(PCONTEXT p)
{
	// p->Esp: 0x0019F65C
	// [p->Esp]: 0x0041A860
	// [[p->Esp]]: http://yonken.blogcn.com

	static size_t b = 0;
	b++;

	sharedata *d = get_sharedata();
	d->set(&b, 0, sharedata::SIZE_T);
	d->cache_apply();

	// 更改数据
	const char *szStr = "hook";
	*(DWORD *)(p->Esp) = (DWORD)szStr;

	// 原代码
	__asm mov ecx, edi;

	p->Eip += 2;
}

void thread_func()
{
	if (!get_sharedata()->init())
	{
		return;
	}

	// 硬件断点 hook
	hooker_base *h = hooker_hard_break::get_instance();
	size_t addr[1] = {(size_t)GetModuleHandle(NULL) + 0x5BEE};
	hook_func func[1] = {pop_esp_data};
	h->set_hook(addr, func);
}

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD ul_reason_for_call,
					  LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		// MessageBox(NULL, "注入成功", "提示", MB_OK);

		DWORD newModule = module_helper::HideModule(hModule);
		if (newModule)
		{
			// MessageBox(NULL, "隐藏dll", "提示", MB_OK);

			// 创建线程
			DWORD new_thread_func = module_helper::new_func((DWORD)thread_func);
			HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)new_thread_func, NULL, 0, NULL);
			if (hThread != NULL)
			{
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

	// return TRUE;
	return FALSE; // 返回false相当于卸载模块
}

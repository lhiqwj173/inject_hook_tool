#include <windows.h>
#pragma comment(lib, "User32.lib")
#include "../../hook.hpp"
#include "../../sharedata.hpp"
// #include "../../module_helper.hpp"

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

	// static int count = 0;
	// if (count++ == 2)
	// {
	// 	// 抛出异常
	// 	int *a = nullptr;
	// 	*a = 1;
	// }

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

void thread_func(LPVOID Param)
{
	MessageBox(NULL, "thread_func", "提示", MB_OK);

	// 设置模块地址范围，出现模块代码异常时，生成dump文件
	// hook_data *_hook_data = hook_data::get_instance();
	// _hook_data->set_dll_hModule((DWORD)Param);

	// 初始化共享内存
	if (!get_sharedata()->init())
	{
		return;
	}

	// 硬件断点 hook
	hooker_base *h = hooker_hard_break::get_instance();

	DWORD addr[1] = {(size_t)GetModuleHandle(NULL) + 0x5BEE};
	DWORD func[1] = {(DWORD)pop_esp_data};
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
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_func, NULL, 0, NULL);
		if (hThread != NULL)
		{
			CloseHandle(hThread);
		}
		// MessageBox(NULL, "注入成功", "提示", MB_OK);

		// DWORD newModule = module_helper::HideModule(hModule);
		// if (newModule)
		// {
		// 	// MessageBox(NULL, "隐藏dll", "提示", MB_OK);
		// 	MessageBox(NULL, (std::string("newModule: ") + std::to_string((DWORD)newModule)).data(), "提示", MB_OK);

		// 	// 创建线程
		// 	DWORD new_thread_func = module_helper::new_func((DWORD)thread_func);
		// 	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)new_thread_func, (LPVOID)newModule, 0, NULL);
		// 	if (hThread != NULL)
		// 	{
		// 		CloseHandle(hThread);
		// 	}
		// }

		// MessageBox(NULL, "卸载原dll", "提示", MB_OK);
	}
	break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}

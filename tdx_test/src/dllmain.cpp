#include <windows.h>
#include <thread>
#pragma comment(lib, "User32.lib")
#include "../../hook.hpp"
#include "../../sharedata.hpp"
#include "../../module_helper.hpp"

// 获取共享内存
sharedata &get_sharedata()
{
	static sharedata d({sharedata::_DWORD, sharedata::_DWORD, sharedata::_DWORD}, "TDX");
	return d;
}

void ZBCJ(PCONTEXT p)
{
	// tdxw.exe+4C1A8B 		- 89 45 E0              - mov [ebp-20],eax   << 目标位置 读取esi中的地址，手动执行__asm mov [ebp-20],eax, 处理完毕后 eip+=0x3
	// 获取数据
	DWORD data = *(DWORD *)(p->Esi);

	// 更新到共享内存
	static sharedata &d = get_sharedata();
	d.set(&data, 0, sharedata::_DWORD);
	d.cache_apply();

	// 原代码
	__asm {
			mov[ebp - 20], eax}

	p->Eip += 0x3;
}

void ZBWT(PCONTEXT p)
{
	// 获取数据
	DWORD data = *(DWORD *)(p->Esi);

	// 更新到共享内存
	static sharedata &d = get_sharedata();
	d.set(&data, 1, sharedata::_DWORD);
	d.cache_apply();

	// 原代码
	__asm {
		and eax,ecx
	}

	p->Eip += 0x2;
}

void SNAPSHOT(PCONTEXT p)
{
	// 获取数据
	DWORD data = *(DWORD *)(p->Esi);

	// 更新到共享内存
	static sharedata &d = get_sharedata();
	d.set(&data, 2, sharedata::_DWORD);
	d.cache_apply();

	// 原代码
	__asm {
		xor eax,eax
	}

	p->Eip += 0x2;
}

void thread_func()
{
	MessageBox(NULL, "thread_func", "提示", MB_OK);

	if (!get_sharedata().init())
	{
		return;
	}

	// 硬件断点 hook
	///////////////////////////////////////
	// hook 逐笔成交数据
	// tdxw.exe+4C1A8B 		- 89 45 E0              - mov [ebp-20],eax   << 目标位置 读取esi中的地址，手动执行__asm mov [ebp-20],eax, 处理完毕后 eip+=0x3
	// 008C1A8B
	//
	// hook 逐笔委托数据
	// tdxw.exe+492F64	  |.  23C1          and eax,ecx 		<< 目标位置 读取esi中的地址，手动执行__asm and eax,ecx, 处理完毕后 eip+=0x2
	// 00892F64
	//
	// hook 切片数据
	// tdxw.exe+4D27E  |> \33C0          xor eax,eax  << 目标位置 读取esi中的地址，手动执行__asm xor eax,eax  , 处理完毕后 eip+=0x2
	// 0044D27E
	///////////////////////////////////////
	hooker_base *h = hooker_hard_break::get_instance();
	DWORD tdxw = (DWORD)GetModuleHandle(NULL);
	// DWORD addr[1] = {(DWORD)GetModuleHandle(NULL) + 0x4D27E};
	// DWORD func[1] = {(DWORD)SNAPSHOT};
	DWORD addr[3] = {tdxw + 0x4C1A8B, tdxw + 0x492F64, tdxw + 0x4D27E};
	DWORD func[3] = {(DWORD)ZBCJ, (DWORD)ZBWT, (DWORD)SNAPSHOT};

	for (int i = 0; i < sizeof(func) / sizeof(DWORD); i++)
	{
		MessageBox(NULL, (std::string("code:") + std::to_string(addr[i]) + " func:" + std::to_string(func[i])).data(), "提示", MB_OK);
	}

	h->set_hook(addr, func, 3);
}

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD ul_reason_for_call,
					  LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		MessageBox(NULL, "注入成功 12", "提示", MB_OK);
		DWORD newModule = module_helper::HideModule(hModule);
		if (newModule)
		{
			MessageBox(NULL, "隐藏dll", "提示", MB_OK);
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

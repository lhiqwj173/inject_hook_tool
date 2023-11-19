﻿#include "pch.h"
#include "../../hook.hpp"

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

BOOL WINAPI DllMain(_In_ void *_DllHandle, _In_ unsigned long _Reason, _In_opt_ void *_Reserved)
{
	switch (_Reason)
	{
	case DLL_PROCESS_ATTACH:
	{
		MessageBox(NULL, "注入成功", "提示", MB_OK);

		// hook
		hooker *h = hooker::get_instance();

		///////////////////////////////////////
		// 00405BEE               |.  8BCF          mov ecx,edi  << 目标位置 8B替换成CC, 读取esp中的字符串，手动执行__asm mov ecx,edi, 处理完毕后 eip+=2
		// 00405BF0               |.  C64424 18 01  mov byte ptr ss:[esp+0x18],0x1
		///////////////////////////////////////
		size_t addr = (size_t)GetModuleHandle(NULL) + 0x5BEE;
		MessageBox(NULL, (std::string("Address: ") + std::to_string(addr)).data(), "断点地址", MB_OK);

		h->set_hook(addr, pop_esp_data);
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

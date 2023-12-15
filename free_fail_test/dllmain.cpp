#include "pch.h"
#include <fstream>

class Data
{
private:
	std::ofstream LogFile;
	int a = 0;

public:
	Data()
	{
		MessageBox(NULL, "Data init", "提示", MB_OK);
		LogFile.open(std::string("C:\\Users\\lh\\Desktop\\") + std::to_string(a++) + "1.txt", std::ios::out | std::ios::app);
		LogFile << "Data init" << std::endl;
	}

	void write(std::string str)
	{
		LogFile << str << std::endl;
	}

	int snapshot_count = 0;
	int zbcj_length = 0;
	int zbwt_length = 0;
};

// 获取联动数据
Data &get_data()
{
	static Data _d;
	return _d;
}

void a()
{
	while (1)
	{
		Data &_d = get_data();

		MessageBox(NULL, std::to_string(_d.snapshot_count).data(), "提示", MB_OK);
		_d.write(std::to_string(_d.snapshot_count) + "\n");
		_d.snapshot_count++;
	}
}

void b()
{
	while (1)
	{
		Data &_d = get_data();

		MessageBox(NULL, std::to_string(_d.snapshot_count).data(), "提示", MB_OK);
		_d.write(std::to_string(_d.snapshot_count) + "\n");
		_d.snapshot_count--;
		_d.snapshot_count--;
	}
}

BOOL WINAPI DllMain(_In_ void *_DllHandle, _In_ unsigned long _Reason, _In_opt_ void *_Reserved)
{
	switch (_Reason)
	{
	case DLL_PROCESS_ATTACH:
	{
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)a, NULL, 0, NULL);
		HANDLE hThread2 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)b, NULL, 0, NULL);
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

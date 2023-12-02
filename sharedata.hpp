/*
共享内存数据
*/
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>

class sharedata
{
public:
    enum type
    {
        CHAR,
        INT,
        DOUBLE,
        CHAR_5,
        CHAR_10,
        CHAR_20,
        CHAR_40,
    };

private:
    size_t size = 0;
    std::string filename;

    HANDLE hMapFile = NULL;
    LPVOID lpBase = NULL;
    HANDLE pMutex = NULL;
    HANDLE pEvent = NULL;

    // 数据类型对应的大小
    const std::map<type, int> type_size{
        {CHAR, sizeof(char)},
        {INT, sizeof(int)},
        {DOUBLE, sizeof(double)},
        {CHAR_5, sizeof(char) * 5},
        {CHAR_10, sizeof(char) * 10},
        {CHAR_20, sizeof(char) * 20},
        {CHAR_40, sizeof(char) * 40},
    };

    // 各数据对应的偏移量
    std::map<int, int> type_offset;

    // 各数据对应的长度
    std::map<int, int> type_length;

    // 禁用拷贝构造函数
    sharedata(const sharedata &) = delete;

    // 禁用赋值运算符
    sharedata &operator=(const sharedata &) = delete;

public:
    sharedata(std::vector<type> data_types, const std::string &filename) : filename(filename)
    {
        int count = 0;
        for (auto &i : data_types)
        {
            type_offset[count] = size;
            type_length[count] = type_size.at(i);
            size += type_size.at(i);
            count++;
        }
    }

    // 等待通知
    void wait_for_notify() const
    {
        WaitForSingleObject(pEvent, INFINITE);
        ResetEvent(pEvent);
    }

    const bool init()
    {
        int if_new = 0;
        int _size = size / 4 + (size % 4 == 0 ? 0 : 1); // 参数是DWORD，所以要除以4

        // 尝试打开现有的文件映射
        hMapFile = OpenFileMapping(
            FILE_MAP_ALL_ACCESS,        // read/write access
            FALSE,                      // do not inherit the name
            (filename + "_FM").data()); // name of mapping object

        if (hMapFile == NULL)
        {
            // 尝试创建文件映射
            hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, _size, (filename + "_FM").data());
            if (hMapFile == NULL)
            {
                MessageBox(NULL, (std::string("获取文件映射失败, 错误码 ") + std::to_string(GetLastError())).data(), "提示", MB_OK);
                return false;
            }

            pMutex = CreateMutex(NULL, FALSE, (filename + "_MTX").data());
            if (pMutex == NULL)
            {
                MessageBox(NULL, (std::string("创建互斥量失败, 错误码 ") + std::to_string(GetLastError())).data(), "提示", MB_OK);
                return false;
            }

            // 新创建的文件映射，负责初始化数据
            if_new = 1;
        }
        else
        {
            pMutex = OpenMutex(NULL, FALSE, (filename + "_MTX").data());
            if (pMutex == NULL)
            {
                MessageBox(NULL, (std::string("打开互斥量失败, 错误码 ") + std::to_string(GetLastError())).data(), "提示", MB_OK);
                return false;
            }
        }

        // 映射到进程空间
        lpBase = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, _size);
        if (lpBase == NULL)
        {
            MessageBox(NULL, (std::string("映射到进程空间失败, 错误码 ") + std::to_string(GetLastError())).data(), "提示", MB_OK);

            // 关闭文件映射
            CloseHandle(hMapFile);
            hMapFile = NULL;

            return false;
        }

        pEvent = CreateEvent(NULL, TRUE, FALSE, (filename + "_E").data());
        if (pEvent == NULL)
        {
            MessageBox(NULL, (std::string("打开事件变量失败, 错误码 ") + std::to_string(GetLastError())).data(), "提示", MB_OK);
            return false;
        }

        // 初始化数据
        if (if_new)
        {
            WaitForSingleObject(pMutex, INFINITE);
            memset(lpBase, 0, size);
            ReleaseMutex(pMutex);
        }

        return true;
    }

    // 读取数据
    const LPVOID read(int index) const
    {
        if (lpBase == NULL)
        {
            return NULL;
        }

        return (LPVOID)((DWORD)lpBase + type_offset.at(index));
    }

    // 发送提醒
    void notify() const
    {
        ResetEvent(pEvent);
        SetEvent(pEvent);
    }

    // 设置数据
    void set(void *data_p, int index, type data_type)
    {
        // 数据地址
        DWORD dst = (DWORD)lpBase + type_offset[index];

        // 获取互斥量
        WaitForSingleObject(pMutex, INFINITE);
        switch (data_type)
        {
        case CHAR:
            memcpy((void *)dst, data_p, type_size.at(data_type));
            break;

        case INT:
            *(int *)dst = *(int *)data_p;
            break;

        case DOUBLE:
            *(double *)dst = *(double *)data_p;
            break;

        case CHAR_5:
        case CHAR_10:
        case CHAR_20:
        case CHAR_40:
            // 置空
            memset((void *)dst, 0, type_length.at(index));
            memcpy((void *)dst, data_p, strlen((char *)data_p));
            break;

        default:
            break;
        }

        ReleaseMutex(pMutex);
    }

    // 输出打印 hex
    void hex() const
    {
        WaitForSingleObject(pMutex, INFINITE);
        for (int i = 0; i < size; i++)
        {
            std::cout << std::showbase << std::hex << (int)((char *)lpBase)[i] << " ";
        }
        ReleaseMutex(pMutex);
        std::cout << std::endl;
    }

    ~sharedata()
    {
        // 卸载映射
        if (lpBase)
        {
            UnmapViewOfFile(lpBase);
        }

        // 关闭文件映射
        if (hMapFile)
        {
            CloseHandle(hMapFile);
            hMapFile = NULL;
        }
    }
};
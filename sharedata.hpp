/*
共享内存数据
*/
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <mutex>

class sharedata
{
public:
    enum type
    {
        CHAR,
        _DWORD,
        INT,
        SIZE_T,
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

    // 缓存数据
    void *cache_data = nullptr;
    mutable std::mutex cache_mutex;

    // 数据类型对应的大小
    const std::map<type, int> type_size{
        {CHAR, sizeof(char)},
        {_DWORD, sizeof(DWORD)},
        {INT, sizeof(int)},
        {SIZE_T, sizeof(size_t)},
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
            pMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, (filename + "_MTX").data());
            if (pMutex == NULL)
            {
                MessageBox(NULL, (std::string("打开互斥量失败, 错误码 ") + std::to_string(GetLastError())).data(), "提示", MB_OK);
                return false;
            }
        }

        // 申请本地缓存空间
        cache_data = malloc(size);
        if (cache_data == NULL)
        {
            MessageBox(NULL, (std::string("申请本地缓存空间失败, 错误码 ") + std::to_string(GetLastError())).data(), "提示", MB_OK);
            return false;
        }
        memset(cache_data, 0, size);

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

    std::mutex &get_mutex()
    {
        return cache_mutex;
    }

    // 读取数据
    const void *const read(int index) const
    {
        return get(index);
    }

    // 获取数据
    const void *get(int index) const
    {
        if (lpBase == NULL)
        {
            return NULL;
        }

        return (void *)((DWORD)cache_data + type_offset.at(index));
    }

    // 发送提醒
    void notify() const
    {
        ResetEvent(pEvent);
        SetEvent(pEvent);
    }

    // 设置数据
    void set(const void *const data_p, int index, type data_type)
    {
        // 数据地址
        DWORD dst = (DWORD)cache_data + type_offset[index];

        std::lock_guard<std::mutex> lock(cache_mutex);
        switch (data_type)
        {
        case CHAR:
            memcpy((void *)dst, data_p, type_size.at(data_type));
            break;

        case _DWORD:
            *(DWORD *)dst = *(DWORD *)data_p;
            break;

        case SIZE_T:
            *(size_t *)dst = *(size_t *)data_p;
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
    }

    // 将缓存数据应用到共享内存
    void cache_apply()
    {
        WaitForSingleObject(pMutex, INFINITE);
        memcpy(lpBase, cache_data, size);

        ResetEvent(pEvent);
        SetEvent(pEvent);

        ReleaseMutex(pMutex);
    }

    // 将共享内存数据更新到缓存
    void cache_update()
    {
        WaitForSingleObject(pEvent, INFINITE);
        WaitForSingleObject(pMutex, INFINITE);
        memcpy(cache_data, lpBase, size);
        ResetEvent(pEvent);

        ReleaseMutex(pMutex);
    }

    // 输出打印 hex
    void hex() const
    {
        {
            std::lock_guard<std::mutex> lock(cache_mutex);
            for (int i = 0; i < size; i++)
            {
                std::cout << std::showbase << std::hex << (int)((char *)lpBase)[i] << " ";
            }
        }
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

        // 释放缓存空间
        if (cache_data)
        {
            free(cache_data);
        }
    }
};
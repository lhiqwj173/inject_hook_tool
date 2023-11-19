#pragma once
#include <Windows.h>
#include <map>
#include <functional>

class hooker
{
private:
    // hook点的函数指针
    std::map<size_t, std::function<void(PCONTEXT)>> _hooks;

    // hook点的原代码
    std::map<size_t, UCHAR> _old_codes;

    void _set_break_point(size_t addr)
    {
        // 用 0xCC 替换原代码
        DWORD dwProtect = 0;
        VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &dwProtect);
        _old_codes[addr] = *(UCHAR *)addr;
        *(UCHAR *)addr = 0xCC;
        VirtualProtect((LPVOID)addr, 1, dwProtect, &dwProtect);
    }

    void _delete_break_point(size_t addr)
    {
        // 恢复原代码
        DWORD dwProtect = 0;
        VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &dwProtect);
        *(UCHAR *)addr = _old_codes[addr];
        VirtualProtect((LPVOID)addr, 1, dwProtect, &dwProtect);

        // 删除记录
        _old_codes.erase(addr);
        _hooks.erase(addr);
    }

private:
    hooker()
    {
        // 设置异常回调
        AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)handler);
    }
    hooker(const hooker &) = delete;            // 禁止拷贝构造函数
    hooker &operator=(const hooker &) = delete; // 禁止赋值运算符

public:
    static hooker *get_instance()
    {
        static hooker _instance;
        return &_instance;
    }

    // 处理异常的函数
    static LONG handler(_EXCEPTION_POINTERS *ExceptionInfo)
    {
        // 判断是否是断点异常
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            hooker *instance = get_instance();

            // 判断是否是hook的地址
            size_t addr = (size_t)ExceptionInfo->ExceptionRecord->ExceptionAddress;
            if (instance->_hooks.find(addr) != instance->_hooks.end())
            {
                // 调用hook函数
                (instance->_hooks[addr])(ExceptionInfo->ContextRecord);

                // 继续执行
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // 非 hook 断点异常
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void set_hook(size_t addr, const std::function<void(PCONTEXT)> &func)
    {
        _hooks[addr] = func;

        // 设置异常
        _set_break_point(addr);
    }

    void delete_hook(size_t addr)
    {
        _delete_break_point(addr);
    }

    ~hooker()
    {
        // 删除断点
        for (auto it = _old_codes.begin(); it != _old_codes.end();)
        {
            auto addr = it->first;
            it++;
            _delete_break_point(addr);
        }
    }
};
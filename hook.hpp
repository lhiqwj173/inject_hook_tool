#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <functional>
#include <string>
#include <map>

class hook_data
{
protected:
    // hook点的函数指针
    std::map<size_t, std::function<void(PCONTEXT)>> _hooks;

private:
    hook_data() {}
    hook_data(const hook_data &) = delete;            // 禁止拷贝构造函数
    hook_data &operator=(const hook_data &) = delete; // 禁止赋值运算符
public:
    static hook_data *get_instance()
    {
        static hook_data instance;
        return &instance;
    }

    void set(size_t addr, const std::function<void(PCONTEXT)> &func)
    {
        _hooks[addr] = func;
    }

    void del(size_t addr)
    {
        _hooks.erase(addr);
    }

    bool check(size_t addr)
    {
        return _hooks.find(addr) != _hooks.end();
    }

    void run(size_t addr, PCONTEXT p)
    {
        if (_hooks.find(addr) == _hooks.end())
        {
            std::string msg = std::to_string(addr) + "没有找到hook点";
            // MessageBox(NULL, msg.data(), "提示", MB_OK);
            return;
        }
        (_hooks[addr])(p);
    }

    size_t next()
    {
        if (_hooks.size() > 0)
        {
            return _hooks.begin()->first;
        }

        return 0;
    }
};

class hooker_base
{
protected:
    hook_data *_hook_data = hook_data::get_instance();

    virtual void _set_break_point(size_t addr){};

    virtual void _delete_break_point(size_t addr){};

    hooker_base()
    {
        // 设置异常回调
        ExceptionHandler_ptr = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)handler);
    }

private:
    PVOID ExceptionHandler_ptr = nullptr;
    hooker_base(const hooker_base &) = delete;            // 禁止拷贝构造函数
    hooker_base &operator=(const hooker_base &) = delete; // 禁止赋值运算符

public:
    static hooker_base *get_instance()
    {
        static hooker_base instance;
        return &instance;
    }

    // 处理异常的函数
    static LONG handler(_EXCEPTION_POINTERS *ExceptionInfo)
    {
        // 判断是否是断点异常
        auto code = ExceptionInfo->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP || code == 0xC0000005)
        {
            hook_data *_hook_data = hook_data::get_instance();

            // 判断是否是hook的地址
            size_t addr = (size_t)ExceptionInfo->ExceptionRecord->ExceptionAddress;
            // MessageBox(NULL, (std::string("断点地址: ") + std::to_string(addr)).data(), "提示", MB_OK);

            if (_hook_data->check(addr))
            {
                // 调用hook函数
                _hook_data->run(addr, ExceptionInfo->ContextRecord);

                // 继续执行
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // 非 hook 断点异常
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void set_hook(size_t addr, const std::function<void(PCONTEXT)> &func)
    {
        _hook_data->set(addr, func);

        // 设置异常
        _set_break_point(addr);
    }

    void delete_hook(size_t addr)
    {
        _delete_break_point(addr);
        _hook_data->del(addr);
    }

    virtual ~hooker_base()
    {
        // MessageBox(NULL, "hooker_base::~hooker_base", "提示", MB_OK);

        // 删除断点
        size_t addr;
        while ((addr = _hook_data->next()) != 0)
        {
            // MessageBox(NULL, std::to_string((int)addr).data(), "删除断点", MB_OK);
            delete_hook(addr);
        }

        // MessageBox(NULL, "取消异常处理回调", "提示", MB_OK);
        // 取消异常处理回调
        // RemoveVectoredExceptionHandler(ExceptionHandler_ptr);
    }
};

class hooker_soft_break : public hooker_base
{
protected:
    // hook点的原代码
    std::map<size_t, UCHAR> _old_codes;

    virtual void _set_break_point(size_t addr)
    {
        // 用 0xCC 替换原代码
        DWORD dwProtect = 0;
        VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &dwProtect);
        _old_codes[addr] = *(UCHAR *)addr;
        *(UCHAR *)addr = 0xCC;
        VirtualProtect((LPVOID)addr, 1, dwProtect, &dwProtect);
    }

    virtual void _delete_break_point(size_t addr)
    {
        // 恢复原代码
        DWORD dwProtect = 0;
        VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &dwProtect);
        *(UCHAR *)addr = _old_codes[addr];
        VirtualProtect((LPVOID)addr, 1, dwProtect, &dwProtect);

        // 删除记录
        _old_codes.erase(addr);
    }

    hooker_soft_break() : hooker_base() {}

public:
    static hooker_base *get_instance()
    {
        static hooker_soft_break instance;
        return &instance;
    }
};

class hooker_hard_break : public hooker_base
{
protected:
    struct param
    {
        size_t addr;
        DWORD threadId;
        int clear;
        int *dr_status;
    };

    int dr_status[4] = {0};

    static void _set_dr(int n, int v, CONTEXT &ctx)
    {
        // MessageBox(NULL, (std::string("设置: ") + std::to_string(n) + std::to_string(v)).data(), "DRS", MB_OK);

        switch (n)
        {
        case 0:
            ctx.Dr0 = v;
            // MessageBox(NULL, (std::to_string(ctx.Dr0)).data(), "DRS", MB_OK);
            break;
        case 1:
            ctx.Dr1 = v;
            // MessageBox(NULL, (std::to_string(ctx.Dr1)).data(), "DRS", MB_OK);
            break;
        case 2:
            ctx.Dr2 = v;
            // MessageBox(NULL, (std::to_string(ctx.Dr2)).data(), "DRS", MB_OK);
            break;
        case 3:
            ctx.Dr3 = v;
            // MessageBox(NULL, (std::to_string(ctx.Dr3)).data(), "DRS", MB_OK);
            break;
        default:
            break;
        }
    }

    // 设置硬件断点
    static void SetHwBreakPoint(HANDLE hThread, size_t addr, int *_dr_status, int clear, int drn)
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &ctx);

        // ctx.Dr1 = (size_t)GetModuleHandle(NULL) + 0x5BEE;
        // ctx.Dr7 |= 0x1 << 2; // 全局开关

        // ctx.Dr0 = (size_t)GetModuleHandle(NULL) + 0x5BEE;
        // ctx.Dr7 |= 0x1 << 1; // 全局开关
        // ctx.Dr7 |= 0x1; // 局部开关

        // MessageBox(NULL, (std::string("dr n: ") + std::to_string(ctx.Dr0) + " dr7: " + std::to_string(ctx.Dr7)).data(), "DRS", MB_OK);
        // SetThreadContext(hThread, &ctx);
        // return;

        if (clear)
        {
            _set_dr(drn, 0, ctx);
        }
        else
        {
            _set_dr(drn, addr, ctx);
        }

        // 全开
        ctx.Dr7 = 0x55;

        SetThreadContext(hThread, &ctx);
    }

    static void loop(param *p, int drn)
    {
        // 遍历线程 通过openthread获取到线程环境后设置硬件断点
        HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hTool32 != INVALID_HANDLE_VALUE)
        {
            // 线程环境结构体
            THREADENTRY32 thread_entry32;

            thread_entry32.dwSize = sizeof(THREADENTRY32);

            HANDLE hHookThread = NULL;

            // 遍历线程
            if (Thread32First(hTool32, &thread_entry32))
            {
                do
                {
                    // 如果线程父进程ID为当前进程ID
                    if (thread_entry32.th32OwnerProcessID == GetCurrentProcessId())
                    {
                        //MessageBox(NULL, (std::string("线程ID: ") + std::to_string(thread_entry32.th32ThreadID) + " 进程ID: " + std::to_string(thread_entry32.th32OwnerProcessID)).data(), "提示", MB_OK);

                        // 打开主线程
                        HANDLE hadl = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_entry32.th32ThreadID);
                        SuspendThread((HANDLE)hadl);
                        SetHwBreakPoint(hadl, p->addr, p->dr_status, p->clear, drn);
                        ResumeThread((HANDLE)hadl);
                        CloseHandle(hadl);
                    }

                } while (Thread32Next(hTool32, &thread_entry32));
            }
            CloseHandle(hTool32);
        }
    }

    static DWORD WINAPI threadPro(_In_ LPVOID lpParam)
    {
        // 获取参数
        param *p = (param *)lpParam;

        // 确定 drn
        int drn = -1;
        if (p->clear)
        {
            // 取消硬件断点
            for (int i = 0; i < 4; i++)
            {
                if (*(p->dr_status + i) == p->addr)
                {
                    *(p->dr_status + i) = 0;

                    drn = i;
                    break;
                }

                if (i == 3)
                {
                    //MessageBox(NULL, "没有找到硬件断点", "DRS", MB_OK);
                }
            }
        }
        else
        {
            // 设置硬件断点
            for (int i = 0; i < 4; i++)
            {
                //MessageBox(NULL, (std::to_string(*(p->dr_status + i))).data(), "DRS", MB_OK);
                if (*(p->dr_status + i) == 0)
                {
                    // dr i
                    drn = i;
                    *(p->dr_status + i) = p->addr;
                    break;
                }

                if (i == 3)
                {
                    //MessageBox(NULL, "没有找到空闲的硬件断点", "DRS", MB_OK);
                }
            }
        }

        // 遍历线程设置断点
        loop(p, drn);

        // 只设置一个线程 全局断点
        // HANDLE hadl = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, p->threadId);
        // SuspendThread((HANDLE)hadl);
        // SetHwBreakPoint(hadl, p->addr, p->dr_status, p->clear);
        // ResumeThread((HANDLE)hadl);
        // CloseHandle(hadl);

        // 释放参数
        delete p;

        return 0;
    }

    void __set_break_point(size_t addr, int clear)
    {
        std::string msg = std::to_string(addr) + ", " + std::to_string(clear) + ", " + std::to_string((int)dr_status);
        //MessageBox(NULL, msg.data(), "提示", MB_OK);

        // 参数
        param *p = new param{addr, GetCurrentThreadId(), clear, dr_status};

        // 在子线程中设置硬件断点
        HANDLE hThread = CreateThread(NULL, NULL, threadPro, (LPVOID)p, NULL, NULL);

        // 关闭线程句柄
        //MessageBox(NULL, "关闭线程句柄", "提示", MB_OK);
        CloseHandle(hThread);
    }

    virtual void _set_break_point(size_t addr) override
    {
        //MessageBox(NULL, "_set_break_point", "提示", MB_OK);
        __set_break_point(addr, 0);
    }

    virtual void _delete_break_point(size_t addr) override
    {
        //MessageBox(NULL, "_delete_break_point", "提示", MB_OK);
        __set_break_point(addr, 1);
    }

    hooker_hard_break() : hooker_base() {}

public:
    static hooker_base *get_instance()
    {
        static hooker_hard_break instance;
        return &instance;
    }

    virtual ~hooker_hard_break() override
    {
        //MessageBox(NULL, "hooker_hard_break::~hooker_hard_break", "提示", MB_OK);
    }
};
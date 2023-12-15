#pragma once
#include <Windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <DbgHelp.h>
#include <functional>
#include <string>
#include <map>
#include <fstream>

// 链接lib
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "DbgHelp.lib")

#include "singlebase.hpp"

template <class... Args>
void info(Args &&...rest)
{
    (std::cout << ... << rest) << std::endl;
}

// 打印堆栈数据
void PrintStackTrace(CONTEXT *context, std::string &data)
{
    STACKFRAME64 stackFrame = {0};
    DWORD machineType;
    DWORD64 basePointer;
    DWORD64 stackPtr;

    // 初始化 STACKFRAME64 结构体
#ifdef _M_IX86
    machineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = context->Eip;
    stackFrame.AddrFrame.Offset = context->Ebp;
    stackFrame.AddrStack.Offset = context->Esp;
    basePointer = context->Ebp;
    stackPtr = context->Esp;
#elif _M_X64
    machineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = context->Rip;
    stackFrame.AddrFrame.Offset = context->Rsp;
    stackFrame.AddrStack.Offset = context->Rsp;
    basePointer = context->Rsp;
    stackPtr = context->Rsp;
#else
#error "Unsupported architecture"
#endif

    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();

    int maxDepth = 5;

    // 遍历堆栈帧
    while ((StackWalk64(machineType, hProcess, hThread, &stackFrame, context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) && (maxDepth-- > 0))
    {
        // 堆栈帧信息
        data += "Frame Addr: " + std::to_string(stackFrame.AddrPC.Offset) + "\t";

        // 获取符号信息
        DWORD64 displacement = 0;
        BYTE symbolBuffer[sizeof(IMAGEHLP_SYMBOL64) + MAX_SYM_NAME];
        PIMAGEHLP_SYMBOL64 symbol = reinterpret_cast<PIMAGEHLP_SYMBOL64>(symbolBuffer);
        symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
        symbol->MaxNameLength = MAX_SYM_NAME;

        if (SymGetSymFromAddr64(hProcess, stackFrame.AddrPC.Offset, &displacement, symbol))
        {
            data += "Func: " + std::string(symbol->Name) + "\t";

            // 遍历函数参数
            DWORD64 framePtr = basePointer;
            while (framePtr < stackPtr)
            {
                data += "\n";
                DWORD64 paramValue;
                if (ReadProcessMemory(hProcess, (LPVOID)framePtr, &paramValue, sizeof(DWORD64), NULL))
                {
                    data += "\tPara: " + std::string(symbol->Name) + " Value: " + std::to_string(paramValue) + "\n";
                }
                framePtr += sizeof(DWORD64);
                symbol++;
            }
        }
        data += "\n";

        // 读取函数源码行信息
        DWORD displacementLine = 0;
        IMAGEHLP_LINE64 line = {sizeof(IMAGEHLP_LINE64)};
        if (SymGetLineFromAddr64(hProcess, stackFrame.AddrPC.Offset, &displacementLine, &line))
        {
            data += std::string("\tFile: ") + line.FileName + ", line " + std::to_string(line.LineNumber) + "\n\n";
        }
    }
}

const std::string parse_error_code(const DWORD &error)
{
    // 异常代码: ExceptionInfo->ExceptionRecord->ExceptionCode
    /*
    EXCEPTION_ACCESS_VIOLATION
    线程尝试从虚拟地址读取或写入其没有相应访问权限的虚拟地址。
    EXCEPTION_ARRAY_BOUNDS_EXCEEDED
    线程尝试访问超出边界且基础硬件支持边界检查的数组元素。
    EXCEPTION_BREAKPOINT
    遇到断点。
    EXCEPTION_DATATYPE_MISALIGNMENT
    线程尝试读取或写入在不提供对齐的硬件上未对齐的数据。 例如，16 位值必须在 2 字节边界上对齐;4 字节边界上的 32 位值等。
    EXCEPTION_FLT_DENORMAL_OPERAND
    浮点运算中的一个操作数是反常运算。 非规范值太小，无法表示为标准浮点值。
    EXCEPTION_FLT_DIVIDE_BY_ZERO
    线程尝试将浮点值除以 0 的浮点除数。
    EXCEPTION_FLT_INEXACT_RESULT
    浮点运算的结果不能完全表示为小数点。
    EXCEPTION_FLT_INVALID_OPERATION
    此异常表示此列表中未包含的任何浮点异常。
    EXCEPTION_FLT_OVERFLOW
    浮点运算的指数大于相应类型允许的量级。
    EXCEPTION_FLT_STACK_CHECK
    堆栈因浮点运算而溢出或下溢。
    EXCEPTION_FLT_UNDERFLOW
    浮点运算的指数小于相应类型允许的量级。
    EXCEPTION_ILLEGAL_INSTRUCTION
    线程尝试执行无效指令。
    EXCEPTION_IN_PAGE_ERROR
    线程尝试访问不存在的页面，但系统无法加载该页。 例如，如果在通过网络运行程序时网络连接断开，则可能会发生此异常。
    EXCEPTION_INT_DIVIDE_BY_ZERO
    线程尝试将整数值除以零的整数除数。
    EXCEPTION_INT_OVERFLOW
    整数运算的结果导致执行结果中最重要的位。
    EXCEPTION_INVALID_DISPOSITION
    异常处理程序向异常调度程序返回了无效处置。 使用高级语言（如 C）的程序员不应遇到此异常。
    EXCEPTION_NONCONTINUABLE_EXCEPTION
    线程尝试在发生不可连续的异常后继续执行。
    EXCEPTION_PRIV_INSTRUCTION
    线程尝试执行在当前计算机模式下不允许其操作的指令。
    EXCEPTION_SINGLE_STEP
    跟踪陷阱或其他单指令机制指示已执行一个指令。
    EXCEPTION_STACK_OVERFLOW
    线程占用了其堆栈。
    */
    switch (error)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        return "EXCEPTION_ACCESS_VIOLATION | 线程尝试从虚拟地址读取或写入其没有相应访问权限的虚拟地址。";
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        return "EXCEPTION_DATATYPE_MISALIGNMENT | 	线程尝试访问超出边界且基础硬件支持边界检查的数组元素。";
    case EXCEPTION_BREAKPOINT:
        return "EXCEPTION_BREAKPOINT | 遇到断点。";
    case EXCEPTION_SINGLE_STEP:
        return "EXCEPTION_SINGLE_STEP | 线程尝试读取或写入在不提供对齐的硬件上未对齐的数据。 例如，16 位值必须在 2 字节边界上对齐;4 字节边界上的 32 位值等。";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED | 浮点运算中的一个操作数是反常运算。 非规范值太小，无法表示为标准浮点值。";
    case EXCEPTION_FLT_DENORMAL_OPERAND:
        return "EXCEPTION_FLT_DENORMAL_OPERAND | 线程尝试将浮点值除以 0 的浮点除数。";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        return "EXCEPTION_FLT_DIVIDE_BY_ZERO | 浮点运算的结果不能完全表示为小数点。";
    case EXCEPTION_FLT_INEXACT_RESULT:
        return "EXCEPTION_FLT_INEXACT_RESULT | 此异常表示此列表中未包含的任何浮点异常。";
    case EXCEPTION_FLT_INVALID_OPERATION:
        return "EXCEPTION_FLT_INVALID_OPERATION | 浮点运算的指数大于相应类型允许的量级。";
    case EXCEPTION_FLT_OVERFLOW:
        return "EXCEPTION_FLT_OVERFLOW | 堆栈因浮点运算而溢出或下溢。";
    case EXCEPTION_FLT_STACK_CHECK:
        return "EXCEPTION_FLT_STACK_CHECK | 浮点运算的指数小于相应类型允许的量级。";
    case EXCEPTION_FLT_UNDERFLOW:
        return "EXCEPTION_FLT_UNDERFLOW | 线程尝试执行无效指令。";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        return "EXCEPTION_INT_DIVIDE_BY_ZERO | 线程尝试将整数值除以零的整数除数。";
    case EXCEPTION_INT_OVERFLOW:
        return "EXCEPTION_INT_OVERFLOW | 整数运算的结果导致执行结果中最重要的位。";
    case EXCEPTION_PRIV_INSTRUCTION:
        return "EXCEPTION_PRIV_INSTRUCTION | 异常处理程序向异常调度程序返回了无效处置。 使用高级语言（如 C）的程序员不应遇到此异常。";
    case EXCEPTION_IN_PAGE_ERROR:
        return "EXCEPTION_IN_PAGE_ERROR | 线程尝试在发生不可连续的异常后继续执行。";
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        return "EXCEPTION_ILLEGAL_INSTRUCTION | 线程尝试执行在当前计算机模式下不允许其操作的指令。";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        return "EXCEPTION_NONCONTINUABLE_EXCEPTION | 跟踪陷阱或其他单指令机制指示已执行一个指令。";
    case EXCEPTION_STACK_OVERFLOW:
        return "EXCEPTION_STACK_OVERFLOW | 线程占用了其堆栈。";
    default:
        return std::to_string(error) + "未知异常";
    }
}

struct hook_addr_func
{
    DWORD addr;
    DWORD func;
};

// 储存hook点的相关数据
// 无依赖
class hook_data : private singlebase
{
public:
    enum hook_type
    {
        soft_break,
        hard_break,
    };

protected:
    // hook点的函数指针
    // <地址, 回调>
    std::map<DWORD, DWORD> _hooks;
    // <hook类型, 地址列表>
    std::map<hook_type, std::vector<DWORD>> _hook_type_addrs;
    hook_data() {}

public:
    static hook_data *get_instance()
    {
        static hook_data instance;
        return &instance;
    }

    void set(DWORD *addr, DWORD *func, size_t n, hook_type type)
    {
        // info("set _hooks:", std::to_string((int)&_hooks), "this:", std::to_string((int)this));
        for (size_t i = 0; i < n; i++)
        {
            _hooks[addr[i]] = func[i];
            _hook_type_addrs[type].push_back(addr[i]);
            // info("set", std::to_string(addr[i]) + " -> " + std::to_string(func[i]));
        }
    }

    void del(DWORD *addr, size_t n, hook_type type)
    {
        for (size_t i = 0; i < n; i++)
        {
            _hooks.erase(addr[i]);
            _hook_type_addrs[type].erase(std::find(_hook_type_addrs[type].begin(), _hook_type_addrs[type].end(), addr[i]));
        }
    }

    bool check(const DWORD &addr) const
    {
        // info("check _hooks:", std::to_string((int)&_hooks), "this:", std::to_string((int)this));
        return _hooks.find(addr) != _hooks.end();
    }

    // 调用hook函数
    void run(const DWORD &addr, PCONTEXT p)
    {
        if (_hooks.find(addr) == _hooks.end())
        {
            std::string msg = std::to_string(addr) + "没有找到hook点";
            info(msg);
            return;
        }

        DWORD func = _hooks[addr];
        void (*pfunc)(PCONTEXT) = (void (*)(PCONTEXT))(func);
        pfunc(p);

        // auto adapter = (std::function<void(PCONTEXT)> *)(func);
        // (*adapter)(p);
    }

    DWORD *hook_addrs(size_t &n, hook_type type) const
    {
        auto &hook_addrs = _hook_type_addrs.at(type);
        n = hook_addrs.size();
        if (n > 0)
        {
            DWORD *addrs = new DWORD[n];

            int i = 0;
            for (const auto &addr : hook_addrs)
            {
                addrs[i] = addr;
                i++;
            }

            return addrs;
        }

        return 0;
    }
};

// 管理异常处理函数的注册与注销
class hook_keeper : private singlebase
{
private:
    PVOID ExceptionHandler_ptr = nullptr;

protected:
    hook_keeper()
    {
        // 设置异常回调
        ExceptionHandler_ptr = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)handler);
    }

public:
    // 获取单例
    static hook_keeper &get_instance()
    {
        static hook_keeper instance;
        return instance;
    }

    // 处理异常的函数
    static LONG handler(_EXCEPTION_POINTERS *ExceptionInfo)
    {
        hook_data *_hook_data = hook_data::get_instance();

        // 判断是否是hook的地址
        DWORD addr = (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress;

        // 判断是否是断点异常
        auto code = ExceptionInfo->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)
        {
            if (_hook_data->check(addr))
            {
                // MessageBox(NULL, (std::string("断点地址: ") + std::to_string(addr)).data(), "提示", MB_OK);
                // 调用hook函数
                _hook_data->run(addr, ExceptionInfo->ContextRecord);

                // 继续执行
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // 获取线程id
        // MessageBox(NULL, (std::string("异常线程: ") + std::to_string(GetCurrentThreadId()) + " " + std::to_string(addr)).data(), "提示", MB_OK);

        // 打印异常信息
        DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
        std::string title = parse_error_code(exceptionCode);

        // 打印堆栈数据
        std::string msg = "";
        PrintStackTrace(ExceptionInfo->ContextRecord, msg);

        info("\n--------------------------------------------------------------------------------------------\n", title, "\n--------------------------------------------------------------------------------------------\n", msg);

        // 退出程序
        TerminateProcess(GetCurrentProcess(), 1);

        // 非 hook 断点异常
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ~hook_keeper()
    {
        // 取消异常处理回调
        if (ExceptionHandler_ptr)
        {
            RemoveVectoredExceptionHandler(ExceptionHandler_ptr);
        }
    }
};

// 依赖: hook_data, hook_keeper, info
class hooker_base : private singlebase
{
protected:
    hook_data *_hook_data = hook_data::get_instance();

    // 异常处理函数管理者
    hook_keeper &_hook_keeper = hook_keeper::get_instance();

    virtual void _set_break_point(DWORD *addr, size_t n, void (*callback)() = nullptr){};

    virtual void _delete_break_point(DWORD *addr, size_t n){};

    virtual constexpr hook_data::hook_type hook_type() const = 0;

    hooker_base() = default;

public:
    void set_hook(DWORD *addr, DWORD *func, size_t n = 1, void (*callback)() = nullptr)
    {
        // MessageBox(NULL, "set_hook", "提示", MB_OK);
        _hook_data->set(addr, func, n, hook_type());

        // 设置异常
        _set_break_point(addr, n, callback);
        info("_set_break_point(addr, n, callback);");
    }

    void clear_hook()
    {
        // 获取所有的hook点
        size_t n = 0;
        DWORD *addrs = _hook_data->hook_addrs(n, hook_type());

        // 删除断点
        delete_hook(addrs, n);

        // 释放内存
        delete[] addrs;
    }

    void delete_hook(DWORD *addr, size_t n = 1)
    {
        // MessageBox(NULL, "_delete_break_point", "提示", MB_OK);
        _delete_break_point(addr, n);
        // MessageBox(NULL, "del", "提示", MB_OK);
        _hook_data->del(addr, n, hook_type());
    }

    virtual ~hooker_base()
    {
        // MessageBox(NULL, "hooker_base::~hooker_base", "提示", MB_OK);
        info("~hooker_base()");
    }
};

class hooker_soft_break : public hooker_base
{
protected:
    // hook点的原代码
    std::map<DWORD, UCHAR> _old_codes;

    virtual constexpr hook_data::hook_type hook_type() const override
    {
        return hook_data::soft_break;
    }

    virtual void _set_break_point(DWORD *addr, size_t n, void (*callback)()) override
    {
        // 用 0xCC 替换原代码
        DWORD dwProtect = 0;

        info("_set_break_point loop");
        bool res = false;
        for (size_t i = 0; i < n; i++)
        {
            res = VirtualProtect((LPVOID)addr[i], 1, PAGE_EXECUTE_READWRITE, &dwProtect);
            info("done 0", std::to_string(res));
            _old_codes[addr[i]] = *(UCHAR *)addr[i];
            info("done 1");
            *(UCHAR *)addr[i] = 0xCC;
            info("done 2");
            VirtualProtect((LPVOID)addr[i], 1, dwProtect, &dwProtect);
            info("done 3");
        }
    }

    virtual void _delete_break_point(DWORD *addr, size_t n) override
    {
        // 恢复原代码
        DWORD dwProtect = 0;

        for (size_t i = 0; i < n; i++)
        {
            VirtualProtect((LPVOID)addr[i], 1, PAGE_EXECUTE_READWRITE, &dwProtect);
            *(UCHAR *)addr[i] = _old_codes[addr[i]];
            VirtualProtect((LPVOID)addr[i], 1, dwProtect, &dwProtect);

            // 删除记录
            _old_codes.erase(addr[i]);
        }
    }

    hooker_soft_break() : hooker_base() {}

public:
    static hooker_base *get_instance()
    {
        static hooker_soft_break instance;
        return &instance;
    }

    virtual ~hooker_soft_break()
    {
        clear_hook();
    }
};

class hooker_hard_break : public hooker_base
{
protected:
    struct param
    {
        DWORD *addr;
        size_t n;
        DWORD threadId;
        int clear;
        int *dr_status;
        void (*callback)();
    };

    virtual constexpr hook_data::hook_type hook_type() const override
    {
        return hook_data::hard_break;
    }

    int dr_status[4] = {0};

    static void __set_dr(int n, int v, CONTEXT &ctx)
    {
        // MessageBox(NULL, (std::string("设置: ") + std::to_string(n) + "->" + std::to_string(v)).data(), "DRS", MB_OK);

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

    static void _set_dr(int *ns, DWORD *v, size_t n, CONTEXT &ctx)
    {
        for (size_t i = 0; i < n; i++)
        {
            // MessageBox(NULL, "__set_dr(ns[i], v[i], ctx);", "DRS", MB_OK);
            __set_dr(ns[i], v[i], ctx);
        }
    }

    // 设置硬件断点
    static void SetHwBreakPoint(HANDLE hThread, DWORD *addr, int clear, int *drn, size_t n)
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &ctx);

        // ctx.Dr1 = (DWORD)GetModuleHandle(NULL) + 0x5BEE;
        // ctx.Dr7 |= 0x1 << 2; // 全局开关

        // ctx.Dr0 = (DWORD)GetModuleHandle(NULL) + 0x5BEE;
        // ctx.Dr7 |= 0x1 << 1; // 全局开关
        // ctx.Dr7 |= 0x1; // 局部开关

        // MessageBox(NULL, (std::string("dr n: ") + std::to_string(ctx.Dr0) + " dr7: " + std::to_string(ctx.Dr7)).data(), "DRS", MB_OK);
        // SetThreadContext(hThread, &ctx);
        // return;

        if (clear)
        {
            // MessageBox(NULL, "clear", "提示", MB_OK);
            for (size_t i = 0; i < n; i++)
            {
                addr[i] = 0;
            }
            _set_dr(drn, addr, n, ctx);
        }
        else
        {
            _set_dr(drn, addr, n, ctx);
        }

        // 全开
        ctx.Dr7 = 0x55;

        if (!SetThreadContext(hThread, &ctx))
        {
            MessageBox(NULL, "SetThreadContext fail", "提示", MB_OK);
        }
    }

    static void loop(param *p, int *drn)
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
                        // MessageBox(NULL, (std::string("线程ID: ") + std::to_string(thread_entry32.th32ThreadID) + " 进程ID: " + std::to_string(thread_entry32.th32OwnerProcessID)).data(), "提示", MB_OK);

                        // 打开主线程
                        HANDLE hadl = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_entry32.th32ThreadID);
                        SuspendThread((HANDLE)hadl);
                        SetHwBreakPoint(hadl, p->addr, p->clear, drn, p->n);
                        ResumeThread((HANDLE)hadl);
                        CloseHandle(hadl);
                    }

                } while (Thread32Next(hTool32, &thread_entry32));
            }
            CloseHandle(hTool32);
        }
    }

    static int check_dr_idx(int *dr_status, int clear, const DWORD &addr)
    {
        // 确定 drn
        int drn = -1;
        if (clear)
        {
            // 取消硬件断点
            for (int i = 0; i < 4; i++)
            {
                if (*(dr_status + i) == addr)
                {
                    *(dr_status + i) = 0;

                    drn = i;
                    break;
                }

                if (i == 3)
                {
                    // MessageBox(NULL, "没有找到硬件断点", "DRS", MB_OK);
                }
            }
        }
        else
        {
            // 设置硬件断点
            for (int i = 0; i < 4; i++)
            {
                if (*(dr_status + i) == 0)
                {
                    // dr i
                    drn = i;
                    *(dr_status + i) = addr;
                    break;
                }

                if (i == 3)
                {
                    // MessageBox(NULL, "没有找到空闲的硬件断点", "DRS", MB_OK);
                }
            }
        }

        return drn;
    }

    static DWORD WINAPI threadPro(_In_ LPVOID lpParam)
    {
        // 获取参数
        param *p = (param *)lpParam;

        // 确定 drn
        int n = min(4, p->n);
        int *drn = new int[n];
        for (int i = 0; i < n; i++)
        {
            drn[i] = check_dr_idx(p->dr_status, p->clear, p->addr[i]);
            // MessageBox(NULL, (std::to_string(i) + ": " + std::to_string(drn[i])).data(), "提示", MB_OK);
        }

        // 遍历线程设置断点
        // MessageBox(NULL, "loop", "提示", MB_OK);
        loop(p, drn);

        // 释放内存
        // MessageBox(NULL, "释放内存", "提示", MB_OK);
        delete[] drn;
        delete[] p->addr;
        delete p;

        // 执行回调
        // MessageBox(NULL, "执行回调", "提示", MB_OK);
        auto callback = p->callback;
        if (callback)
        {
            callback();
        }

        return 0;
    }

    void __set_break_point(DWORD *addr, int clear, size_t n, void (*callback)())
    {
        // MessageBox(NULL, "__set_break_point", "提示", MB_OK);
        // 固化参数 addr
        DWORD *_addr = new DWORD[n];
        memcpy(_addr, addr, n * sizeof(DWORD));

        // 参数
        param *p = new param{_addr, n, GetCurrentThreadId(), clear, dr_status, callback};
        // MessageBox(NULL, "param *p", "提示", MB_OK);

        // 在子线程中设置硬件断点
        HANDLE hThread = CreateThread(NULL, NULL, threadPro, (LPVOID)p, NULL, NULL);
        // MessageBox(NULL, "CreateThread", "提示", MB_OK);

        // 等待线程结束
        if (clear)
        {
            // MessageBox(NULL, "WaitForSingleObject", "提示", MB_OK);
            WaitForSingleObject(hThread, INFINITE);
        }

        // 关闭线程句柄
        CloseHandle(hThread);
        // MessageBox(NULL, "CloseHandle", "提示", MB_OK);
    }

    virtual void _set_break_point(DWORD *addr, size_t n, void (*callback)()) override
    {
        __set_break_point(addr, 0, n, callback);
    }

    virtual void _delete_break_point(DWORD *addr, size_t n) override
    {
        // MessageBox(NULL, "_delete_break_point", "提示", MB_OK);
        __set_break_point(addr, 1, n, nullptr);
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
        clear_hook();
    }
};
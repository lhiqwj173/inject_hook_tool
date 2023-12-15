#include <windows.h>
#include <tlhelp32.h>
DWORD ThreadID;
HANDLE hThread;
PVOID ExceptionHandle = NULL;
PVOID T_OrgProc[4];
PVOID T_NewProc[4];
class Dr7_Hook
{
public:
    Dr7_Hook();
    ~Dr7_Hook();
    HANDLE Start_Thread();
    BOOL Initialize();
    DWORD HOOK(PVOID OrgProc, PVOID NewProc);
    BOOL UnHOOK(PVOID NewProc);
    // void Start(HANDLE hThread);
    void Start();
    void Stop();

};

// Hook
void Dr7_Hook::Start()
{
    CONTEXT Context;
    Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    ;
    GetThreadContext(GetCurrentThread(), &Context);
    Context.Dr0 = (DWORD)T_OrgProc[0];
    Context.Dr1 = (DWORD)T_OrgProc[1];
    Context.Dr2 = (DWORD)T_OrgProc[2];
    Context.Dr3 = (DWORD)T_OrgProc[3];
    Context.Dr7 = 0x405;
    SetThreadContext(GetCurrentThread(), &Context);
}
// Hook指定线程
void Start(DWORD dwThreadId)
{
    CONTEXT Context;
    HANDLE hThread;
    Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dwThreadId);
    GetThreadContext(hThread, &Context);
    DbgPrintf_Mine("Hook Addr:%X", T_OrgProc[0]);
    Context.Dr0 = (DWORD)T_OrgProc[0];
    Context.Dr1 = (DWORD)T_OrgProc[1];
    Context.Dr2 = (DWORD)T_OrgProc[2];
    Context.Dr3 = (DWORD)T_OrgProc[3];
    Context.Dr7 = NULL;
    if (Context.Dr0)
    {
        Context.Dr7 = Context.Dr7 | 3;
    }
    if (Context.Dr1)
    {
        Context.Dr7 = Context.Dr7 | 12;
    }
    if (Context.Dr2)
    {
        Context.Dr7 = Context.Dr7 | 48;
    }
    if (Context.Dr3)
    {
        Context.Dr7 = Context.Dr7 | 192;
    }
    Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    // Context.Dr7 = 0x405;
    SetThreadContext(hThread, &Context);
    CloseHandle(hThread);
}
void Dr7_Hook::Stop()
{
    CONTEXT Context;
    Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    ;
    GetThreadContext(GetCurrentThread(), &Context);
    Context.Dr0 = NULL;
    Context.Dr1 = NULL;
    Context.Dr2 = NULL;
    Context.Dr3 = NULL;
    Context.Dr7 = NULL;
    SetThreadContext(GetCurrentThread(), &Context);
}
// 多线程Hook
bool Initialize_Thread()
{
    HANDLE hThreadSnap = NULL;
    // HANDLE hThread;
    DWORD dwMypid;
    dwMypid = GetMyProcessId();
    THREADENTRY32 te32 = {0};
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return (FALSE);
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hThreadSnap, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == dwMypid)
            {
                DbgPrintf_Mine("ThreadID=%d", te32.th32ThreadID);
                if (ThreadID != te32.th32ThreadID)
                {
                    SuspendThread(hThread); // 线程挂起
                    Start(te32.th32ThreadID);
                    ResumeThread(hThread); // 线程恢复
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    else
    {
        return FALSE;
        CloseHandle(hThreadSnap);
    }
    CloseHandle(hThreadSnap);
    return TRUE;
}
HANDLE Dr7_Hook::Start_Thread()
{
    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Initialize_Thread, NULL, NULL, &ThreadID);
    return hThread;
}
DWORD NTAPI ExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
    for (size_t i = 0; i < 4; i++)
    {
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == T_OrgProc[i])
        {
            DbgPrintf_Mine("NewProc Addr=%X", T_NewProc[i]);
            DbgPrintf_Mine("ExceptionHandler To Eip=%X", T_OrgProc[i]);
            ExceptionInfo->ContextRecord->Eip = (DWORD)T_NewProc[i];
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
BOOL Dr7_Hook::Initialize()
{
    BOOL Jud;
    ExceptionHandle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler);
    for (size_t i = 0; i < 4; i++)
    {
        T_OrgProc[i] = NULL;
        T_NewProc[i] = NULL;
    }
    Jud = (BOOL)ExceptionHandle;
    // CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc, this, 0, NULL);
    return Jud;
}
DWORD Dr7_Hook::HOOK(PVOID OrgProc, PVOID NewProc)
{
    for (size_t i = 0; i < 4; i++)
    {
        if (!T_OrgProc[i])
        {
            T_OrgProc[i] = OrgProc;
            T_NewProc[i] = NewProc;
            return i;
        }
    }
    return 0;
}
BOOL Dr7_Hook::UnHOOK(PVOID NewProc)
{
    if (NewProc == NULL)
    {
        Stop();
        return (BOOL)RemoveVectoredExceptionHandler(ExceptionHandle);
    }
    else
    {
        for (size_t i = 0; i < 4; i++)
        {
            if (T_NewProc[i] == NewProc)
            {
                T_OrgProc[i] = 0;
                T_NewProc[i] = 0;
                Start();
                return TRUE;
            }
        }
    }
    return FALSE;
}
Dr7_Hook::Dr7_Hook()
{
    if (ExceptionHandle == NULL)
    {
        if (Initialize())
        {
            DbgPrintf_Mine("Success Initialize VectoredExceptionHandler");
        }
        else
        {
            DbgPrintf_Mine("Error Initialize");
        }
    }
}
Dr7_Hook::~Dr7_Hook()
{
    UnHOOK(NULL);
    CloseHandle(HANDLE(ThreadID));
    DbgPrintf_Mine("Success UnVectoredExceptionHandler！");
}
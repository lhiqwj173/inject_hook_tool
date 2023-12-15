// 针对DWORD类型，按照位来操作
#include <Windows.h>

class Singleton
{
private:
    // 禁用拷贝构造函数
    Singleton(const Singleton &) = delete;

    // 禁用赋值运算符
    Singleton &operator=(const Singleton &) = delete;

public:
    Singleton(){};
};

class bit_data_32 : private Singleton
{
private:
    bit_data_32(){};

    // 检查索引是否合法
    bool check_idx(int index) const
    {
        return index >= 0 && index < 32;
    }

public:
    static bit_data_32 &get_instance()
    {
        static bit_data_32 instance;
        return instance;
    }

    // 设置标志位
    void set_bit(DWORD &flag, int index)
    {
        if (!check_idx(index))
            return;

        flag |= (1 << index);
    }

    // 清除标志位
    void clear_bit(DWORD &flag, int index)
    {
        if (!check_idx(index))
            return;

        flag &= ~(1 << index);
    }

    // 获取标志位
    const bool get_bit(DWORD &flag, int index) const
    {
        if (!check_idx(index))
            return false;

        return flag & (1 << index);
    }
};

class flagdata
{
private:
    DWORD &_flag;
    bit_data_32 &_bit_data = bit_data_32::get_instance();

public:
    flagdata(DWORD &data) : _flag(data){};

    // 设置标志位
    void set(int idx)
    {
        _bit_data.set_bit(_flag, idx);
    }

    // 清除标志位
    void clear(int idx)
    {
        _bit_data.clear_bit(_flag, idx);
    }

    // 获取标志位
    bool get(int idx) const
    {
        return _bit_data.get_bit(_flag, idx);
    }

    DWORD *get_data_ptr()
    {
        return &_flag;
    }

    // 不允许实例化
    virtual ~flagdata(){};
};

// 储存状态
class state_data : public flagdata
{
public:
    enum state
    {
        // hook完成
        HOOK_DONE,

        // 数据更新完成
        DATA_DONE,
    };

    state_data(DWORD &data) : flagdata(data){};
    virtual ~state_data(){};
};
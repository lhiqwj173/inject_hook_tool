#include <iostream>

struct sharedata
{
    int value;
};

// 获取共享数据的函数
sharedata &get_sharedata()
{
    static sharedata sd;
    sd.value = 42;
    return sd;
}

// 回调函数1
void callback1()
{
    static sharedata &d = get_sharedata();
    std::cout << "Callback 1 - d.value: " << d.value << std::endl;
}

// 回调函数2
void callback2()
{
    static sharedata &d = get_sharedata();
    std::cout << "Callback 2 - d.value: " << d.value << std::endl;
}

// 回调函数3
void callback3()
{
    static sharedata &d = get_sharedata();
    std::cout << "Callback 3 - d.value: " << d.value << std::endl;
}

int main()
{

    // 调用回调函数1
    callback1();

    // 调用回调函数2
    callback2();

    // 调用回调函数1
    callback1();

    // 调用回调函数2
    callback2();

    // 调用回调函数3
    callback3();

    getchar();
    return 0;
}

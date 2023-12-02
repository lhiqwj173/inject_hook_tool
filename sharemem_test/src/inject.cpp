#include <windows.h>
#include <iostream>
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

#include "../../sharedata.hpp"

int main()
{
    sharedata d({sharedata::INT, sharedata::DOUBLE, sharedata::CHAR_20}, "TEST");
    if (d.init())
    {
        printf("第一个数据: %d\n", *(int *)d.read(0));
        printf("第二个数据: %f\n", *(double *)d.read(1));
        printf("第三个数据: %s\n", (char *)d.read(2));

        d.hex();

        int a = 1;
        double b = 59.890;
        std::string s = "Hello World!";
        d.set(&a, 0, sharedata::INT);
        d.set(&b, 1, sharedata::DOUBLE);
        d.set(s.data(), 2, sharedata::CHAR_20);

        d.hex();

        printf("第一个数据: %d\n", *(int *)d.read(0));
        printf("第二个数据: %f\n", *(double *)d.read(1));
        printf("第三个数据: %s\n", (char *)d.read(2));
    }
}

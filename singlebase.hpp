/*
单例基类
*/
#pragma once

class singlebase
{
private:
    // 禁止拷贝构造
    singlebase(const singlebase &) = delete;
    // 禁止赋值
    singlebase &operator=(const singlebase &) = delete;

public:
    singlebase() = default;
};
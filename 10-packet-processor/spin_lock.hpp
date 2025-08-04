#pragma once 
#include <atomic>

class spin_lock
{
private:
    std::atomic_flag flag;

public:
    spin_lock();

    ~spin_lock();

    void acquire();

    void release();
};

spin_lock::spin_lock() : flag(ATOMIC_FLAG_INIT) {

}

spin_lock::~spin_lock() {

}

void spin_lock::acquire() {
    while (flag.test_and_set(std::memory_order_acquire));
}

void spin_lock::release() {
    flag.clear(std::memory_order_release);
}
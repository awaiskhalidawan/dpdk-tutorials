#pragma once 
#include <atomic>

class spin_lock
{
private:
    std::atomic_flag flag {ATOMIC_FLAG_INIT};

public:
    spin_lock() : flag(ATOMIC_FLAG_INIT) {

    }

    ~spin_lock() {

    }

    void acquire() {
        while (flag.test_and_set(std::memory_order_acquire));
    }

    void release() {
        flag.clear(std::memory_order_release);
    }
};
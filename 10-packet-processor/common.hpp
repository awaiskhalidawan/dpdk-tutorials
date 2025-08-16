#pragma once
#include <stdint.h>

constexpr uint32_t MAX_QUEUES = 128;

#define ATOMIC_INCREMENT_RELAXED(a, val)  \
    do {                                  \
        a.store((a.load(std::memory_order_relaxed) + val), std::memory_order_relaxed); \
    } while(0);

#define ATOMIC_DECREMENT_RELAXED(a, val)  \
    do {                                  \
        a.store((a.load(std::memory_order_relaxed) - val), std::memory_order_relaxed); \
    } while(0);

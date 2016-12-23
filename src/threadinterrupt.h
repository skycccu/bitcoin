// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mutex>
#include <condition_variable>
#include <atomic>

class CThreadInterrupt
{
public:
    CThreadInterrupt() : interrupt(false), wakeup(false) {}
    void reset()
    {
        interrupt.store(false, std::memory_order_release);
        wakeup.store(false, std::memory_order_release);
    }
    void operator()()
    {
        {
            std::unique_lock<std::mutex> lock(mut);
            interrupt.store(true, std::memory_order_release);
        }
        cond.notify_all();
    }
    explicit operator bool() const
    {
        return interrupt.load(std::memory_order_acquire) == true;
    }

    /*
     * Sleep for the stated period of time, interruptible by clearing the flag and notifying the condvar.
     * @param   rel_time maximum time to wait. Should be a std::chrono::duration.
     * @param   threadInterrupt The interrupt that may wake the sleep
     * @returns false if the sleep was interrupted, true otherwise
     */
    template <typename Duration>
    bool InterruptibleSleep(const Duration& rel_time)
    {
        std::unique_lock<std::mutex> lock(mut);
        return !cond.wait_for(lock, rel_time, [&threadInterrupt]() { return interrupt.load(std::memory_order_acquire) || wakeup.load(std::memory_order_acquire); });
    }

    void NonInterruptWakeup(bool fAll)
    {
        {
            std::unique_lock<std::mutex> lock(mut);
            wakeup.store(true, std::memory_order_release);
        }
        if (fAll)
            cond.notify_all();
        else
            cond.notify_one();
    }

    void ClearWakeup()
    {
        wakeup.store(false, std::memory_order_release);
    }

private:
    std::condition_variable cond;
    std::mutex mut;
    std::atomic<bool> interrupt, wakeup;
};



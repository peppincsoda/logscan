#pragma once

#include <chrono>

namespace logscan
{
    // Simple timing class
    class Clock {
    public:
        void start() {
            time_start = std::chrono::system_clock::now();
        }

        void stop() {
            time_end = std::chrono::system_clock::now();
        }

        double seconds() const {
            std::chrono::duration<double> delta = time_end - time_start;
            return delta.count();
        }
    private:
        std::chrono::time_point<std::chrono::system_clock> time_start, time_end;
    };
} // namespace logscan

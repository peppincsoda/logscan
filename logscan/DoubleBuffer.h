#pragma once

#include <string>
#include <iosfwd>

namespace logscan
{
    class DoubleBuffer
    {
    public:
        using scanBufferFn = bool (const char* buffer, unsigned int buffer_size, void* context);

        explicit DoubleBuffer(int buffer_size);
        ~DoubleBuffer();

        const char* getMatch(unsigned long long to, unsigned long long from);
        bool scanStream(std::istream& stream, scanBufferFn scanBuffer, void* context);

        DoubleBuffer(const DoubleBuffer&) = delete;
        DoubleBuffer& operator=(const DoubleBuffer&) = delete;

        DoubleBuffer(DoubleBuffer&&) = delete;
        DoubleBuffer& operator=(DoubleBuffer&&) = delete;

    private:
        int buffer_size_;
        std::string buffer_;
        char* curr_buffer_;
        char* prev_buffer_;

        std::string match_buffer_;
        unsigned long long bytes_processed_;
    };

} // namespace logscan

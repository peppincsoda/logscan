#include "DoubleBuffer.h"

#include <iostream>
#include <cstring>

using namespace std;

namespace logscan
{
    DoubleBuffer::DoubleBuffer(int buffer_size)
        : buffer_size_(buffer_size)
        , buffer_(buffer_size * 2, '\0')
        , curr_buffer_(&buffer_[0])
        , prev_buffer_(&buffer_[buffer_size])
        , match_buffer_(buffer_size, '\0')
        , bytes_processed_(0)
    {
    }

    DoubleBuffer::~DoubleBuffer()
    {

    }

    const char* DoubleBuffer::getMatch(unsigned long long to, unsigned long long from) {
        const int match_length = to - from;
        if (match_length > buffer_size_) {
            cerr << "Match length is greater than the buffer size" << endl;
            return nullptr;
        }

        const char* match = nullptr;
        // `to` is always >= `bytes_processed_`
        if (from >= bytes_processed_) {
            // The start of the match is in the same buffer as the end
            if (curr_buffer_ == &buffer_[buffer_size_]) {
                // It starts in the 2nd buffer
                match = &buffer_[buffer_size_ + (from - bytes_processed_)];
            } else {
                // It starts in the 1st buffer
                match = &buffer_[from - bytes_processed_];
            }
        } else {
            // The start and the end are in different buffers
            if (curr_buffer_ == &buffer_[buffer_size_]) {
                // It starts in the 1st buffer so is contiguous
                match = &buffer_[from - (bytes_processed_ - buffer_size_)];
            } else {
                // It starts in the 2nd buffer so we need to copy to make it contiguous
                match = &match_buffer_[0];
                memcpy(&match_buffer_[0],
                    &buffer_[2*buffer_size_ - (bytes_processed_ - from)],
                    bytes_processed_ - from);
                memcpy(&match_buffer_[bytes_processed_ - from],
                    &buffer_[0],
                    to - bytes_processed_);
            }
        }

        return match;
    }

    bool DoubleBuffer::scanStream(istream& stream, scanBufferFn scanBuffer, void* context)
    {
        for (;;) {
            stream.read(curr_buffer_, buffer_size_);
            const unsigned int bytes_read = stream.gcount();

            if (!scanBuffer(curr_buffer_, bytes_read, context))
                return false;

            bytes_processed_ += bytes_read;
            if (bytes_read < buffer_size_)
                break;

            std::swap(curr_buffer_, prev_buffer_);
        }
        return true;
    }

} // logscan

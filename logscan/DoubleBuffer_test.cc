#include "DoubleBuffer.h"

#include <sstream>

#include <gtest/gtest.h>

using namespace std;
using namespace logscan;

static bool TestScanBuffer(const char* buffer, unsigned int buffer_size, void* context)
{
    DoubleBuffer* buf = static_cast<DoubleBuffer*>(context);
    const char* match = buf->GetMatch(4, 0);
    EXPECT_STREQ("alma", match);
}

TEST(DoubleBuffer, Test1)
{
    stringstream stream("alma");

    DoubleBuffer buf(4);
    buf.ScanStream(stream, TestScanBuffer, &buf);
}

#include "logscan.h"

#include <gtest/gtest.h>

void f()
{
  test_fn(42);
}

TEST(sample_test_case, sample_test)
{
    EXPECT_EQ(1, 1);
}

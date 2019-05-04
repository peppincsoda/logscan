#include "RegexDB.h"

#include <gtest/gtest.h>

using namespace logscan;

TEST(RegexDB, AddPattern)
{
    RegexDB db;
    db.AddPattern("id", "pattern", 0);
}

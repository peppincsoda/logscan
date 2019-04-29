#include "PatternsDB.h"

#include <gtest/gtest.h>

using namespace logscan;

TEST(PatternsDB, addPattern)
{
    PatternsDB db;
    db.addPattern("id", "pattern", 0);
}

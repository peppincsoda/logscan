#ifndef LOGSCAN_HYPERSCANDB_H_
#define LOGSCAN_HYPERSCANDB_H_

#include <string>
#include <hs/hs.h>

#include "RegexArray.h"

namespace logscan
{
    class HyperscanDB
    {
    public:
        HyperscanDB();
        ~HyperscanDB();

        HyperscanDB(const HyperscanDB&) = delete;
        HyperscanDB& operator=(const HyperscanDB&) = delete;

        HyperscanDB(HyperscanDB&&) = default;
        HyperscanDB& operator=(HyperscanDB&&) = default;

        bool BuildFrom(const RegexArray& regexes);

        int FindRegex(const std::string& line);

    private:
        static int OnMatch(unsigned int id, unsigned long long from, unsigned long long to,
            unsigned int flags, void* context);

        hs_database_t* db_;
        hs_scratch_t* scratch_;

        int match_id_;
    };
} // namespace logscan

#endif  // LOGSCAN_HYPERSCANDB_H_

#ifndef LOGSCAN_PCREDB_H_
#define LOGSCAN_PCREDB_H_

#include <vector>
#include <unordered_map>
#include <pcre.h>

#include "RegexArray.h"

namespace logscan
{
    using CaptureGroups = std::unordered_map<std::string, std::string>;

    enum class PCREMatchResult
    {
        OK,
        NoMatch,
        Error,
    };

    class PCREDB
    {
    public:
        PCREDB();
        ~PCREDB();

        PCREDB(const PCREDB&) = delete;
        PCREDB& operator=(const PCREDB&) = delete;

        PCREDB(PCREDB&&) = default;
        PCREDB& operator=(PCREDB&&) = default;

        bool BuildFrom(const RegexArray& regexes);

        PCREMatchResult MatchRegex(int index, const std::string& line, CaptureGroups& capture_groups) const;

    private:
        struct PCRE
        {
            pcre* pcregex = nullptr;
            int name_count = 0;
            int name_entry_size = 0;
            char* name_table = nullptr;
        };

        std::vector<PCRE> pcres_;
    };
} // namespace logscan

#endif  // LOGSCAN_PCREDB_H_

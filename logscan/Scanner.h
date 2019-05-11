#ifndef LOGSCAN_SCANNER_H_
#define LOGSCAN_SCANNER_H_

#include <functional>
#include <string>

#include "HyperscanDB.h"
#include "PCREDB.h"
#include "RegexArray.h"

namespace logscan
{
    struct MatchResults
    {
        std::string regex_id;
        CaptureGroups capture_groups;
    };

    using ScannerMatchFn = std::function<void (const MatchResults& results)>;

    class Scanner
    {
    public:
        explicit Scanner(ScannerMatchFn match_fn);
        ~Scanner();

        Scanner(const Scanner&) = delete;
        Scanner& operator=(const Scanner&) = delete;

        Scanner(Scanner&&) = default;
        Scanner& operator=(Scanner&&) = default;

        bool BuildFrom(const char* patterns_file);

        bool ScanStream(std::istream& input_stream);

    private:
        bool ProcessLine(const std::string& line, MatchResults& match_results);

        RegexArray regex_array_;
        HyperscanDB hs_db_;
        PCREDB pcre_db_;
        ScannerMatchFn match_fn_;
    };

    void PrintJSONMatchFn(const MatchResults& results, std::ostream& output_stream);

} // namespace logscan

#endif  // LOGSCAN_SCANNER_H_

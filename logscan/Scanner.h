#ifndef LOGSCAN_SCANNER_H_
#define LOGSCAN_SCANNER_H_

#include <iosfwd>
#include <functional>

#include "DoubleBuffer.h"
#include "RegexDB.h"

namespace logscan
{
    using ScannerMatchFn = std::function<void (const MatchResults& results)>;

    void PrintJSONMatchFn(const MatchResults& results, std::ostream& output_stream);

    class Scanner
    {
    public:
        explicit Scanner(const RegexDB& regex_db, ScannerMatchFn match_fn);
        ~Scanner();

        Scanner(const Scanner&) = delete;
        Scanner& operator=(const Scanner&) = delete;

        Scanner(Scanner&&) = default;
        Scanner& operator=(Scanner&&) = default;

        void ScanStream(std::istream& input_stream);

    private:
        static int OnMatch(unsigned int id, unsigned long long from, unsigned long long to,
            unsigned int flags, void* context);
        int OnMatch(unsigned int id, unsigned long long from, unsigned long long to,
            unsigned int flags);
        static bool ScanBuffer(const char* buffer, unsigned int buffer_size, void* context);

    private:
        const RegexDB& regex_db_;
        ScannerMatchFn match_fn_;

        DoubleBuffer dbl_buf_;

        // Hyperscan temporary scratch space
        hs_scratch_t* scratch_;

        // Hyperscan stream state
        hs_stream_t* stream_;
    };
} // namespace logscan

#endif  // LOGSCAN_SCANNER_H_

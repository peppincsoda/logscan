#include "Scanner.h"

#include <iostream>

using namespace std;

namespace logscan
{
    Scanner::Scanner(const RegexDB& regex_db, ScannerMatchFn match_fn)
    : regex_db_(regex_db)
    , match_fn_(std::move(match_fn))
    , dbl_buf_(16) // TODO: parameterize?
    , scratch_(nullptr)
    , stream_(nullptr)
    {
        hs_error_t err = hs_alloc_scratch(regex_db_.hs_db_, &scratch_);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: could not allocate scratch space. Exiting." << endl;
            exit(-1);
        }

        err = hs_open_stream(regex_db_.hs_db_, 0, &stream_);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: Unable to open stream. Exiting." << endl;
            exit(-1);
        }
    }

    Scanner::~Scanner()
    {
        // Close Hyperscan stream (potentially generating any end-anchored matches)
        hs_error_t err = hs_close_stream(stream_, scratch_, OnMatch,
                                            this);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: Unable to close stream. Exiting." << endl;
            exit(-1);
        }

        if (scratch_ != nullptr) {
            hs_free_scratch(scratch_);
            scratch_ = nullptr;
        }
    }

    // Match event handler: called every time Hyperscan finds a match.
    int Scanner::OnMatch(unsigned int id, unsigned long long from, unsigned long long to,
        unsigned int flags, void* context)
    {
        return static_cast<Scanner*>(context)->OnMatch(id, from, to, flags);
    }

    int Scanner::OnMatch(unsigned int id, unsigned long long from, unsigned long long to,
        unsigned int flags)
    {
        const char* match = dbl_buf_.GetMatch(to, from);
        if (match == nullptr)
            return 0;
        const int match_length = to - from;

        MatchResults match_results;
        regex_db_.Execute(match, match_length, id, match_results);

        match_fn_(match_results);

        return 0; // continue matching
    }

    bool Scanner::ScanBuffer(const char* buffer, unsigned int buffer_size, void* context) {
        Scanner* self = static_cast<Scanner*>(context);

        hs_error_t err = hs_scan_stream(self->stream_,
                                        buffer, buffer_size, 0,
                                        self->scratch_, OnMatch, self);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: Unable to scan buffer. Exiting." << endl;
            return false;
        }
        return true;
    }

    void Scanner::ScanStream(istream& input_stream)
    {
        dbl_buf_.ScanStream(input_stream, ScanBuffer, this);
    }

    void PrintJSONMatchFn(const MatchResults& results, std::ostream& output_stream)
    {
        output_stream << "{ \"id\": \"" << results.regex_id << "\"";
        for (const auto& group : results.capture_groups) {
            output_stream << ", \"" << group.first
                        << "\": \"" << group.second
                        << "\"";

        }
        output_stream << " }" << endl;
    }

} // namespace logscan

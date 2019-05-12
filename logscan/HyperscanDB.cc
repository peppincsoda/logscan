#include "HyperscanDB.h"

#include <iostream>

using namespace std;

namespace logscan
{
    HyperscanDB::HyperscanDB()
    : db_(nullptr)
    , scratch_(nullptr)
    , match_id_(-1)
    {
    }

    bool HyperscanDB::BuildFrom(const RegexArray& regexes)
    {
        const unsigned int common_flags = HS_FLAG_ALLOWEMPTY;

        vector<const char*> cstr_patterns;
        vector<unsigned int> all_flags;
        vector<unsigned int> num_seq;
        for (int i = 0; i < regexes.size(); i++) {
            const auto& regex = regexes.get(i);
            cstr_patterns.push_back(regex.pattern.c_str());
            all_flags.push_back(regex.flags | common_flags);
            num_seq.push_back(i);
        }

        hs_compile_error_t* compile_err;
        hs_error_t err;
        err = hs_compile_multi(
            cstr_patterns.data(),
            all_flags.data(),
            num_seq.data(),
            regexes.size(),
            HS_MODE_BLOCK,
            nullptr,
            &db_,
            &compile_err);

        if (err != HS_SUCCESS) {
            if (compile_err->expression < 0) {
                // The error does not refer to a particular expression
                cerr << "Hyperscan error: " << compile_err->message << endl;
            } else {
                cerr << "Hyperscan error: Pattern '" << cstr_patterns[compile_err->expression]
                    << "' failed compilation with error: " << compile_err->message << endl;
            }
            // As the compile_err pointer points to dynamically allocated memory, if
            // we get an error, we must be sure to release it
            hs_free_compile_error(compile_err);
            return false;
        }

        err = hs_alloc_scratch(db_, &scratch_);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: could not allocate scratch space" << endl;
            return false;
        }

        return true;
    }

    HyperscanDB::~HyperscanDB()
    {
        if (scratch_ != nullptr) {
            hs_free_scratch(scratch_);
            scratch_ = nullptr;
        }

        if (db_ != nullptr) {
            hs_free_database(db_);
            db_ = nullptr;
        }
    }

    int HyperscanDB::OnMatch(unsigned int id, unsigned long long from, unsigned long long to,
        unsigned int flags, void* context)
    {
        (void)from;
        (void)to;
        (void)flags;

        static_cast<HyperscanDB*>(context)->match_id_ = id;
        return 0; // continue scanning
    }

    int HyperscanDB::FindRegex(const string& line)
    {
        match_id_ = -1;

        hs_error_t err = hs_scan(db_, line.c_str(), line.size(), 0, scratch_, OnMatch, this);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: Unable to scan buffer: " << err << endl;
            return -1;
        }

        return match_id_;
    }

} // namespace logscan

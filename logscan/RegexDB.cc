#include "RegexDB.h"

#include <fstream>
#include <iomanip>
#include <iostream>

#include "Clock.h"

using namespace std;

namespace logscan
{
    RegexDB::RegexDB()
    : ids_()
    , patterns_()
    , flags_()
    , hs_db_(nullptr)
    , pcres_()
    , compiled_(false)
    {
    }

    RegexDB::~RegexDB()
    {
        for (auto re : pcres_) {
            pcre_free(re);
        }

        if (hs_db_ != nullptr) {
            hs_free_database(hs_db_);
            hs_db_ = nullptr;
        }
    }

    RegexDB RegexDB::LoadFromFile(const char* filename)
    {
        ifstream input_stream(filename);
        if (!input_stream.good()) {
            cerr << "Cannot open patterns file: " << filename << endl;
            exit(-1);
        }

        return LoadFromFile(input_stream);
    }

    RegexDB RegexDB::LoadFromFile(istream& input_stream)
    {
        RegexDB db;

        ParseFile(input_stream, db.ids_, db.patterns_, db.flags_);
        db.Compile();

        return db;
    }

    void RegexDB::AddPattern(const string& id, const string& pattern, unsigned int flags)
    {
        ids_.push_back(id);
        patterns_.push_back(pattern);
        flags_.push_back(flags);
    }

    void RegexDB::Compile()
    {
        // This function can be called only once
        if (compiled_) {
            return;
        } else {
            compiled_ = true;
        }

        CompileHS();
        CompilePCRE();
    }

    void RegexDB::CompileHS()
    {
        Clock clock;
        clock.start();

        vector<const char*> cstr_patterns;
        for (const auto& pattern : patterns_) {
            cstr_patterns.push_back(pattern.c_str());
        }

        // TODO: Do we really need this?
        for (auto& flags : flags_) {
            flags = flags | HS_FLAG_SOM_LEFTMOST;
        }

        vector<unsigned int> num_seq(patterns_.size());
        for (size_t i = 0; i < patterns_.size(); i++)
            num_seq[i] = i;

        hs_compile_error_t* compile_err;
        hs_error_t err;

        err = hs_compile_multi(
            cstr_patterns.data(),
            flags_.data(),
            num_seq.data(),
            patterns_.size(),
            HS_MODE_STREAM | HS_MODE_SOM_HORIZON_SMALL, // find patterns having length up to 2^16,
            nullptr,
            &hs_db_,
            &compile_err);

        if (err != HS_SUCCESS) {
            if (compile_err->expression < 0) {
                // The error does not refer to a particular expression.
                cerr << "ERROR: " << compile_err->message << endl;
            } else {
                cerr << "ERROR: Pattern '" << patterns_[compile_err->expression]
                    << "' failed compilation with error: " << compile_err->message << endl;
            }
            // As the compile_err pointer points to dynamically allocated memory, if
            // we get an error, we must be sure to release it. This is not
            // necessary when no error is detected.
            hs_free_compile_error(compile_err);
            exit(-1);
        }

        clock.stop();
        cout << "Hyperscan streaming"
            << " mode database compiled in " << clock.seconds() << " seconds" << endl;
    }

    void RegexDB::CompilePCRE()
    {
        Clock clock;
        clock.start();

        for (const auto& pattern : patterns_) {
            const char* err;
            int erroffset;

            pcre* re = pcre_compile(
                pattern.c_str(),      /* the pattern */
                0,                    /* default options */
                &err,                 /* for error message */
                &erroffset,           /* for error offset */
                nullptr);             /* use default character tables */

            if (re == nullptr) {
                cerr << "PCRE compilation failed at offset " << erroffset << ":" << err << endl;
                exit(-1);
            }

            pcres_.push_back(re);
        }

        clock.stop();
        cout << fixed << setprecision(4);
        cout << "Compilation of PCRE patterns took " << clock.seconds() << " seconds" << endl;
    }

    void ParseFile(istream& input_stream, vector<string>& ids,
                    vector<string>& patterns, vector<unsigned int>& flags)
    {
        for (int i = 1; !input_stream.eof(); ++i) {
            string line;
            getline(input_stream, line);

            // if line is empty, or a comment, we can skip it
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // otherwise, it should be ID:PCRE, e.g.
            //  10001:/foobar/is
            const size_t colon_idx = line.find_first_of(':');
            if (colon_idx == string::npos) {
                cerr << "ERROR: Missing ':' char" << i << endl;
                exit(-1);
            }

            // we should have a string as an ID, before the colon
            const string id(line.substr(0, colon_idx));

            // rest of the expression is the PCRE
            const string expr(line.substr(colon_idx + 1));

            const size_t flags_start = expr.find_last_of('/');
            if (flags_start == string::npos) {
                cerr << "ERROR: no trailing '/' char" << endl;
                exit(-1);
            }

            const string pcre(expr.substr(1, flags_start - 1));
            const string flags_str(expr.substr(flags_start + 1, expr.size() - flags_start));
            const unsigned int pattern_flags = ParseFlags(flags_str);

            ids.push_back(id);
            patterns.push_back(pcre);
            flags.push_back(pattern_flags);
        }
    }

    unsigned int ParseFlags(const string& flags_str) {
        unsigned int flags = 0;
        for (const char& c : flags_str) {
            switch (c) {
            case 'i':
                flags |= HS_FLAG_CASELESS; break;
            case 'm':
                flags |= HS_FLAG_MULTILINE; break;
            case 's':
                flags |= HS_FLAG_DOTALL; break;
            case 'H':
                flags |= HS_FLAG_SINGLEMATCH; break;
            case 'V':
                flags |= HS_FLAG_ALLOWEMPTY; break;
            case '8':
                flags |= HS_FLAG_UTF8; break;
            case 'W':
                flags |= HS_FLAG_UCP; break;
            case '\r': // stray carriage-return
                break;
            default:
                cerr << "Unsupported flag \'" << c << "\'" << endl;
                exit(-1);
            }
        }
        return flags;
    }

    void RegexDB::Execute(const char* buffer, int buffer_length, unsigned int hs_id, MatchResults &match_results) const
    {
        pcre* re = pcres_[hs_id];

        const int OVECCOUNT = 30;    /* should be a multiple of 3 */
        int ovector[OVECCOUNT];

        const int rc = pcre_exec(
            re,                   /* the compiled pattern */
            nullptr,              /* no extra data - we didn't study the pattern */
            buffer,               /* the subject string */
            buffer_length,        /* the length of the subject */
            0,                    /* start at offset 0 in the subject */
            0,                    /* default options */
            ovector,              /* output vector for substring information */
            OVECCOUNT);           /* number of elements in the output vector */

        /* Matching failed: handle error cases */
        if (rc < 0) {
            switch(rc) {
            // This can happen as PCRE does a greedy match while HS doesn't
            case PCRE_ERROR_NOMATCH: cout << "Mismatch between Hyperscan and PCRE" << endl; break;
            /*
            Handle other special cases if you like
            */
            default: cout << "Matching error " << rc << endl; break;
            }
            return; // TODO: error handling
        }

        /* The output vector wasn't big enough */
        if (rc == 0) {
            cout << "ovector only has room for " << ((OVECCOUNT/3) - 1) << " captured substrings" << endl;
        }

        /* See if there are any named substrings, and if so, show them by name. First
        we have to extract the count of named parentheses from the pattern. */

        int namecount;
        pcre_fullinfo(
            re,                   /* the compiled pattern */
            nullptr,              /* no extra data - we didn't study the pattern */
            PCRE_INFO_NAMECOUNT,  /* number of named substrings */
            &namecount);          /* where to put the answer */

        if (namecount <= 0) {
            //printf("No named substrings\n");
        } else {
            int name_entry_size;
            char* name_table;
            char* tabptr;
            //printf("Named substrings\n");

            /* Before we can access the substrings, we must extract the table for
            translating names to numbers, and the size of each entry in the table. */

            pcre_fullinfo(
                re,                       /* the compiled pattern */
                nullptr,                  /* no extra data - we didn't study the pattern */
                PCRE_INFO_NAMETABLE,      /* address of the table */
                &name_table);             /* where to put the answer */

            pcre_fullinfo(
                re,                       /* the compiled pattern */
                nullptr,                  /* no extra data - we didn't study the pattern */
                PCRE_INFO_NAMEENTRYSIZE,  /* size of each entry in the table */
                &name_entry_size);        /* where to put the answer */

            /* Now we can scan the table and, for each entry, print the number, the name,
            and the substring itself. */

            tabptr = name_table;
            match_results.regex_id = ids_[hs_id];
            for (int i = 0; i < namecount; i++) {
                const int n = (tabptr[0] << 8) | tabptr[1];

                match_results.capture_groups[string(tabptr + 2, name_entry_size - 3)] =
                    string(buffer + ovector[2*n], ovector[2*n+1] - ovector[2*n]);
                tabptr += name_entry_size;
            }
        }

    }

} // namespace logscan

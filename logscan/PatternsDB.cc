#include "PatternsDB.h"
#include "Clock.h"

#include <iomanip>
#include <iostream>
#include <fstream>

using namespace std;

namespace logscan
{
    PatternsDB::PatternsDB()
    : ids_()
    , patterns_()
    , flags_()
    , hs_db_(nullptr)
    , compiled_patterns_()
    , compiled_(false)
    {
    }

    PatternsDB::~PatternsDB()
    {
        for (auto re : compiled_patterns_) {
            pcre_free(re);
        }

        if (hs_db_ != nullptr) {
            hs_free_database(hs_db_);
            hs_db_ = nullptr;
        }
    }

    PatternsDB PatternsDB::loadFromFile(const char *filename)
    {
        ifstream inFile(filename);
        if (!inFile.good()) {
            cerr << "Cannot open patterns file: " << filename << endl;
            exit(-1);
        }

        return loadFromFile(inFile);
    }

    PatternsDB PatternsDB::loadFromFile(istream &inFile)
    {
        PatternsDB db;

        parseFile(inFile, db.ids_, db.patterns_, db.flags_);
        db.compile();

        return db;
    }

    void PatternsDB::addPattern(const string &id, const string &pattern, unsigned int flags)
    {
        ids_.push_back(id);
        patterns_.push_back(pattern);
        flags_.push_back(flags);
    }

    void PatternsDB::compile()
    {
        // This function can be called only once
        if (compiled_) {
            return;
        } else {
            compiled_ = true;
        }

        compileHS();
        compilePCRE();
    }

    void PatternsDB::compileHS()
    {
        Clock clock;
        clock.start();

        vector<const char*> cstrPatterns;
        for (const auto &pattern : patterns_) {
            cstrPatterns.push_back(pattern.c_str());
        }

        // TODO: Do we really need this?
        for (auto &flags : flags_) {
            flags = flags | HS_FLAG_SOM_LEFTMOST;
        }

        vector<unsigned int> num_seq(patterns_.size());
        for (size_t i = 0; i < patterns_.size(); i++)
            num_seq[i] = i;

        hs_compile_error_t *compileErr;
        hs_error_t err;

        err = hs_compile_multi(
            cstrPatterns.data(),
            flags_.data(),
            num_seq.data(),
            patterns_.size(),
            HS_MODE_STREAM | HS_MODE_SOM_HORIZON_SMALL, // find patterns having length up to 2^16,
            nullptr,
            &hs_db_,
            &compileErr);

        if (err != HS_SUCCESS) {
            if (compileErr->expression < 0) {
                // The error does not refer to a particular expression.
                cerr << "ERROR: " << compileErr->message << endl;
            } else {
                cerr << "ERROR: Pattern '" << patterns_[compileErr->expression]
                    << "' failed compilation with error: " << compileErr->message << endl;
            }
            // As the compileErr pointer points to dynamically allocated memory, if
            // we get an error, we must be sure to release it. This is not
            // necessary when no error is detected.
            hs_free_compile_error(compileErr);
            exit(-1);
        }

        clock.stop();
        cout << "Hyperscan streaming"
            << " mode database compiled in " << clock.seconds() << " seconds" << endl;
    }

    void PatternsDB::compilePCRE()
    {
        Clock clock;
        clock.start();

        for (const auto& pattern : patterns_) {
            const char *error;
            int erroffset;

            pcre *re = pcre_compile(
                pattern.c_str(),      /* the pattern */
                0,                    /* default options */
                &error,               /* for error message */
                &erroffset,           /* for error offset */
                nullptr);             /* use default character tables */

            if (re == nullptr) {
                cerr << "PCRE compilation failed at offset " << erroffset << ":" << error << endl;
                exit(-1);
            }

            compiled_patterns_.push_back(re);
        }

        clock.stop();
        cout << fixed << setprecision(4);
        cout << "Compilation of PCRE patterns took " << clock.seconds() << " seconds" << endl;
    }

    void parseFile(istream &inFile, vector<string> &ids,
                    vector<string> &patterns, vector<unsigned int> &flags)
    {
        for (int i = 1; !inFile.eof(); ++i) {
            string line;
            getline(inFile, line);

            // if line is empty, or a comment, we can skip it
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // otherwise, it should be ID:PCRE, e.g.
            //  10001:/foobar/is
            size_t colonIdx = line.find_first_of(':');
            if (colonIdx == string::npos) {
                cerr << "ERROR: Missing ':' char" << i << endl;
                exit(-1);
            }

            // we should have a string as an ID, before the colon
            const string id(line.substr(0, colonIdx));

            // rest of the expression is the PCRE
            const string expr(line.substr(colonIdx + 1));

            size_t flagsStart = expr.find_last_of('/');
            if (flagsStart == string::npos) {
                cerr << "ERROR: no trailing '/' char" << endl;
                exit(-1);
            }

            const string pcre(expr.substr(1, flagsStart - 1));
            const string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
            const unsigned int patternFlags = parseFlags(flagsStr);

            ids.push_back(id);
            patterns.push_back(pcre);
            flags.push_back(patternFlags);
        }
    }

    unsigned int parseFlags(const string &flagsStr) {
        unsigned int flags = 0;
        for (const char &c : flagsStr) {
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

} // namespace logscan

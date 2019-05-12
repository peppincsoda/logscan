#include "RegexArray.h"

#include <fstream>
#include <iostream>

using namespace std;

namespace logscan
{
    RegexArray::RegexArray()
    : regexes_()
    , prefix_regex_index_(-1)
    {
    }

    void RegexArray::AddRegex(const std::string& id, const std::string& pattern, unsigned int flags)
    {
        if (id == "prefix") {
            prefix_regex_index_ = regexes_.size();
        }

        regexes_.emplace_back(Regex { id, pattern, flags });
    }

    bool RegexArray::LoadFromFile(const char* filename)
    {
        ifstream input_stream(filename);
        if (!input_stream.good()) {
            cerr << "Cannot open patterns file: " << filename << endl;
            return false;
        }

        return LoadFromFile(input_stream);
    }

    bool RegexArray::LoadFromFile(istream& input_stream)
    {
        for (int lineno = 1; !input_stream.eof(); lineno++) {
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
                cerr << "ERROR: Missing ':' char at line " << lineno << endl;
                return false;
            }

            // we should have a string as an ID, before the colon
            const string id(line.substr(0, colon_idx));

            // rest of the expression is the PCRE
            const string expr(line.substr(colon_idx + 1));

            const size_t flags_start = expr.find_last_of('/');
            if (flags_start == string::npos) {
                cerr << "ERROR: no trailing '/' char" << endl;
                return false;
            }

            const string pattern(expr.substr(1, flags_start - 1));
            const string flags_str(expr.substr(flags_start + 1, expr.size() - flags_start));

            AddRegex(id, pattern, 0);
        }

        return true;
    }

} // namespace logscan

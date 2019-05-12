#include "Scanner.h"

#include <iostream>

using namespace std;

namespace logscan
{
    Scanner::Scanner(ScannerMatchFn match_fn)
    : regex_array_()
    , hs_db_()
    , pcre_db_()
    , match_fn_(std::move(match_fn))
    {
    }

    Scanner::~Scanner()
    {
    }

    bool Scanner::BuildFrom(const char* patterns_file)
    {
        if (!regex_array_.LoadFromFile(patterns_file))
            return false;

        if (!hs_db_.BuildFrom(regex_array_))
            return false;

        if (!pcre_db_.BuildFrom(regex_array_))
            return false;

        return true;
    }

    bool Scanner::ProcessLine(const string& line, MatchResults& results)
    {
        CaptureGroups::iterator details_it = results.capture_groups.end();
        if (regex_array_.prefix_regex_index() != -1) {
            if (pcre_db_.MatchRegex(regex_array_.prefix_regex_index(), line, results.capture_groups) == PCREDB::PCRE_OK) {
                details_it = results.capture_groups.find("details");
                // prefix_regex must contain a capture group named "details"
            }
        }

        const string* message = nullptr;
        if (details_it != results.capture_groups.end()) {
            message = &details_it->second;
        } else {
            message = &line;
        }

        const int regex_index = hs_db_.FindRegex(*message);
        if (regex_index == -1) {
            results.regex_id = "";
            return false;
        }

        results.regex_id = regex_array_.get(regex_index).id;
        const PCREDB::MatchResult result = pcre_db_.MatchRegex(regex_index, *message, results.capture_groups);
        if (result != PCREDB::PCRE_OK) {
            if (result == PCREDB::PCRE_NoMatch) {
                // This can happen as PCRE does a greedy match while HS doesn't
                cerr << "Mismatch between Hyperscan and PCRE for regex id: " << results.regex_id << endl;
            }
            return false;
        }

        if (details_it != results.capture_groups.end()) {
            results.capture_groups.erase(details_it); // delete "details" from the output
        }

        return true;
    }

    bool Scanner::ScanStream(istream& input_stream)
    {
        for (string line; getline(input_stream, line); ) {
            MatchResults results;
            if (ProcessLine(line, results)) {
                match_fn_(results);
            }
        }

        return true;
    }

    void PrintJSONMatchFn(const MatchResults& results, ostream& output_stream)
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

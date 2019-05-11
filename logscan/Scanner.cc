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
        CaptureGroups::iterator message_it = results.capture_groups.end();
        if (regex_array_.prefix_regex_index() != -1) {
            if (pcre_db_.MatchRegex(regex_array_.prefix_regex_index(), line, results.capture_groups)) {
                message_it = results.capture_groups.find("message");
                // prefix_regex must contain a capture group named "message"
            }
        }

        const string* message = nullptr;
        if (message_it != results.capture_groups.end()) {
            message = &message_it->second;
        } else {
            message = &line;
        }

        const int regex_index = hs_db_.FindRegex(*message);
        results.regex_id = regex_array_.get(regex_index).id;
        if (regex_index == -1)
            return false;

        if (!pcre_db_.MatchRegex(regex_index, *message, results.capture_groups))
            return false;

        if (message_it != results.capture_groups.end()) {
            results.capture_groups.erase(message_it); // delete "message" from the output
        }
    }

    bool Scanner::ScanStream(istream& input_stream)
    {
        for (string line; getline(input_stream, line); ) {
            line.push_back('\n');

            MatchResults results;
            if (ProcessLine(line, results)) {
                match_fn_(results);
            }
        }
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

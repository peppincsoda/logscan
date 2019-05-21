#include "Scanner.h"

#include "Clock.h"

#include <iostream>

using namespace std;

namespace logscan
{
    Scanner::Scanner(ScannerMatchFn match_fn, bool perf_stats)
    : regex_array_()
    , hs_db_()
    , pcre_db_()
    , match_fn_(std::move(match_fn))
    , perf_stats_(perf_stats)
    {
    }

    Scanner::~Scanner()
    {
    }

    bool Scanner::BuildFrom(const char* patterns_file)
    {
        if (!regex_array_.LoadFromFile(patterns_file))
            return false;

        Clock clock;
        clock.start();
        if (!hs_db_.BuildFrom(regex_array_))
            return false;
        clock.stop();
        if (perf_stats_) {
            cerr << "Hyperscan DB compilation time (sec): " << clock.seconds() << endl;
        }

        clock.start();
        if (!pcre_db_.BuildFrom(regex_array_))
            return false;
        clock.stop();
        if (perf_stats_) {
            cerr << "PCRE compilation time (sec): " << clock.seconds() << endl;
        }

        return true;
    }

    bool Scanner::ProcessLine(const string& line, MatchResults& results)
    {
        CaptureGroups::iterator details_it = results.capture_groups.end();
        if (regex_array_.prefix_regex_index() != -1) {
            if (pcre_db_.MatchRegex(regex_array_.prefix_regex_index(), line, results.capture_groups) == PCREMatchResult::OK) {
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
        const PCREMatchResult result = pcre_db_.MatchRegex(regex_index, *message, results.capture_groups);
        if (result != PCREMatchResult::OK) {
            if (result == PCREMatchResult::NoMatch) {
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
        Clock clock;
        clock.start();
        int total_lines = 0;
        int total_bytes = 0;
        for (string line; getline(input_stream, line); ) {
            // Support both Windows and macOS/Linux line endings
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            MatchResults results;
            if (ProcessLine(line, results)) {
                match_fn_(results);
            }

            total_lines++;
            total_bytes += line.size();
        }
        clock.stop();
        if (perf_stats_) {
            cerr << "Total scanning time (sec): " << clock.seconds() << endl;
            cerr << "Total number of lines: " << total_lines << endl;
            cerr << "Total bytes: " << total_bytes << endl;
            cerr << "Average throughput (bytes/sec): " << (total_bytes / clock.seconds()) << endl;
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

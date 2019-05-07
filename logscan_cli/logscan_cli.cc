
#include <iostream>
#include <fstream>
#include <unistd.h> // getopt

#include "logscan/logscan.h"

using namespace std;
using namespace logscan;

static void Usage(const char* prog) {
    cerr << "Usage: " << prog << " [-n repeats] <pattern file> <log file>" << endl;
}

static void ProcessLine(const string& line, CaptureGroups& capture_groups)
{
    CaptureGroups message_it = capture_groups.end();
    if (prefix_regex != null) {
        if (MatchRegex(prefix_regex, line, capture_groups)) {
            message_it = capture_groups.find("message");
            // prefix_regex must contain a capture group named "message"
        }
    }

    string* message = nullptr;
    if (message_it != capture_groups.end()) {
        message = &message_it->second;
    } else {
        message = &line;
    }

    const int regex_id = FindRegex(regex_db, *message);
    if (regex_id > 0) {
        MatchRegex(regex_db[regex_id], *message, capture_groups);
    }

    if (message_it != capture_groups.end()) {
        capture_groups.erase(message_it); // delete "message" from the output
    }
}

static void ProcessStream(istream& input, ostream& output)
{
    for (string line; getline(input, line); ) {
        line.push_back('\n');

        CaptureGroups capture_groups;
        if (ProcessLine(line, capture_groups)) {
            output << line;
        }
    }
}

int main(int argc, char** argv) {
    //unsigned int repeat_count = 1;

    // Process command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "n:")) != -1) {
        switch (opt) {
        case 'n':
            //repeat_count = atoi(optarg);
            break;
        default:
            Usage(argv[0]);
            exit(-1);
        }
    }

    if (argc - optind != 2) {
        Usage(argv[0]);
        exit(-1);
    }

    const char* patterns_file = argv[optind];
    const char* input_file = argv[optind + 1];

    ProcessStream(cin, cout);

    // auto regex_db = RegexDB::LoadFromFile(patterns_file);

    // ifstream input_stream;
    // input_stream.open(input_file, ios::binary);
    // cout << "Input file: " << input_file << endl;
    // if (input_stream.fail()) {
    //     cerr << "Cannot open input file" << endl;
    //     exit(-1);
    // }

    // Scanner scanner(regex_db, [](const MatchResults& match_results) { PrintJSONMatchFn(match_results, std::cout); });
    // scanner.ScanStream(input_stream);

    return 0;
}

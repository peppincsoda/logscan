
#include <iostream>
#include <fstream>
#include <unistd.h> // getopt

#include "logscan/logscan.h"

using namespace std;
using namespace logscan;

static void Usage(const char* prog) {
    cerr << "Usage: " << prog << " -p <pattern file> [-o <output file>] [<input file>...]" << endl;
}

int main(int argc, char** argv) {
    const char* patterns_file = nullptr;
    const char* output_file = nullptr;

    // Process command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:o:")) != -1) {
        switch (opt) {
        case 'p':
            patterns_file = optarg;
            break;
        case 'o':
            output_file = optarg;
            break;
        default:
            Usage(argv[0]);
            return -1;
        }
    }

    if (patterns_file == nullptr) {
        Usage(argv[0]);
        return -1;
    }

    ostream* p_output_stream = nullptr;
    ofstream output_stream;
    if (output_file != nullptr) {
        output_stream.open(output_file);
        if (!output_stream.good()) {
            cerr << "Cannot open output file: " << output_file << endl;
            return -1;
        }
        p_output_stream = &output_stream;
    } else {
        p_output_stream = &cout;
    }

    auto match_fn = [p_output_stream](const MatchResults& match_results) {
        PrintJSONMatchFn(match_results, *p_output_stream);
    };
    Scanner scanner(match_fn);
    if (!scanner.BuildFrom(patterns_file))
        return -1;

    if (optind == argc) {
        // No input files were specified - use stdin
        if (!scanner.ScanStream(cin))
            return -1;

    } else {
        // Input files were specified - open and parse them one by one
        for (int i = optind; i < argc; i++) {
            const char* input_file = argv[i];
            ifstream input_stream(input_file);
            if (!input_stream.good()) {
                cerr << "Cannot open input file: " << input_file << endl;
                return -1;
            }
            if (!scanner.ScanStream(input_stream))
                return -1;
        }
    }

    return 0;
}

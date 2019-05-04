
#include <iostream>
#include <fstream>
#include <unistd.h> // getopt

#include "logscan/logscan.h"

using namespace std;
using namespace logscan;

// Class wrapping all state associated with the benchmark
// class Benchmark {
// private:
//     std::ifstream inputStream_;
//     static const int buffer_size = 16;
// public:
//     void displayStats() {
//         hs_error_t err;
//         size_t dbStream_size = 0;
//         err = hs_database_size(db_streaming, &dbStream_size);
//         if (err == HS_SUCCESS) {
//             cout << "Streaming mode Hyperscan database size    : "
//                  << dbStream_size << " bytes." << endl;
//         } else {
//             cout << "Error getting streaming mode Hyperscan database size"
//                  << endl;
//         }

//         size_t stream_size = 0;
//         err = hs_stream_size(db_streaming, &stream_size);
//         if (err == HS_SUCCESS) {
//             cout << "Streaming mode Hyperscan stream state size: "
//                  << stream_size << " bytes (per stream)." << endl;
//         } else {
//             cout << "Error getting stream state size" << endl;
//         }
//     }
// };

static void Usage(const char* prog) {
    cerr << "Usage: " << prog << " [-n repeats] <pattern file> <log file>" << endl;
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

    auto regex_db = RegexDB::LoadFromFile(patterns_file);

    ifstream input_stream;
    input_stream.open(input_file, ios::binary);
    cout << "Input file: " << input_file << endl;
    if (input_stream.fail()) {
        cerr << "Cannot open input file" << endl;
        exit(-1);
    }

    Scanner scanner(regex_db, [](const MatchResults& match_results) { PrintJSONMatchFn(match_results, std::cout); });
    scanner.ScanStream(input_stream);

    return 0;
}

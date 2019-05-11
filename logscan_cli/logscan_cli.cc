
#include <iostream>
#include <fstream>
#include <unistd.h> // getopt

#include "logscan/logscan.h"

using namespace std;
using namespace logscan;

static void Usage(const char* prog) {
    cerr << "Usage: " << prog << " [-n repeats] <pattern file>" << endl;
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
            return -1;
        }
    }

    if (argc - optind != 1) {
        Usage(argv[0]);
        return -1;
    }

    const char* patterns_file = argv[optind];

    auto match_fn = [](const MatchResults& match_results) { PrintJSONMatchFn(match_results, std::cout); };
    Scanner scanner(match_fn);
    if (!scanner.BuildFrom(patterns_file))
        return -1;

    if (!scanner.ScanStream(cin))
        return -1;

    return 0;
}

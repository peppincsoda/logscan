/*
 * Build instructions:
 *
 *     g++ -Wall -std=c++11 -O2 -o logscan logscan.cc $(pkg-config --cflags --libs libhs libpcre)
 *
 * Usage:
 *
 *     ./logscan <pattern file> <log file>
 *
 */

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <unistd.h>

#include <hs.h>
#include <pcre.h>

#include "logscan/logscan.h"

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::ios;
using std::string;
using std::unordered_map;
using std::vector;

using namespace logscan;

// Class wrapping all state associated with the benchmark
class Benchmark {
private:
    // Hyperscan compiled database (streaming mode)
    const hs_database_t *db_streaming;

    const vector<pcre*> compiled_patterns_;

    const vector<string> ids_;

    // Hyperscan temporary scratch space
    hs_scratch_t *scratch;

    // Hyperscan stream state
    hs_stream_t *stream;

    DoubleBuffer dblbuf_;

    std::ifstream input_stream_;

    static const int buffer_size = 16;

public:
    // Match event handler: called every time Hyperscan finds a match.
    static
    int onMatch(unsigned int id, unsigned long long from, unsigned long long to,
                unsigned int flags, void *ctx) {
        Benchmark* benchmark = static_cast<Benchmark*>(ctx);
        return benchmark->processMatch(id, from, to, flags);
    }

    int processMatch(unsigned int id, unsigned long long from, unsigned long long to,
                unsigned int flags) {

        // cout << "MATCH" << endl;
        // cout << ids_[id] << endl;

        pcre *re = compiled_patterns_[id];

        const int OVECCOUNT = 30;    /* should be a multiple of 3 */
        int ovector[OVECCOUNT];

        // cout << id << " " << from << ":" << to << " " << flags << endl;
        // cout << bytes_processed << endl;

        const char* match = dblbuf_.getMatch(to, from);
        if (match == nullptr)
            return 0;
        const int match_length = to - from;

        const int rc = pcre_exec(
            re,                   /* the compiled pattern */
            nullptr,              /* no extra data - we didn't study the pattern */
            match,                /* the subject string */
            match_length,         /* the length of the subject */
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
            return 0;
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
            char *name_table;
            char *tabptr;
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

            std::ostream& output_stream = cout;

            tabptr = name_table;
            output_stream << "{ \"id\": \"" << ids_[id] << "\"";
            for (int i = 0; i < namecount; i++) {
                const int n = (tabptr[0] << 8) | tabptr[1];
                output_stream << ", \"" << string(tabptr + 2, name_entry_size - 3)
                              << "\": \"" << string(match + ovector[2*n], ovector[2*n+1] - ovector[2*n])
                              << "\"";
                tabptr += name_entry_size;
            }
            output_stream << " }" << endl;
        }

        return 0; // continue matching
    }

    Benchmark(const hs_database_t *streaming, const vector<pcre*> &compiled_patterns, const vector<string> &ids)
        : db_streaming(streaming), compiled_patterns_(compiled_patterns), ids_(ids),
          scratch(nullptr), stream(nullptr),
          dblbuf_(buffer_size) {
        // Allocate enough scratch space to handle streaming mode.
        hs_error_t err = hs_alloc_scratch(db_streaming, &scratch);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: could not allocate scratch space. Exiting." << endl;
            exit(-1);
        }
    }

    ~Benchmark() {
        // Free scratch region
        hs_free_scratch(scratch);

        for (auto re : compiled_patterns_) {
            pcre_free(re);
        }
    }

    void openStream() {
        hs_error_t err = hs_open_stream(db_streaming, 0, &stream);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: Unable to open stream. Exiting." << endl;
            exit(-1);
        }
    }

    // Close Hyperscan stream (potentially generating any
    // end-anchored matches)
    void closeStream() {
        hs_error_t err = hs_close_stream(stream, scratch, onMatch,
                                            this);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: Unable to close stream. Exiting." << endl;
            exit(-1);
        }
    }

    static bool scanBuffer(const char* buffer, unsigned int buffer_size, void* context) {
        Benchmark* self = static_cast<Benchmark*>(context);

        hs_error_t err = hs_scan_stream(self->stream,
                                        buffer, buffer_size, 0,
                                        self->scratch, onMatch, self);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: Unable to scan packet. Exiting." << endl;
            return false;
        }
        return true;
    }

    void scanStream(const char* input_file) {
        input_stream_.open(input_file, ios::binary);
        cout << "Input file: " << input_file << endl;
        if (input_stream_.fail()) {
            cerr << "Cannot open input file" << endl;
            exit(-1);
        }

        dblbuf_.scanStream(input_stream_, scanBuffer, this);
    }

    void displayStats() {
        hs_error_t err;
        size_t dbStream_size = 0;
        err = hs_database_size(db_streaming, &dbStream_size);
        if (err == HS_SUCCESS) {
            cout << "Streaming mode Hyperscan database size    : "
                 << dbStream_size << " bytes." << endl;
        } else {
            cout << "Error getting streaming mode Hyperscan database size"
                 << endl;
        }

        size_t stream_size = 0;
        err = hs_stream_size(db_streaming, &stream_size);
        if (err == HS_SUCCESS) {
            cout << "Streaming mode Hyperscan stream state size: "
                 << stream_size << " bytes (per stream)." << endl;
        } else {
            cout << "Error getting stream state size" << endl;
        }
    }
};

static void usage(const char *prog) {
    cerr << "Usage: " << prog << " [-n repeats] <pattern file> <log file>" << endl;
}

int main(int argc, char **argv) {
    unsigned int repeatCount = 1;

    // Process command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "n:")) != -1) {
        switch (opt) {
        case 'n':
            repeatCount = atoi(optarg);
            break;
        default:
            usage(argv[0]);
            exit(-1);
        }
    }

    if (argc - optind != 2) {
        usage(argv[0]);
        exit(-1);
    }

    const char *patternsFile = argv[optind];
    const char *inputFile = argv[optind + 1];

    auto db = PatternsDB::loadFromFile(patternsFile);

    // Benchmark bench(db_streaming, compiled_patterns, ids);

    // if (repeatCount != 1) {
    //     cout << "Repeating PCAP scan " << repeatCount << " times." << endl;
    // }

    // bench.openStream();
    // bench.scanStream(input_file);
    // bench.closeStream();

    return 0;
}

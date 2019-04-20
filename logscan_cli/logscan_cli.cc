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
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <unistd.h>

#include <hs.h>
#include <pcre.h>

#include "logscan/DoubleBuffer.h"

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::ios;
using std::string;
using std::unordered_map;
using std::vector;

using namespace logscan;

// Simple timing class
class Clock {
public:
    void start() {
        time_start = std::chrono::system_clock::now();
    }

    void stop() {
        time_end = std::chrono::system_clock::now();
    }

    double seconds() const {
        std::chrono::duration<double> delta = time_end - time_start;
        return delta.count();
    }
private:
    std::chrono::time_point<std::chrono::system_clock> time_start, time_end;
};

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

// helper function - see end of file
static void parseFile(const char *filename, vector<string> &patterns,
                      vector<unsigned> &flags, vector<string> &ids);

static hs_database_t *buildDatabase(const vector<const char *> &expressions,
                                    const vector<unsigned> &flags,
                                    unsigned int mode,
                                    vector<pcre*> *compiled_patterns) {
    hs_database_t *db;
    hs_compile_error_t *compileErr;
    hs_error_t err;

    Clock clock;
    clock.start();

    vector<unsigned> ids(expressions.size());
    for (size_t i = 0; i < expressions.size(); i++)
        ids[i] = i;

    err = hs_compile_multi(expressions.data(), flags.data(), ids.data(),
                           expressions.size(), mode, nullptr, &db, &compileErr);

    clock.stop();

    if (err != HS_SUCCESS) {
        if (compileErr->expression < 0) {
            // The error does not refer to a particular expression.
            cerr << "ERROR: " << compileErr->message << endl;
        } else {
            cerr << "ERROR: Pattern '" << expressions[compileErr->expression]
                 << "' failed compilation with error: " << compileErr->message
                 << endl;
        }
        // As the compileErr pointer points to dynamically allocated memory, if
        // we get an error, we must be sure to release it. This is not
        // necessary when no error is detected.
        hs_free_compile_error(compileErr);
        exit(-1);
    }

    cout << "Hyperscan streaming"
         << " mode database compiled in " << clock.seconds() << " seconds."
         << endl;

    if (compiled_patterns != nullptr) {
        // compile all patterns with PCRE
        clock.start();

        for (const char* pattern : expressions) {
            const char *error;
            int erroffset;

            pcre *re = pcre_compile(
                pattern,              /* the pattern */
                0,                    /* default options */
                &error,               /* for error message */
                &erroffset,           /* for error offset */
                nullptr);             /* use default character tables */

            if (re == nullptr) {
                printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
                exit(-1); // TODO
            }


            compiled_patterns->push_back(re);
        }

        clock.stop();
        cout << std::fixed << std::setprecision(4);
        cout << "Compilation of PCRE patterns took " << clock.seconds() << " seconds."
            << endl;
    }

    return db;
}

/**
 * This function will read in the file with the specified name, with an
 * expression per line, ignoring lines starting with '#' and build a Hyperscan
 * database for it.
 */
static void databasesFromFile(const char *filename,
                              hs_database_t **db_streaming,
                              vector<pcre*> &compiled_patterns,
                              vector<string> &ids) {
    // hs_compile_multi requires three parallel arrays containing the patterns,
    // flags and ids that we want to work with. To achieve this we use
    // vectors and new entries onto each for each valid line of input from
    // the pattern file.
    vector<string> patterns;
    vector<unsigned> flags;

    // do the actual file reading and string handling
    parseFile(filename, patterns, flags, ids);

    // Turn our vector of strings into a vector of char*'s to pass in to
    // hs_compile_multi. (This is just using the vector of strings as dynamic
    // storage.)
    vector<const char*> cstrPatterns;
    for (const auto &pattern : patterns) {
        cstrPatterns.push_back(pattern.c_str());
    }

    cout << "Compiling Hyperscan databases with " << patterns.size()
         << " patterns." << endl;

    //*db_block = buildDatabase(cstrPatterns, flags, HS_MODE_BLOCK, &compiled_patterns);

    for (auto &flag : flags) {
        flag = flag | HS_FLAG_SOM_LEFTMOST;
    }

    *db_streaming = buildDatabase(
        cstrPatterns,
        flags,
        HS_MODE_STREAM | HS_MODE_SOM_HORIZON_SMALL, // will find patterns having length up to 2^16
        &compiled_patterns
    );

}

static void usage(const char *prog) {
    cerr << "Usage: " << prog << " [-n repeats] <pattern file> <log file>" << endl;
}

// Main entry point.
int main(int argc, char **argv) {
    unsigned int repeatCount = 1;

    // Process command line arguments.
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

    const char *patternFile = argv[optind];
    const char *input_file = argv[optind + 1];

    // Read our pattern set in and build Hyperscan databases from it.
    cout << "Pattern file: " << patternFile << endl;
    hs_database_t *db_streaming;
    vector<pcre*> compiled_patterns;
    vector<string> ids;
    databasesFromFile(patternFile, &db_streaming, compiled_patterns, ids);

    Benchmark bench(db_streaming, compiled_patterns, ids);

    if (repeatCount != 1) {
        cout << "Repeating PCAP scan " << repeatCount << " times." << endl;
    }


    bench.openStream();
    bench.scanStream(input_file);
    bench.closeStream();

    // Close Hyperscan databases
    hs_free_database(db_streaming);

    return 0;
}

static unsigned parseFlags(const string &flagsStr) {
    unsigned flags = 0;
    for (const auto &c : flagsStr) {
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

static void parseFile(const char *filename, vector<string> &patterns,
                      vector<unsigned> &flags, vector<string> &ids) {
    ifstream inFile(filename);
    if (!inFile.good()) {
        cerr << "ERROR: Can't open pattern file \"" << filename << "\"" << endl;
        exit(-1);
    }

    for (unsigned i = 1; !inFile.eof(); ++i) {
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
            cerr << "ERROR: Could not parse line " << i << endl;
            exit(-1);
        }

        // we should have a string as an ID, before the colon
        const string id = line.substr(0, colonIdx);

        // rest of the expression is the PCRE
        const string expr(line.substr(colonIdx + 1));

        size_t flagsStart = expr.find_last_of('/');
        if (flagsStart == string::npos) {
            cerr << "ERROR: no trailing '/' char" << endl;
            exit(-1);
        }

        string pcre(expr.substr(1, flagsStart - 1));
        string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
        unsigned flag = parseFlags(flagsStr);

        patterns.push_back(pcre);
        flags.push_back(flag);
        ids.push_back(id);
    }
}


#include "PCREDB.h"

#include <cassert>
#include <iostream>

using namespace std;

namespace logscan
{
    PCREDB::PCREDB()
    : pcres_()
    {
    }

    bool PCREDB::BuildFrom(const RegexArray& regexes)
    {
        for (int i = 0; i < regexes.size(); i++) {
            const auto& regex = regexes.get(i);

            PCRE pcre_data;

            const char* err;
            int erroffset;
            pcre_data.pcregex = pcre_compile(
                regex.pattern.c_str(),  /* the pattern */
                0,                      /* default options */
                &err,                   /* for error message */
                &erroffset,             /* for error offset */
                nullptr);               /* use default character tables */

            if (pcre_data.pcregex == nullptr) {
                cerr << "PCRE compilation failed at offset " << erroffset << ":" << err << endl;
                return false;

            } else {
                pcre_fullinfo(
                    pcre_data.pcregex,      /* the compiled pattern */
                    nullptr,                /* no extra data - we didn't study the pattern */
                    PCRE_INFO_NAMECOUNT,    /* number of named substrings */
                    &pcre_data.name_count); /* where to put the answer */

                if (pcre_data.name_count > 0) {
                    pcre_fullinfo(
                        pcre_data.pcregex,        /* the compiled pattern */
                        nullptr,                  /* no extra data - we didn't study the pattern */
                        PCRE_INFO_NAMETABLE,      /* address of the table */
                        &pcre_data.name_table);   /* where to put the answer */

                    pcre_fullinfo(
                        pcre_data.pcregex,           /* the compiled pattern */
                        nullptr,                     /* no extra data - we didn't study the pattern */
                        PCRE_INFO_NAMEENTRYSIZE,     /* size of each entry in the table */
                        &pcre_data.name_entry_size); /* where to put the answer */
                }
            }

            pcres_.emplace_back(pcre_data);
        }

        return true;
    }

    PCREDB::~PCREDB()
    {
        for (PCRE& pcre_data : pcres_) {
            if (pcre_data.pcregex != nullptr) {
                pcre_free(pcre_data.pcregex);
                pcre_data.pcregex = nullptr;
            }
        }
    }

    PCREDB::MatchResult PCREDB::MatchRegex(int index, const std::string& line, CaptureGroups& capture_groups) const
    {
        const PCRE& pcre_data = pcres_[index];

        vector<int> output_vector((pcre_data.name_count + 1) * 3);
        const int rc = pcre_exec(
            pcre_data.pcregex,     /* the compiled pattern */
            nullptr,               /* no extra data - we didn't study the pattern */
            line.c_str(),          /* the subject string */
            line.size(),           /* the length of the subject */
            0,                     /* start at offset 0 in the subject */
            0,                     /* default options */
            output_vector.data(),  /* output vector for substring information */
            output_vector.size()); /* number of elements in the output vector */

        if (rc < 0) {
            switch(rc) {
            case PCRE_ERROR_NOMATCH:
                return PCRE_NoMatch;
            default:
                cerr << "PCRE matching error: " << rc << endl;
                return PCRE_Error;
            }
        }

        if (pcre_data.name_count > 0) {
            char* tabptr = pcre_data.name_table;

            for (int i = 0; i < pcre_data.name_count; i++) {
                const int n = (tabptr[0] << 8) | tabptr[1];

                string key(tabptr + 2);
                string value(line.c_str() + output_vector[2*n], output_vector[2*n+1] - output_vector[2*n]);
                capture_groups[std::move(key)] = std::move(value);
                tabptr += pcre_data.name_entry_size;
            }
        }

        return PCRE_OK;
    }

} // namespace logscan

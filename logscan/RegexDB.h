#ifndef LOGSCAN_REGEXDB_H_
#define LOGSCAN_REGEXDB_H_

#include <hs/hs.h>
#include <pcre.h>

#include <iosfwd>
#include <string>
#include <unordered_map>
#include <vector>

namespace logscan
{
    using NamedCaptureGroups = std::unordered_map<std::string, std::string>;

    struct MatchResults
    {
        std::string regex_id;
        NamedCaptureGroups capture_groups;
    };

    class RegexDB
    {
    public:
        static RegexDB LoadFromFile(const char* filename);
        static RegexDB LoadFromFile(std::istream& input_stream);

        RegexDB();
        ~RegexDB();

        RegexDB(const RegexDB&) = delete;
        RegexDB& operator=(const RegexDB&) = delete;

        RegexDB(RegexDB&&) = default;
        RegexDB& operator=(RegexDB&&) = default;

        void AddPattern(const std::string& id, const std::string& pattern, unsigned int flags);
        void Compile();
        void Execute(const char* buffer, int buffer_length, unsigned int hs_id, MatchResults& match_results) const;

    private:
        friend class Scanner;

        void CompileHS();
        void CompilePCRE();

        std::vector<std::string> ids_;
        std::vector<std::string> patterns_;
        std::vector<unsigned int> flags_;

        hs_database_t* hs_db_;
        std::vector<pcre*> pcres_;
        bool compiled_;
    };

    void ParseFile(std::istream& input_stream, std::vector<std::string>& ids,
                    std::vector<std::string>& patterns, std::vector<unsigned int>& flags);
    unsigned int ParseFlags(const std::string& flags_str);

} // namespace logscan

#endif  // LOGSCAN_REGEXDB_H_

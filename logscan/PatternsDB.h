#pragma once

#include <vector>
#include <string>
#include <iosfwd>

#include <hs/hs.h>
#include <pcre.h>

namespace logscan
{
    class PatternsDB
    {
    public:
        static PatternsDB loadFromFile(const char *filename);
        static PatternsDB loadFromFile(std::istream &inFile);

        PatternsDB();
        ~PatternsDB();

        PatternsDB(const PatternsDB&) = delete;
        PatternsDB& operator=(const PatternsDB&) = delete;

        PatternsDB(PatternsDB&&) = default;
        PatternsDB& operator=(PatternsDB&&) = default;

        void addPattern(const std::string &id, const std::string &pattern, unsigned int flags);
        void compile();

    private:
        void compileHS();
        void compilePCRE();

        std::vector<std::string> ids_;
        std::vector<std::string> patterns_;
        std::vector<unsigned int> flags_;

        hs_database_t *hs_db_;
        std::vector<pcre*> compiled_patterns_;
        bool compiled_;
    };

    void parseFile(std::istream &inFile, std::vector<std::string> &ids,
                    std::vector<std::string> &patterns, std::vector<unsigned int> &flags);
    unsigned int parseFlags(const std::string &flagsStr);

} // namespace logscan

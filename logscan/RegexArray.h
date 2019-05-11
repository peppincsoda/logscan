#ifndef LOGSCAN_REGEXARRAY_H_
#define LOGSCAN_REGEXARRAY_H_

#include <iosfwd>
#include <string>
#include <vector>

namespace logscan
{
    class RegexArray
    {
    public:
        struct Regex
        {
            std::string id;
            std::string pattern;
            unsigned int flags;
        };

        RegexArray();
        ~RegexArray() = default;

        RegexArray(const RegexArray&) = delete;
        RegexArray& operator=(const RegexArray&) = delete;

        RegexArray(RegexArray&&) = default;
        RegexArray& operator=(RegexArray&&) = default;

        bool LoadFromFile(const char* filename);
        bool LoadFromFile(std::istream& input_stream);

        void AddRegex(const std::string& id, const std::string& pattern, unsigned int flags);

        int size() const { return regexes_.size(); }
        const Regex& get(int index) const { return regexes_[index]; }

        int prefix_regex_index() const { return prefix_regex_index_; }

    private:
        std::vector<Regex> regexes_;
        int prefix_regex_index_;
    };
} // namespace logscan

#endif  // LOGSCAN_REGEXARRAY_H_

#pragma once

#include <list>
#include <string>
#include <ranges>

class util {
public: 
    util() = delete;

    static std::list<std::string> tokenize_string(const std::string &input_string, const char token) {
        std::list<std::string> tokens;
        for (auto word : std::views::split(input_string, token)) {
            tokens.emplace_back(std::string(word.begin(), word.end()));
        }

        return tokens;
    }

    /*
     * @brief Converts the input string to non-negative integer.
     * @return -1 on failure. 
     */
    static int string_to_int(const std::string& input_string) {
        try {
            return std::stoi(input_string);
        } catch(const std::exception& e) {
            return -1;
        }
    }
};
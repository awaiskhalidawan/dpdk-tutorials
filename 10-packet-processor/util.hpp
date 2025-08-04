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
};
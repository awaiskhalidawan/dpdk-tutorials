// MIT License
//
// Copyright (c) 2025 Muhammad Awais Khalid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
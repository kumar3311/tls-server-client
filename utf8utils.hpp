#pragma once

#include <string>
#include <vector>
#include <set>
#include <stdexcept>
#include <cstdint>
#include <thread>
#include <mutex>
#include <algorithm>
#include <iostream>

namespace Utf8Utils {

    // Constants for UTF-8 encoding
    constexpr uint32_t MAX_1_BYTE_CODE_POINT = 0x7F;
    constexpr uint32_t MAX_2_BYTE_CODE_POINT = 0x7FF;
    constexpr uint32_t MAX_3_BYTE_CODE_POINT = 0xFFFF;
    constexpr uint32_t MAX_CODE_POINT = 0x10FFFF;

    constexpr uint32_t SURROGATE_MIN = 0xD800;
    constexpr uint32_t SURROGATE_MAX = 0xDFFF;

    constexpr int CONTINUATION_BITS = 6;
    constexpr uint8_t CONTINUATION_HEADER = 0x80;
    constexpr uint8_t TWO_BYTE_HEADER = 0xC0;
    constexpr uint8_t THREE_BYTE_HEADER = 0xE0;
    constexpr uint8_t FOUR_BYTE_HEADER = 0xF0;
    constexpr uint8_t CONTINUATION_MASK = 0x3F;

    // Function to convert a Unicode code point to its UTF-8 representation
    std::string toUtf8(uint32_t codePoint) {
        if ((codePoint >= SURROGATE_MIN && codePoint <= SURROGATE_MAX) || codePoint > MAX_CODE_POINT) {
            throw std::invalid_argument("Invalid Unicode code point.");
        }

        std::string utf8Bytes;
        if (codePoint <= MAX_1_BYTE_CODE_POINT) {
            utf8Bytes.push_back(static_cast<char>(codePoint));
        } else if (codePoint <= MAX_2_BYTE_CODE_POINT) {
            utf8Bytes.push_back(static_cast<char>(TWO_BYTE_HEADER | (codePoint >> CONTINUATION_BITS)));
            utf8Bytes.push_back(static_cast<char>(CONTINUATION_HEADER | (codePoint & CONTINUATION_MASK)));
        } else if (codePoint <= MAX_3_BYTE_CODE_POINT) {
            utf8Bytes.push_back(static_cast<char>(THREE_BYTE_HEADER | (codePoint >> (2 * CONTINUATION_BITS))));
            utf8Bytes.push_back(static_cast<char>(CONTINUATION_HEADER | ((codePoint >> CONTINUATION_BITS) & CONTINUATION_MASK)));
            utf8Bytes.push_back(static_cast<char>(CONTINUATION_HEADER | (codePoint & CONTINUATION_MASK)));
        } else {
            utf8Bytes.push_back(static_cast<char>(FOUR_BYTE_HEADER | (codePoint >> (3 * CONTINUATION_BITS))));
            utf8Bytes.push_back(static_cast<char>(CONTINUATION_HEADER | ((codePoint >> (2 * CONTINUATION_BITS)) & CONTINUATION_MASK)));
            utf8Bytes.push_back(static_cast<char>(CONTINUATION_HEADER | ((codePoint >> CONTINUATION_BITS) & CONTINUATION_MASK)));
            utf8Bytes.push_back(static_cast<char>(CONTINUATION_HEADER | (codePoint & CONTINUATION_MASK)));
        }
        return utf8Bytes;
    }

    // Helper to check for excluded characters
    bool isExcluded(uint32_t codePoint) {
        switch (codePoint) {
            case '\n':
            case '\r':
            case '\t':
            case ' ':
                return true;
            default:
                return false;
        }
    }

    // Function to return all UTF-8 characters in range, excluding specific control characters
    std::string getAllUtf8Characters(uint32_t start = 0x0000, uint32_t end = 0x00FF) {
        if (start > end) {
            return "";
        }

        std::string allUtf8Characters;
        // Pre-allocate memory to avoid reallocations
        size_t estimatedSize = 0;
        for (uint32_t i = start; i <= end; ++i) {
            if (isExcluded(i)) continue;
            if (i <= MAX_1_BYTE_CODE_POINT) estimatedSize += 1;
            else if (i <= MAX_2_BYTE_CODE_POINT) estimatedSize += 2;
            else if (i <= MAX_3_BYTE_CODE_POINT) estimatedSize += 3;
            else estimatedSize += 4;
        }
        allUtf8Characters.reserve(estimatedSize);

        for (uint32_t i = start; i <= end; ++i) {
            if (isExcluded(i)) continue;
            allUtf8Characters += toUtf8(i);
        }
        return allUtf8Characters;
    }

    // Recursive helper to generate all combinations for a specific length
    void generateCombinationsForLength(std::set<std::string>& localSet, const std::string& charset, std::string& currentString, size_t targetLength) {
        if (currentString.length() == targetLength) {
            localSet.insert(currentString);
            return;
        }

        if (currentString.length() > targetLength) {
            return;
        }

        for (char c : charset) {
            currentString.push_back(c);
            generateCombinationsForLength(localSet, charset, currentString, targetLength);
            currentString.pop_back();
        }
    }

    // Function to add unique strings of lengths within a given range to a set
    void addUniqueStringsToSet(std::set<std::string>& stringSet, const std::string& charset, size_t minLength, size_t maxLength) {
        if (minLength > maxLength) {
            throw std::invalid_argument("Minimum length cannot be greater than maximum length.");
        }
        if (charset.empty()) {
            return;
        }

        std::vector<std::thread> threads;
        std::mutex set_mutex;

        for (size_t length = minLength; length <= maxLength; ++length) {
            threads.emplace_back([&, length]() {
                std::set<std::string> local_set;
                std::string current_string;
                generateCombinationsForLength(local_set, charset, current_string, length);

                std::lock_guard<std::mutex> lock(set_mutex);
                stringSet.insert(local_set.begin(), local_set.end());
                std::cout << "Generated " << local_set.size() << " unique strings of length " << length << std::endl;
            });
            std::cout << "Starting thread for length " << length << std::endl;
            std::cout << "Thread ID: " << std::this_thread::get_id() << std::endl; 
        }
        std::cout << "Total threads started: " << threads.size() << std::endl;

        for (auto& t : threads) {
            t.join();
        }
    }
}
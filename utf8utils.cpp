#include "tls_imp.hpp"

int main() {
    try {
        // Generate the initial charset from printable ASCII characters
        std::string charset = Utf8Utils::getAllUtf8Characters(0x0021, 0x007E);
        std::cout << "Generated Charset: " << charset << "\n\n";

        // Create a set and add unique strings to it
        std::set<std::string> uniqueStrings;
        size_t minLength = 4;
        size_t maxLength = 12;

        Utf8Utils::addUniqueStringsToSet(uniqueStrings, charset, minLength, maxLength);

        std::cout << "Set of unique strings with lengths from " << minLength << " to " << maxLength << ":\n";
        for (const auto& str : uniqueStrings) {
            std::cout << "  Length " << str.length() << ": " << str << '\n';
        }

    } catch (const std::invalid_argument& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}